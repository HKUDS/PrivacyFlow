from __future__ import annotations

import hashlib
import io
import json
import os
import secrets
import shutil
import stat
import tempfile
import threading
import time
from contextlib import contextmanager
from collections.abc import MutableMapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

import tomlkit
from ruamel.yaml import YAML

try:
    import fcntl
except ImportError:  # pragma: no cover - exercised only on Windows
    fcntl = None

try:
    import msvcrt
except ImportError:  # pragma: no cover - exercised only on POSIX
    msvcrt = None

from gateway.cli.launcher import (
    generate_local_api_key,
    save_launcher_connector_api_key,
    save_launcher_connector_api_keys,
)
from gateway.compat import ensure_private_state_directory


CONNECTOR_PROTOCOLS = {
    "codex": "openai_responses",
    "claude-code": "anthropic_messages",
    "deepseek-harness": "openai_chat_completions",
    "nanobot": "openai_chat_completions",
}
CONNECTOR_NAMES = {
    "codex": "Codex",
    "claude-code": "Claude Code",
    "deepseek-harness": "DeepSeek Harness",
    "nanobot": "nanobot",
}
COMMANDS = {
    "codex": ("codex",),
    "claude-code": ("claude",),
    # The official npm package is @deepseek-ai/dsh and normally installs
    # ``dsh``. Keep distribution-era aliases too; GUI-launched processes can
    # miss the package manager's bin directory, so _package_executable also
    # inspects the installed manifest without executing it.
    "deepseek-harness": ("dsh", "deepseek-harness", "deepseek"),
    "nanobot": ("nanobot",),
}


class ConnectorError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        code: str = "CONNECTOR_ERROR",
        status_code: int = 400,
        paths: list[str] | None = None,
        requires_confirmation: bool = False,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.status_code = status_code
        self.paths = paths or []
        self.requires_confirmation = requires_confirmation


@dataclass(frozen=True)
class PreparedFile:
    path: Path
    content: bytes


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _json_bytes(value: Mapping[str, Any]) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode()


def _yaml_load(raw: bytes) -> Any:
    yaml = YAML()
    yaml.preserve_quotes = True
    return yaml.load(raw.decode("utf-8")) if raw else None


def _yaml_bytes(value: Any) -> bytes:
    yaml = YAML()
    yaml.preserve_quotes = True
    stream = io.StringIO()
    yaml.dump(value, stream)
    return stream.getvalue().encode()


_PROCESS_LOCKS: dict[str, threading.RLock] = {}
_PROCESS_LOCKS_GUARD = threading.Lock()
_HELD_TRANSACTION_LOCKS = threading.local()


def _process_lock_for(path: Path) -> threading.RLock:
    """Return the process-wide lock for one canonical state directory."""

    key = os.path.normcase(str(path))
    with _PROCESS_LOCKS_GUARD:
        lock = _PROCESS_LOCKS.get(key)
        if lock is None:
            lock = threading.RLock()
            _PROCESS_LOCKS[key] = lock
        return lock


class AgentConnectorService:
    def __init__(
        self,
        state_dir: Path,
        launcher_path: Path,
        *,
        environ: Mapping[str, str] | None = None,
        home: Path | None = None,
        which: Callable[[str], str | None] = shutil.which,
        base_url: str = "http://127.0.0.1:8765",
    ) -> None:
        # Credential commands may run from an Agent's project directory rather
        # than PrivacyFlow's current working directory. Persist absolute state paths so
        # the generated Codex command and every restore transaction resolve the
        # same files after a process restart.
        self.state_dir = state_dir.expanduser().resolve()
        self.launcher_path = launcher_path.expanduser().resolve()
        self.environ = dict(os.environ if environ is None else environ)
        self.home = home or Path.home()
        self.which = which
        self.base_url = base_url.rstrip("/")
        self.index_path = self.state_dir / "agent-connections.json"
        self.lock_path = self.state_dir / "agent-connections.lock"
        self.transactions_dir = self.state_dir / "agent-connection-transactions"
        self._process_lock = _process_lock_for(self.state_dir)
        self._ensure_state_dirs()

    def list(self) -> dict[str, Any]:
        state = self._read_state()
        return {"connectors": [self._public_status(connector_id, state) for connector_id in CONNECTOR_NAMES]}

    def connect(
        self,
        connector_id: str,
        model: str,
        models: list[str],
        *,
        confirm_existing_config: bool = False,
    ) -> dict[str, Any]:
        with self._transaction_lock():
            return self._connect_locked(
                connector_id,
                model,
                models,
                confirm_existing_config=confirm_existing_config,
            )

    def _connect_locked(
        self,
        connector_id: str,
        model: str,
        models: list[str],
        *,
        confirm_existing_config: bool = False,
    ) -> dict[str, Any]:
        self._validate_connector(connector_id)
        model = self._validate_model(model)
        if not self._executable(connector_id):
            raise ConnectorError("The Agent is not installed or is not available on PATH.", code="CONNECTOR_NOT_INSTALLED", status_code=409)
        state = self._read_state()
        active = state["active"].get(connector_id)
        if active:
            if self._transaction_issue(connector_id, active):
                raise ConnectorError(
                    "The saved Agent connection transaction is incomplete and requires manual repair.",
                    code="CONNECTOR_TRANSACTION_INCOMPLETE",
                    status_code=409,
                )
            changed = self._changed_paths(active)
            if changed:
                raise ConnectorError(
                    "The Agent configuration changed after PrivacyFlow connected it. Restore the original configuration first.",
                    code="CONNECTOR_EXTERNAL_CHANGES",
                    status_code=409,
                    paths=changed,
                )
            if active.get("model") == model:
                return self._public_status(connector_id, state)
            raise ConnectorError(
                "This Agent is already connected. Restore its original configuration before choosing another model.",
                code="CONNECTOR_ALREADY_ACTIVE",
                status_code=409,
            )
        prepared = self._prepare(connector_id, model, models, key="__PF_CONNECTOR_KEY__")
        for item in prepared:
            self._validate_target(item.path)
        # Reserved names may have been written by Claude/cc-switch or by a
        # previous APG installation.  Do not infer ownership from the names;
        # an explicit migration confirmation is required before replacement.
        self._check_collision(
            connector_id,
            prepared,
            confirm_existing_config=confirm_existing_config,
        )

        transaction_id = f"txn_{int(time.time())}_{secrets.token_hex(6)}"
        key = generate_local_api_key(legacy=self.state_dir.name == ".apg")
        prepared = self._prepare(connector_id, model, models, key=key)
        connector_transactions_dir = self.transactions_dir / connector_id
        connector_transactions_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(connector_transactions_dir, 0o700)
        transaction_dir = connector_transactions_dir / transaction_id
        transaction_dir.mkdir(mode=0o700)
        os.chmod(transaction_dir, 0o700)
        files: list[dict[str, Any]] = []
        for index, item in enumerate(prepared):
            captured = self._capture_target(item.path)
            existed = captured["existed"]
            raw = captured["content"]
            mode = captured["mode"]
            snapshot = transaction_dir / f"{index}.snapshot"
            snapshot.write_bytes(raw)
            os.chmod(snapshot, 0o600)
            files.append({
                "path": str(item.path), "existed": existed, "mode": mode,
                "snapshot": str(snapshot.relative_to(self.state_dir)), "connected_sha256": _sha256(item.content),
            })

        record = {
            "id": transaction_id, "connector_id": connector_id, "model": model,
            "created_at": int(time.time()), "files": files,
        }
        files_replaced = False
        try:
            save_launcher_connector_api_key(self.launcher_path, connector_id, key)
            # Re-check reserved IDs after regenerating the final payload. A
            # user may have created a provider/preset between the initial
            # collision check and this transaction's snapshot.
            self._check_collision(
                connector_id,
                prepared,
                confirm_existing_config=confirm_existing_config,
            )
            self._replace_all(prepared, files)
            files_replaced = True
            state["active"][connector_id] = record
            self._write_state(state)
        except Exception:
            if files_replaced:
                self._restore_files(files)
            save_launcher_connector_api_key(self.launcher_path, connector_id, None)
            shutil.rmtree(transaction_dir, ignore_errors=True)
            raise
        return self._public_status(connector_id, state)

    def restore(self, connector_id: str, *, confirm_external_changes: bool = False) -> dict[str, Any]:
        with self._transaction_lock():
            return self._restore_locked(connector_id, confirm_external_changes=confirm_external_changes)

    def _restore_locked(self, connector_id: str, *, confirm_external_changes: bool = False) -> dict[str, Any]:
        self._validate_connector(connector_id)
        state = self._read_state()
        active = state["active"].get(connector_id)
        if not active:
            return self._public_status(connector_id, state)
        changed = self._changed_paths(active)
        if changed and not confirm_external_changes:
            raise ConnectorError(
                "The Agent configuration changed after PrivacyFlow connected it. Confirm to save a safety backup and restore the original files.",
                code="CONNECTOR_EXTERNAL_CHANGES",
                status_code=409,
                paths=changed,
            )
        if changed:
            self._save_safety_backup(connector_id, active, changed)
        connected_files = self._capture_current_files(active["files"])
        try:
            key = self.credential(connector_id)
        except Exception as exc:
            raise ConnectorError(
                "The Connector credential is missing; the saved transaction requires manual repair.",
                code="CONNECTOR_TRANSACTION_INCOMPLETE",
                status_code=409,
            ) from exc
        try:
            self._restore_transaction(active["files"])
            save_launcher_connector_api_key(self.launcher_path, connector_id, None)
            state["active"].pop(connector_id, None)
            completed = state["completed"].setdefault(connector_id, [])
            completed.insert(0, {**active, "restored_at": int(time.time())})
            del completed[5:]
            self._write_state(state)
        except Exception:
            self._apply_captured_files(connected_files)
            save_launcher_connector_api_key(self.launcher_path, connector_id, key)
            raise
        try:
            self._prune_transaction_dirs(connector_id, {item["id"] for item in completed})
        except OSError:
            # Restoration and credential revocation are already committed.
            # Old transaction directories are bounded cleanup artifacts; a
            # cleanup failure must not turn a successful restore into a false
            # API failure or resurrect the revoked Connector credential.
            pass
        return self._public_status(connector_id, state)

    def credential(self, connector_id: str) -> str:
        from gateway.cli.launcher import load_connector_api_key
        return load_connector_api_key(self.launcher_path, connector_id)

    def migrate_legacy_namespace(self) -> dict[str, Any]:
        with self._transaction_lock():
            return self._migrate_legacy_namespace()

    def _migrate_legacy_namespace(self) -> dict[str, Any]:
        """Migrate APG-owned Agent files to the PrivacyFlow namespace.

        Only active transactions are eligible.  A reserved APG/PF provider found
        without a transaction is deliberately reported as a conflict rather than
        guessed to be ours; this keeps a cc-switch or hand-written configuration
        out of the migration path.
        """
        state = self._read_state()
        for connector_id in CONNECTOR_NAMES:
            active = state["active"].get(connector_id)
            if active:
                changed = self._changed_paths(active)
                if changed:
                    raise ConnectorError(
                        "An Agent configuration changed outside PrivacyFlow; resolve it before migration.",
                        code="PF_MIGRATION_CONFIG_CONFLICT",
                        status_code=409,
                        paths=changed,
                    )
            elif self._reserved_config_exists(connector_id):
                raise ConnectorError(
                    "A reserved Agent configuration exists without a PrivacyFlow transaction; it was not migrated.",
                    code="PF_MIGRATION_UNKNOWN_CONFIG",
                    status_code=409,
                    paths=[str(path) for path in self._paths(connector_id)],
                )

        migrations: list[dict[str, Any]] = []
        for connector_id, active in list(state["active"].items()):
            if connector_id not in CONNECTOR_NAMES or not active:
                continue
            old_key = self.credential(connector_id)
            new_key = generate_local_api_key()
            paths = [Path(item["path"]) for item in active.get("files", [])]
            if len(paths) != len(self._paths(connector_id)):
                raise ConnectorError(
                    "The saved Agent transaction does not match the current connector layout.",
                    code="PF_MIGRATION_CONFIG_CONFLICT",
                    status_code=409,
                )
            current = self._capture_current_files(active["files"])
            prepared = self._prepare_namespace_migration(
                connector_id,
                paths,
                active.get("model", ""),
                old_key,
                new_key,
            )
            if len(current) != len(prepared):
                raise ConnectorError(
                    "The saved Agent transaction does not match the prepared migration.",
                    code="PF_MIGRATION_CONFIG_CONFLICT",
                    status_code=409,
                )
            for item in prepared:
                self._validate_target(item.path)
            migrations.append({
                "connector_id": connector_id,
                "active": active,
                "paths": paths,
                "current": current,
                "prepared": prepared,
                "new_key": new_key,
            })

        if not migrations:
            return {"migrated_connectors": [], "count": 0}

        # Treat every active Connector, its external files, the Launcher key
        # ring, and the transaction index as one transaction. A later failure
        # must never strand an earlier Agent on the PF namespace while the PF
        # state directory is rolled back by the CLI.
        launcher_before = self._capture_paths([self.launcher_path])
        index_before = self._capture_paths([self.index_path])
        all_current = [item for migration in migrations for item in migration["current"]]
        all_prepared = [item for migration in migrations for item in migration["prepared"]]
        try:
            for migration in migrations:
                self._save_safety_backup(
                    migration["connector_id"],
                    migration["active"],
                    [str(path) for path in migration["paths"]],
                )
            self._replace_captured(all_current, all_prepared)
            save_launcher_connector_api_keys(
                self.launcher_path,
                {migration["connector_id"]: migration["new_key"] for migration in migrations},
            )
            for migration in migrations:
                migration["active"]["files"] = [
                    {**item, "connected_sha256": _sha256(migration["prepared"][index].content)}
                    for index, item in enumerate(migration["active"]["files"])
                ]
            self._write_state(state)
        except Exception:
            self._apply_captured_files(all_current)
            self._apply_captured_files(index_before)
            self._apply_captured_files(launcher_before)
            raise

        migrated = [migration["connector_id"] for migration in migrations]
        return {"migrated_connectors": migrated, "count": len(migrated)}

    def _prepare_namespace_migration(
        self,
        connector_id: str,
        paths: list[Path],
        model: str,
        old_key: str,
        new_key: str,
    ) -> list[PreparedFile]:
        if connector_id == "codex":
            try:
                value = tomlkit.parse(paths[0].read_text("utf-8"))
                providers = value.get("model_providers", {})
                self._require_mapping(providers, paths[0], "model_providers")
                if "pf" in providers and "apg" in providers:
                    raise ConnectorError("Both Codex APG and PF providers exist; migration is ambiguous.", code="PF_MIGRATION_CONFIG_CONFLICT", status_code=409)
                if "apg" in providers:
                    providers["pf"] = providers.pop("apg")
                provider = providers.get("pf")
                if isinstance(provider, MutableMapping):
                    provider["name"] = "PrivacyFlow"
                    auth = provider.get("auth")
                    if isinstance(auth, MutableMapping):
                        auth["command"] = "privacyflow"
                        auth["args"] = ["credential", "--connector", "codex", "--launcher-config", str(self.launcher_path)]
                if value.get("model_provider") == "apg":
                    value["model_provider"] = "pf"
                return [PreparedFile(paths[0], tomlkit.dumps(value).encode())]
            except ConnectorError:
                raise
            except Exception as exc:
                raise ConnectorError(f"Cannot migrate {paths[0]}: {exc}", code="CONNECTOR_CONFIG_INVALID") from exc

        if connector_id == "claude-code":
            value = self._load_json_object(paths[0])
            env = value.get("env", {})
            if not isinstance(env, MutableMapping) or env.get("ANTHROPIC_AUTH_TOKEN") != old_key:
                raise ConnectorError(
                    "The Claude Code credential does not match the managed Connector transaction.",
                    code="PF_MIGRATION_CONFIG_CONFLICT",
                    status_code=409,
                    paths=[str(paths[0])],
                )
            env["ANTHROPIC_AUTH_TOKEN"] = new_key
            for key in list(env):
                if key.startswith("APG_"):
                    env["PF_" + key[4:]] = env.pop(key)
            return [PreparedFile(paths[0], _json_bytes(value))]

        if connector_id == "deepseek-harness":
            settings = _yaml_load(paths[0].read_bytes()) or {}
            credentials = _yaml_load(paths[1].read_bytes()) or {}
            if not isinstance(settings, MutableMapping) or not isinstance(credentials, MutableMapping):
                raise ConnectorError("DeepSeek Harness configuration roots must be mappings.", code="CONNECTOR_CONFIG_INVALID")
            llm = settings.get("llm-pi-ai", {})
            providers = llm.get("providers", {}) if isinstance(llm, MutableMapping) else {}
            if isinstance(providers, MutableMapping):
                if "pf" in providers and "apg" in providers:
                    raise ConnectorError("Both dsh APG and PF providers exist; migration is ambiguous.", code="PF_MIGRATION_CONFIG_CONFLICT", status_code=409)
                if "apg" in providers:
                    providers["pf"] = providers.pop("apg")
                provider = providers.get("pf")
                if isinstance(provider, MutableMapping):
                    provider["displayName"] = "PrivacyFlow"
                    if provider.get("apiKeyEnv") == "APG_DSH_API_KEY":
                        provider["apiKeyEnv"] = "PF_DSH_API_KEY"
            if not isinstance(providers, MutableMapping) or not isinstance(providers.get("pf"), MutableMapping):
                raise ConnectorError(
                    "The dsh provider does not match the managed Connector transaction.",
                    code="PF_MIGRATION_CONFIG_CONFLICT",
                    status_code=409,
                    paths=[str(paths[0])],
                )
            default_model = settings.get("agent-default-model")
            if isinstance(default_model, MutableMapping) and default_model.get("provider") == "apg":
                default_model["provider"] = "pf"
            if "APG_DSH_API_KEY" in credentials:
                if "PF_DSH_API_KEY" in credentials and credentials["PF_DSH_API_KEY"] != credentials["APG_DSH_API_KEY"]:
                    raise ConnectorError("Both dsh APG and PF credentials exist; migration is ambiguous.", code="PF_MIGRATION_CONFIG_CONFLICT", status_code=409)
                if credentials["APG_DSH_API_KEY"] != old_key:
                    raise ConnectorError(
                        "The dsh credential does not match the managed Connector transaction.",
                        code="PF_MIGRATION_CONFIG_CONFLICT",
                        status_code=409,
                        paths=[str(paths[1])],
                    )
                credentials["PF_DSH_API_KEY"] = new_key
                credentials.pop("APG_DSH_API_KEY", None)
            elif credentials.get("PF_DSH_API_KEY") == old_key:
                # A Connector created during the transition may already use
                # the PF environment name while still holding an APG-prefixed
                # credential. It must be rotated with the Launcher key too.
                credentials["PF_DSH_API_KEY"] = new_key
            else:
                raise ConnectorError(
                    "The dsh credential does not match the managed Connector transaction.",
                    code="PF_MIGRATION_CONFIG_CONFLICT",
                    status_code=409,
                    paths=[str(paths[1])],
                )
            return [PreparedFile(paths[0], _yaml_bytes(settings)), PreparedFile(paths[1], _yaml_bytes(credentials))]

        value = self._load_json_object(paths[0])
        providers = value.get("providers", {})
        presets = value.get("modelPresets", {})
        if isinstance(providers, MutableMapping):
            if "pf" in providers and "apg" in providers:
                raise ConnectorError("Both nanobot APG and PF providers exist; migration is ambiguous.", code="PF_MIGRATION_CONFIG_CONFLICT", status_code=409)
            if "apg" in providers:
                providers["pf"] = providers.pop("apg")
            provider = providers.get("pf")
            if not isinstance(provider, MutableMapping) or provider.get("apiKey") != old_key:
                raise ConnectorError(
                    "The nanobot credential does not match the managed Connector transaction.",
                    code="PF_MIGRATION_CONFIG_CONFLICT",
                    status_code=409,
                    paths=[str(paths[0])],
                )
            provider["apiKey"] = new_key
        else:
            raise ConnectorError(
                "The nanobot provider does not match the managed Connector transaction.",
                code="PF_MIGRATION_CONFIG_CONFLICT",
                status_code=409,
                paths=[str(paths[0])],
            )
        if isinstance(presets, MutableMapping):
            if "APG" in presets and "PF" in presets:
                raise ConnectorError("Both nanobot APG and PF presets exist; migration is ambiguous.", code="PF_MIGRATION_CONFIG_CONFLICT", status_code=409)
            if "APG" in presets:
                presets["PF"] = presets.pop("APG")
            preset = presets.get("PF")
            if isinstance(preset, MutableMapping) and preset.get("provider") == "apg":
                preset["provider"] = "pf"
        agents = value.get("agents", {})
        defaults = agents.get("defaults", {}) if isinstance(agents, MutableMapping) else {}
        if isinstance(defaults, MutableMapping) and defaults.get("modelPreset") == "APG":
            defaults["modelPreset"] = "PF"
        return [PreparedFile(paths[0], _json_bytes(value))]

    def _replace_captured(self, current: list[dict[str, Any]], prepared: list[PreparedFile]) -> None:
        if len(current) != len(prepared):
            raise ConnectorError(
                "The saved Agent transaction does not match the prepared migration.",
                code="PF_MIGRATION_CONFIG_CONFLICT",
                status_code=409,
            )
        for before in current:
            path = Path(before["path"])
            try:
                if before["existed"]:
                    unchanged = (
                        path.exists()
                        and not path.is_symlink()
                        and path.is_file()
                        and path.read_bytes() == before["content"]
                        and stat.S_IMODE(path.stat().st_mode) == before["mode"]
                    )
                else:
                    unchanged = not path.exists()
            except OSError:
                unchanged = False
            if not unchanged:
                raise ConnectorError(
                    "The Agent configuration changed while PrivacyFlow was migrating it.",
                    code="PF_MIGRATION_CONCURRENT_CHANGE",
                    status_code=409,
                    paths=[str(path)],
                )
        replaced = 0
        try:
            for item, before in zip(prepared, current, strict=True):
                self._atomic_write(item.path, item.content, int(before["mode"] or 0o600))
                replaced += 1
        except Exception:
            self._apply_captured_files(current[:replaced])
            raise

    def _reserved_config_exists(self, connector_id: str) -> bool:
        paths = self._paths(connector_id)
        if connector_id == "codex" and paths[0].exists():
            value = tomlkit.parse(paths[0].read_text("utf-8"))
            return any(item in value.get("model_providers", {}) for item in ("pf", "apg"))
        if connector_id == "claude-code" and paths[0].exists():
            env = self._load_json_object(paths[0]).get("env", {})
            return isinstance(env, MutableMapping) and any(key.startswith("APG_") or key.startswith("PF_") for key in env)
        if connector_id == "deepseek-harness" and paths[0].exists():
            value = _yaml_load(paths[0].read_bytes()) or {}
            providers = value.get("llm-pi-ai", {}).get("providers", {}) if isinstance(value, MutableMapping) else {}
            return isinstance(providers, MutableMapping) and any(item in providers for item in ("pf", "apg"))
        if connector_id == "nanobot" and paths[0].exists():
            value = self._load_json_object(paths[0])
            return any(item in value.get("providers", {}) for item in ("pf", "apg")) or any(item in value.get("modelPresets", {}) for item in ("PF", "APG"))
        return False

    def _paths(self, connector_id: str) -> list[Path]:
        if connector_id == "codex":
            return [Path(self.environ.get("CODEX_HOME", self.home / ".codex")) / "config.toml"]
        if connector_id == "claude-code":
            return [Path(self.environ.get("CLAUDE_CONFIG_DIR", self.home / ".claude")) / "settings.json"]
        if connector_id == "deepseek-harness":
            root = Path(self.environ.get("DSH_HOME", self.home / ".dsh"))
            return [root / "settings.yaml", root / ".credentials.yaml"]
        return [self.home / ".nanobot" / "config.json"]

    def _prepare(self, connector_id: str, model: str, models: list[str], *, key: str) -> list[PreparedFile]:
        paths = self._paths(connector_id)
        if connector_id == "codex":
            raw = paths[0].read_text("utf-8") if paths[0].exists() else ""
            try:
                value = tomlkit.parse(raw)
            except Exception as exc:
                raise ConnectorError(f"Cannot parse {paths[0]}: {exc}", code="CONNECTOR_CONFIG_INVALID") from exc
            providers = value.setdefault("model_providers", tomlkit.table())
            self._require_mapping(providers, paths[0], "model_providers")
            provider = tomlkit.table()
            provider["name"] = "PrivacyFlow"
            provider["base_url"] = f"{self.base_url}/v1"
            provider["wire_api"] = "responses"
            auth = tomlkit.table()
            auth["command"] = "privacyflow"
            auth["args"] = ["credential", "--connector", "codex", "--launcher-config", str(self.launcher_path)]
            provider["auth"] = auth
            providers["pf"] = provider
            value["model_provider"] = "pf"
            value["model"] = model
            return [PreparedFile(paths[0], tomlkit.dumps(value).encode())]
        if connector_id == "claude-code":
            value = self._load_json_object(paths[0])
            env = value.setdefault("env", {})
            if not isinstance(env, dict):
                raise ConnectorError(f"{paths[0]}: env must be an object", code="CONNECTOR_CONFIG_INVALID")
            env.update({
                "ANTHROPIC_BASE_URL": self.base_url,
                "ANTHROPIC_AUTH_TOKEN": key,
                "ANTHROPIC_MODEL": model,
                "ANTHROPIC_DEFAULT_OPUS_MODEL": model,
                "ANTHROPIC_DEFAULT_SONNET_MODEL": model,
                "ANTHROPIC_DEFAULT_HAIKU_MODEL": model,
                "ANTHROPIC_DEFAULT_FABLE_MODEL": model,
            })
            return [PreparedFile(paths[0], _json_bytes(value))]
        if connector_id == "deepseek-harness":
            settings = _yaml_load(paths[0].read_bytes()) if paths[0].exists() else None
            credentials = _yaml_load(paths[1].read_bytes()) if paths[1].exists() else None
            settings = {} if settings is None else settings
            credentials = {} if credentials is None else credentials
            if not isinstance(settings, dict) or not isinstance(credentials, dict):
                raise ConnectorError("DeepSeek Harness configuration roots must be mappings.", code="CONNECTOR_CONFIG_INVALID")
            llm_pi_ai = settings.setdefault("llm-pi-ai", {})
            self._require_mapping(llm_pi_ai, paths[0], "llm-pi-ai")
            providers = llm_pi_ai.setdefault("providers", {})
            self._require_mapping(providers, paths[0], "llm-pi-ai.providers")
            providers["pf"] = {
                "displayName": "PrivacyFlow", "api": "openai-completions",
                "baseURL": f"{self.base_url}/v1", "apiKeyEnv": "PF_DSH_API_KEY",
                "models": [{"id": item, "name": item, "input": ["text"]} for item in models],
            }
            settings["agent-default-model"] = {"provider": "pf", "model": model}
            credentials["PF_DSH_API_KEY"] = key
            return [PreparedFile(paths[0], _yaml_bytes(settings)), PreparedFile(paths[1], _yaml_bytes(credentials))]
        value = self._load_json_object(paths[0])
        providers = value.setdefault("providers", {})
        presets = value.setdefault("modelPresets", {})
        agents_root = value.setdefault("agents", {})
        self._require_mapping(providers, paths[0], "providers")
        self._require_mapping(presets, paths[0], "modelPresets")
        self._require_mapping(agents_root, paths[0], "agents")
        agents = agents_root.setdefault("defaults", {})
        self._require_mapping(agents, paths[0], "agents.defaults")
        providers["pf"] = {"apiKey": key, "apiBase": f"{self.base_url}/v1", "apiType": "chat_completions"}
        presets["PF"] = {"provider": "pf", "model": model}
        agents["modelPreset"] = "PF"
        return [PreparedFile(paths[0], _json_bytes(value))]

    def _load_json_object(self, path: Path) -> dict[str, Any]:
        try:
            value = json.loads(path.read_text("utf-8")) if path.exists() else {}
        except (OSError, ValueError) as exc:
            raise ConnectorError(f"Cannot parse {path}: {exc}", code="CONNECTOR_CONFIG_INVALID") from exc
        if not isinstance(value, dict):
            raise ConnectorError(f"{path} must contain an object", code="CONNECTOR_CONFIG_INVALID")
        return value

    def _require_mapping(self, value: Any, path: Path, field: str) -> None:
        if not isinstance(value, MutableMapping):
            raise ConnectorError(f"{path}: {field} must be an object", code="CONNECTOR_CONFIG_INVALID")

    def _check_collision(
        self,
        connector_id: str,
        prepared: list[PreparedFile],
        *,
        confirm_existing_config: bool = False,
    ) -> None:
        paths = self._paths(connector_id)
        try:
            if connector_id == "codex" and paths[0].exists():
                value = tomlkit.parse(paths[0].read_text("utf-8"))
                if any(item in value.get("model_providers", {}) for item in ("pf", "apg")):
                    self._raise_collision(
                        "The reserved Codex PrivacyFlow provider already exists. Confirm migration before it is replaced.",
                        prepared,
                        confirm_existing_config=confirm_existing_config,
                    )
            elif connector_id == "claude-code" and paths[0].exists():
                value = self._load_json_object(paths[0])
                env = value.get("env", {})
                if isinstance(env, dict) and any(
                    key in env
                    for key in (
                        "ANTHROPIC_BASE_URL",
                        "ANTHROPIC_AUTH_TOKEN",
                        "ANTHROPIC_MODEL",
                        "ANTHROPIC_DEFAULT_OPUS_MODEL",
                        "ANTHROPIC_DEFAULT_SONNET_MODEL",
                        "ANTHROPIC_DEFAULT_HAIKU_MODEL",
                        "ANTHROPIC_DEFAULT_FABLE_MODEL",
                    )
                ):
                    self._raise_collision(
                        "The reserved Claude Code PrivacyFlow environment keys already exist. Confirm migration before they are replaced.",
                        prepared,
                        confirm_existing_config=confirm_existing_config,
                    )
            elif connector_id == "deepseek-harness" and paths[0].exists():
                value = _yaml_load(paths[0].read_bytes()) or {}
                if any(item in value.get("llm-pi-ai", {}).get("providers", {}) for item in ("pf", "apg")):
                    self._raise_collision(
                        "The reserved dsh PrivacyFlow provider already exists. Confirm migration before it is replaced.",
                        prepared,
                        confirm_existing_config=confirm_existing_config,
                    )
            elif connector_id == "nanobot" and paths[0].exists():
                value = self._load_json_object(paths[0])
                if any(item in value.get("providers", {}) for item in ("pf", "apg")) or any(item in value.get("modelPresets", {}) for item in ("PF", "APG")):
                    self._raise_collision(
                        "The reserved nanobot PrivacyFlow provider or preset already exists. Confirm migration before it is replaced.",
                        prepared,
                        confirm_existing_config=confirm_existing_config,
                    )
        except ConnectorError:
            raise
        except Exception as exc:
            raise ConnectorError(f"Cannot inspect existing Agent configuration: {exc}", code="CONNECTOR_CONFIG_INVALID") from exc

    @staticmethod
    def _raise_collision(
        message: str,
        prepared: list[PreparedFile],
        *,
        confirm_existing_config: bool,
    ) -> None:
        if confirm_existing_config:
            return
        raise ConnectorError(
            message,
            code="CONNECTOR_CONFIG_CONFLICT",
            status_code=409,
            paths=[str(item.path) for item in prepared],
            requires_confirmation=True,
        )

    def _validate_target(self, path: Path) -> None:
        if path.is_symlink():
            raise ConnectorError(f"Refusing symbolic link: {path}", code="CONNECTOR_PATH_UNSAFE")
        if path.exists():
            info = path.stat()
            if not stat.S_ISREG(info.st_mode):
                raise ConnectorError(f"Refusing non-regular file: {path}", code="CONNECTOR_PATH_UNSAFE")
            if hasattr(os, "getuid") and info.st_uid != os.getuid():
                raise ConnectorError(f"Refusing file owned by another user: {path}", code="CONNECTOR_PATH_UNSAFE")
        parent = path.parent
        while True:
            if parent.exists() and parent.is_symlink():
                raise ConnectorError(f"Refusing symbolic-link parent: {parent}", code="CONNECTOR_PATH_UNSAFE")
            if parent == parent.parent:
                break
            parent = parent.parent

    def _snapshot_path(self, item: dict[str, Any]) -> Path:
        raw = item.get("snapshot")
        if not isinstance(raw, str) or not raw:
            raise ConnectorError("A required Agent configuration snapshot is missing.", code="CONNECTOR_SNAPSHOT_MISSING", status_code=500)
        relative = Path(raw)
        if relative.is_absolute() or ".." in relative.parts:
            raise ConnectorError("The Agent Connector snapshot path is unsafe.", code="CONNECTOR_STATE_INVALID", status_code=500)
        root = self.state_dir.resolve()
        candidate = self.state_dir / relative
        current = candidate
        while current != self.state_dir:
            if current.is_symlink():
                raise ConnectorError("The Agent Connector snapshot path is unsafe.", code="CONNECTOR_PATH_UNSAFE", status_code=500)
            if current == current.parent:
                raise ConnectorError("The Agent Connector snapshot path is unsafe.", code="CONNECTOR_STATE_INVALID", status_code=500)
            current = current.parent
        try:
            candidate.resolve().relative_to(root)
        except (OSError, ValueError) as exc:
            raise ConnectorError("The Agent Connector snapshot path is unsafe.", code="CONNECTOR_STATE_INVALID", status_code=500) from exc
        return candidate

    def _replace_all(self, prepared: list[PreparedFile], snapshots: list[dict[str, Any]]) -> None:
        for item, snapshot in zip(prepared, snapshots, strict=True):
            path = item.path
            if snapshot["existed"]:
                expected = self._snapshot_path(snapshot).read_bytes()
                captured = self._capture_target(path)
                if not captured["existed"] or captured["content"] != expected:
                    raise ConnectorError(
                        "The Agent configuration changed while PrivacyFlow was preparing the connection.",
                        code="CONNECTOR_CONCURRENT_CHANGE",
                        status_code=409,
                        paths=[str(path)],
                    )
            elif path.exists():
                raise ConnectorError(
                    "The Agent configuration was created while PrivacyFlow was preparing the connection.",
                    code="CONNECTOR_CONCURRENT_CHANGE",
                    status_code=409,
                    paths=[str(path)],
                )
        replaced = 0
        try:
            for item in prepared:
                self._atomic_write(item.path, item.content, 0o600)
                replaced += 1
        except Exception:
            self._restore_files(snapshots[:replaced])
            raise

    def _restore_files(self, files: list[dict[str, Any]]) -> None:
        for item in files:
            path = Path(item["path"])
            self._validate_target(path)
            if item["existed"]:
                raw = self._snapshot_path(item).read_bytes()
                self._atomic_write(path, raw, int(item["mode"]))
            else:
                self._unlink_target(path)

    def _restore_transaction(self, files: list[dict[str, Any]]) -> None:
        current = self._capture_current_files(files)
        for item in files:
            if item["existed"] and not self._snapshot_path(item).is_file():
                raise ConnectorError("A required Agent configuration snapshot is missing.", code="CONNECTOR_SNAPSHOT_MISSING", status_code=500)
        replaced = 0
        try:
            for item in files:
                path = Path(item["path"])
                if item["existed"]:
                    self._atomic_write(path, self._snapshot_path(item).read_bytes(), int(item["mode"]))
                else:
                    self._unlink_target(path)
                replaced += 1
        except Exception:
            self._apply_captured_files(current[:replaced])
            raise

    def _capture_current_files(self, files: list[dict[str, Any]]) -> list[dict[str, Any]]:
        current: list[dict[str, Any]] = []
        for item in files:
            path = Path(item["path"])
            current.append({"path": path, **self._capture_target(path)})
        return current

    def _capture_paths(self, paths: list[Path]) -> list[dict[str, Any]]:
        return self._capture_current_files([{"path": str(path)} for path in paths])

    def _apply_captured_files(self, files: list[dict[str, Any]]) -> None:
        for item in reversed(files):
            if item["existed"]:
                self._atomic_write(item["path"], item["content"], int(item["mode"]))
            else:
                self._unlink_target(item["path"])

    def _changed_paths(self, active: dict[str, Any]) -> list[str]:
        changed = []
        for item in active["files"]:
            path = Path(item["path"])
            try:
                captured = self._capture_target(path)
                is_changed = not captured["existed"] or _sha256(captured["content"]) != item["connected_sha256"]
            except OSError:
                # An unreadable target is not safe to treat as unchanged. The
                # UI can request an explicit external-change restore without
                # receiving file contents or permissions.
                is_changed = True
            if is_changed:
                changed.append(str(path))
        return changed

    def _save_safety_backup(self, connector_id: str, active: dict[str, Any], paths: list[str]) -> None:
        root = self.transactions_dir / connector_id / "safety"
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(root, 0o700)
        backup = root / f"{int(time.time())}_{secrets.token_hex(4)}"
        backup.mkdir(mode=0o700)
        manifest = []
        for index, raw_path in enumerate(paths):
            path = Path(raw_path)
            captured = self._capture_target(path)
            if captured["existed"]:
                target = backup / f"{index}.backup"
                target.write_bytes(captured["content"])
                os.chmod(target, 0o600)
                manifest.append({"path": raw_path, "file": target.name, "mode": captured["mode"]})
            else:
                manifest.append({"path": raw_path, "file": None, "mode": None})
        (backup / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        os.chmod(backup / "manifest.json", 0o600)
        backups = sorted((item for item in root.iterdir() if item.is_dir()), key=lambda item: item.name, reverse=True)
        for old in backups[5:]:
            shutil.rmtree(old)

    def _atomic_write(self, path: Path, content: bytes, mode: int) -> None:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._validate_target(path)
        if os.name != "nt" and hasattr(os, "O_DIRECTORY") and hasattr(os, "O_NOFOLLOW"):
            parent_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            temporary_name = f".{path.name}.{secrets.token_hex(8)}"
            try:
                self._validate_target_at(parent_fd, path.name, path)
                descriptor = os.open(
                    temporary_name,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    mode,
                    dir_fd=parent_fd,
                )
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(content)
                    stream.flush()
                    os.fsync(stream.fileno())
                self._validate_target_at(parent_fd, path.name, path)
                os.replace(temporary_name, path.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
            finally:
                try:
                    os.unlink(temporary_name, dir_fd=parent_fd)
                except FileNotFoundError:
                    pass
                os.close(parent_fd)
            return
        fd, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        temporary = Path(name)
        try:
            os.fchmod(fd, mode)
            with os.fdopen(fd, "wb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            self._validate_target(path)
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)

    def _capture_target(self, path: Path) -> dict[str, Any]:
        self._validate_target(path)
        if not path.parent.exists():
            return {"existed": False, "content": b"", "mode": None}
        if os.name != "nt" and hasattr(os, "O_DIRECTORY") and hasattr(os, "O_NOFOLLOW"):
            parent_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                if not self._validate_target_at(parent_fd, path.name, path, allow_missing=True):
                    return {"existed": False, "content": b"", "mode": None}
                descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
                try:
                    info = os.fstat(descriptor)
                    if not stat.S_ISREG(info.st_mode) or (hasattr(os, "getuid") and info.st_uid != os.getuid()):
                        raise ConnectorError(f"Refusing unsafe file: {path}", code="CONNECTOR_PATH_UNSAFE")
                    with os.fdopen(descriptor, "rb") as stream:
                        descriptor = -1
                        content = stream.read()
                    return {"existed": True, "content": content, "mode": stat.S_IMODE(info.st_mode)}
                finally:
                    if descriptor >= 0:
                        os.close(descriptor)
            finally:
                os.close(parent_fd)
        self._validate_target(path)
        if not path.exists():
            return {"existed": False, "content": b"", "mode": None}
        content = path.read_bytes()
        self._validate_target(path)
        return {"existed": True, "content": content, "mode": stat.S_IMODE(path.stat().st_mode)}

    def _unlink_target(self, path: Path) -> None:
        self._validate_target(path)
        if not path.parent.exists():
            return
        if os.name != "nt" and hasattr(os, "O_DIRECTORY") and hasattr(os, "O_NOFOLLOW"):
            parent_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                if not self._validate_target_at(parent_fd, path.name, path, allow_missing=True):
                    return
                os.unlink(path.name, dir_fd=parent_fd)
            finally:
                os.close(parent_fd)
            return
        if path.exists():
            self._validate_target(path)
            path.unlink()

    @staticmethod
    def _validate_target_at(parent_fd: int, name: str, display_path: Path, *, allow_missing: bool = True) -> bool:
        try:
            info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            if allow_missing:
                return False
            raise
        if not stat.S_ISREG(info.st_mode):
            raise ConnectorError(f"Refusing non-regular file: {display_path}", code="CONNECTOR_PATH_UNSAFE")
        if hasattr(os, "getuid") and info.st_uid != os.getuid():
            raise ConnectorError(f"Refusing file owned by another user: {display_path}", code="CONNECTOR_PATH_UNSAFE")
        return True

    def _public_status(self, connector_id: str, state: dict[str, Any]) -> dict[str, Any]:
        active = state["active"].get(connector_id)
        changed = self._changed_paths(active) if active else []
        executable = self._executable(connector_id)
        installed = bool(executable)
        incomplete = self._transaction_issue(connector_id, active) if active else ""
        status = "attention_required" if incomplete else "configuration_changed" if changed else "connected" if active else "ready" if installed else "not_installed"
        detection = "package" if executable and "node_modules" in Path(executable).parts else "path"
        return {
            "id": connector_id, "name": CONNECTOR_NAMES[connector_id], "protocol": CONNECTOR_PROTOCOLS[connector_id],
            "installed": installed, "paths": [str(path) for path in self._paths(connector_id)],
            "command": COMMANDS[connector_id][0], "executable": executable,
            "detection": detection if executable else "not_found_on_pf_path",
            "status": status, "connected": bool(active), "external_changes": changed,
            "can_restore": bool(active), "model": active.get("model") if active else None,
        }

    def _executable(self, connector_id: str) -> str | None:
        """Resolve Agent CLIs using the PrivacyFlow process environment, not the shell UI.

        Desktop-launched PrivacyFlow processes often inherit a minimal PATH.  Include
        common user-level Node/Python install locations while never executing a
        discovered binary or treating a config directory as proof of install.
        """
        search_path = self.environ.get("PATH", "")
        candidates = [item for item in search_path.split(os.pathsep) if item]
        home = self.home
        candidates.extend(
            [
                str(home / ".local" / "bin"),
                str(home / ".npm-global" / "bin"),
                str(home / ".bun" / "bin"),
                str(home / ".volta" / "bin"),
                str(home / ".cargo" / "bin"),
                self.environ.get("NVM_BIN", ""),
                self.environ.get("PNPM_HOME", ""),
                self.environ.get("BUN_INSTALL", "") + "/bin" if self.environ.get("BUN_INSTALL") else "",
                self.environ.get("npm_config_prefix", "") + "/bin" if self.environ.get("npm_config_prefix") else "",
                "/opt/homebrew/bin",
                "/usr/local/bin",
            ]
        )
        merged_path = os.pathsep.join(dict.fromkeys(item for item in candidates if item))
        for command in COMMANDS[connector_id]:
            try:
                found = self.which(command, path=merged_path)
            except TypeError:
                found = self.which(command)
            if found:
                return str(found)
        return self._package_executable(connector_id)

    def _package_executable(self, connector_id: str) -> str | None:
        """Find an installed Node package when its bin shim is outside PATH.

        GUI-launched PrivacyFlow processes frequently miss the npm prefix inherited by
        an interactive shell.  The official DSH package can still be present in
        ``lib/node_modules`` even when its ``dsh`` shim was not linked; reading
        its package manifest lets the status page report the real installation
        without executing untrusted package code.
        """
        package_names = {
            "deepseek-harness": ("@deepseek-ai/dsh", "deepseek-harness"),
        }.get(connector_id, ())
        if not package_names:
            return None
        roots: list[Path] = []
        prefixes = [
            self.environ.get("npm_config_prefix", ""),
            self.environ.get("NPM_CONFIG_PREFIX", ""),
            self.environ.get("PNPM_HOME", ""),
            str(self.home / ".npm-global"),
            str(self.home / ".local"),
            str(self.home / "Library" / "pnpm"),
            str(self.home / ".pnpm"),
            str(self.home / ".bun" / "install" / "global"),
            "/opt/homebrew",
            "/usr/local",
        ]
        for entry in self.environ.get("PATH", "").split(os.pathsep):
            if entry:
                path = Path(entry).expanduser()
                if path.name == "bin":
                    prefixes.append(str(path.parent))
        for prefix in prefixes:
            if prefix:
                roots.append(Path(prefix).expanduser() / "lib" / "node_modules")
        pnpm_homes = [self.environ.get("PNPM_HOME", ""), str(self.home / "Library" / "pnpm"), str(self.home / ".pnpm")]
        for raw_pnpm_home in dict.fromkeys(item for item in pnpm_homes if item):
            pnpm_global = Path(raw_pnpm_home).expanduser() / "global"
            try:
                roots.extend(path for path in pnpm_global.glob("*/node_modules") if path.is_dir())
            except OSError:
                pass
        npm_caches = [
            self.environ.get("npm_config_cache", ""),
            self.environ.get("NPM_CONFIG_CACHE", ""),
            str(self.home / ".npm"),
            str(self.home / ".cache"),
        ]
        # ``npx @deepseek-ai/dsh`` is an official installation/run path. It
        # leaves the package under an opaque ``_npx/<hash>`` directory without
        # creating a global ``dsh`` shim, so inspect only its package manifest
        # and never execute the cached code.
        for raw_cache in dict.fromkeys(item for item in npm_caches if item):
            npx_root = Path(raw_cache).expanduser() / "_npx"
            try:
                roots.extend(path / "node_modules" for path in npx_root.iterdir() if (path / "node_modules").is_dir())
            except OSError:
                pass
        for root in dict.fromkeys(roots):
            for package_name in package_names:
                package_dir = root / package_name
                manifest_path = package_dir / "package.json"
                try:
                    if not manifest_path.is_file():
                        continue
                    manifest = json.loads(manifest_path.read_text("utf-8"))
                    bin_spec = manifest.get("bin") if isinstance(manifest, dict) else None
                    if isinstance(bin_spec, dict):
                        bin_spec = next(
                            (
                                bin_spec.get(name)
                                for name in ("dsh", "deepseek-harness", "deepseek")
                                if isinstance(bin_spec.get(name), str)
                            ),
                            next((item for item in bin_spec.values() if isinstance(item, str)), None),
                        )
                    if not isinstance(bin_spec, str) or not bin_spec.strip():
                        continue
                    candidate = (package_dir / bin_spec.strip()).resolve()
                    if not candidate.is_file():
                        continue
                    if hasattr(os, "getuid") and candidate.stat().st_uid != os.getuid():
                        continue
                    return str(candidate)
                except (OSError, ValueError, TypeError, json.JSONDecodeError):
                    continue
        return None

    def _transaction_issue(self, connector_id: str, active: dict[str, Any]) -> str:
        try:
            self.credential(connector_id)
        except Exception:
            return "credential_missing"
        for item in active.get("files", []):
            if item.get("existed"):
                try:
                    if not self._snapshot_path(item).is_file():
                        return "snapshot_missing"
                except ConnectorError:
                    return "snapshot_missing"
        return ""

    def _read_state(self) -> dict[str, Any]:
        if not self.index_path.exists():
            return {"version": 1, "active": {}, "completed": {}}
        try:
            value = json.loads(self.index_path.read_text("utf-8"))
        except (OSError, ValueError) as exc:
            raise ConnectorError(f"Cannot read connector state: {exc}", code="CONNECTOR_STATE_INVALID", status_code=500) from exc
        if not isinstance(value, dict) or not isinstance(value.get("active"), dict):
            raise ConnectorError("Connector state is invalid.", code="CONNECTOR_STATE_INVALID", status_code=500)
        value.setdefault("completed", {})
        return value

    def _write_state(self, state: dict[str, Any]) -> None:
        self._atomic_write(self.index_path, _json_bytes(state), 0o600)

    @contextmanager
    def _transaction_lock(self):
        """Serialize Connector transactions for this state directory.

        The process lock avoids the per-process behaviour differences of OS file
        locks (and makes separate service instances in one process safe).  The
        file lock covers separate PrivacyFlow processes.  Both locks are acquired
        in this order and released in ``finally`` so a failed transaction cannot
        strand either lock.
        """

        lock_key = os.path.normcase(str(self.state_dir))
        held = getattr(_HELD_TRANSACTION_LOCKS, "keys", set())
        self._process_lock.acquire()
        if lock_key in held:
            try:
                yield
            finally:
                self._process_lock.release()
            return

        lock_fd: int | None = None
        file_locked = False
        try:
            flags = os.O_RDWR | os.O_CREAT
            if hasattr(os, "O_CLOEXEC"):
                flags |= os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            lock_fd = os.open(self.lock_path, flags, 0o600)
            os.fchmod(lock_fd, 0o600)
            if fcntl is not None:
                fcntl.flock(lock_fd, fcntl.LOCK_EX)
            elif msvcrt is not None:  # pragma: no cover - Windows only
                # ``msvcrt.locking`` locks a byte starting at the current file
                # position. Keep one non-secret byte in the lock file.
                if os.fstat(lock_fd).st_size == 0:
                    os.write(lock_fd, b"\0")
                    os.fsync(lock_fd)
                os.lseek(lock_fd, 0, os.SEEK_SET)
                msvcrt.locking(lock_fd, msvcrt.LK_LOCK, 1)
            else:  # pragma: no cover - unsupported Python platform
                raise OSError("No supported cross-process file locking primitive is available")
            file_locked = True
            held.add(lock_key)
            _HELD_TRANSACTION_LOCKS.keys = held
            yield
        finally:
            try:
                held.discard(lock_key)
                if lock_fd is not None:
                    try:
                        if file_locked:
                            if fcntl is not None:
                                fcntl.flock(lock_fd, fcntl.LOCK_UN)
                            elif msvcrt is not None:  # pragma: no cover - Windows only
                                os.lseek(lock_fd, 0, os.SEEK_SET)
                                msvcrt.locking(lock_fd, msvcrt.LK_UNLCK, 1)
                    finally:
                        os.close(lock_fd)
            finally:
                self._process_lock.release()

    def _ensure_state_dirs(self) -> None:
        ensure_private_state_directory(self.state_dir)
        ensure_private_state_directory(self.transactions_dir, always_owned=True)

    def _prune_transaction_dirs(self, connector_id: str, keep: set[str]) -> None:
        root = self.transactions_dir / connector_id
        if not root.exists():
            return
        for path in root.iterdir():
            if path.is_dir() and path.name != "safety" and path.name not in keep:
                shutil.rmtree(path)

    def _validate_connector(self, connector_id: str) -> None:
        if connector_id not in CONNECTOR_NAMES:
            raise ConnectorError("Unknown Agent connector.", code="CONNECTOR_NOT_FOUND", status_code=404)

    def _validate_model(self, model: str) -> str:
        value = model.strip() if isinstance(model, str) else ""
        if not value or len(value) > 256 or any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise ConnectorError("The model ID is invalid.", code="CONNECTOR_MODEL_INVALID")
        return value
