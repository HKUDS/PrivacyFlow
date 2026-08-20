from __future__ import annotations

import hashlib
import io
import json
import os
import secrets
import shutil
import stat
import tempfile
import time
from collections.abc import MutableMapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

import tomlkit
from ruamel.yaml import YAML

from gateway.cli.launcher import generate_local_api_key, save_launcher_connector_api_key


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
    # The official npm package is @deepseek-ai/dsh and installs ``dsh``.
    # Keep the older distribution name as a harmless fallback for users who
    # installed a pre-release wrapper with that entry point.
    "deepseek-harness": ("dsh", "deepseek-harness"),
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
        # than APG's current working directory. Persist absolute state paths so
        # the generated Codex command and every restore transaction resolve the
        # same files after a process restart.
        self.state_dir = state_dir.expanduser().resolve()
        self.launcher_path = launcher_path.expanduser().resolve()
        self.environ = dict(os.environ if environ is None else environ)
        self.home = home or Path.home()
        self.which = which
        self.base_url = base_url.rstrip("/")
        self.index_path = state_dir / "agent-connections.json"
        self.transactions_dir = state_dir / "agent-connection-transactions"
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
                    "The Agent configuration changed after APG connected it. Restore the original configuration first.",
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
        prepared = self._prepare(connector_id, model, models, key="__APG_CONNECTOR_KEY__")
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
        key = generate_local_api_key()
        prepared = self._prepare(connector_id, model, models, key=key)
        connector_transactions_dir = self.transactions_dir / connector_id
        connector_transactions_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(connector_transactions_dir, 0o700)
        transaction_dir = connector_transactions_dir / transaction_id
        transaction_dir.mkdir(mode=0o700)
        os.chmod(transaction_dir, 0o700)
        files: list[dict[str, Any]] = []
        for index, item in enumerate(prepared):
            existed = item.path.exists()
            raw = item.path.read_bytes() if existed else b""
            mode = stat.S_IMODE(item.path.stat().st_mode) if existed else None
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
        self._validate_connector(connector_id)
        state = self._read_state()
        active = state["active"].get(connector_id)
        if not active:
            return self._public_status(connector_id, state)
        changed = self._changed_paths(active)
        if changed and not confirm_external_changes:
            raise ConnectorError(
                "The Agent configuration changed after APG connected it. Confirm to save a safety backup and restore the original files.",
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
        self._prune_transaction_dirs(connector_id, {item["id"] for item in completed})
        return self._public_status(connector_id, state)

    def credential(self, connector_id: str) -> str:
        from gateway.cli.launcher import load_connector_api_key
        return load_connector_api_key(self.launcher_path, connector_id)

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
            provider["name"] = "Agent Privacy Gateway"
            provider["base_url"] = f"{self.base_url}/v1"
            provider["wire_api"] = "responses"
            auth = tomlkit.table()
            auth["command"] = "apg"
            auth["args"] = ["credential", "--connector", "codex", "--launcher-config", str(self.launcher_path)]
            provider["auth"] = auth
            providers["apg"] = provider
            value["model_provider"] = "apg"
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
            providers["apg"] = {
                "displayName": "Agent Privacy Gateway", "api": "openai-completions",
                "baseURL": f"{self.base_url}/v1", "apiKeyEnv": "APG_DSH_API_KEY",
                "models": [{"id": item, "name": item, "input": ["text"]} for item in models],
            }
            settings["agent-default-model"] = {"provider": "apg", "model": model}
            credentials["APG_DSH_API_KEY"] = key
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
        providers["apg"] = {"apiKey": key, "apiBase": f"{self.base_url}/v1", "apiType": "chat_completions"}
        presets["APG"] = {"provider": "apg", "model": model}
        agents["modelPreset"] = "APG"
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
                if "apg" in value.get("model_providers", {}):
                    self._raise_collision(
                        "The reserved Codex provider 'apg' already exists. Confirm migration before APG replaces it.",
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
                        "The reserved Claude Code APG environment keys already exist. Confirm migration before APG replaces them.",
                        prepared,
                        confirm_existing_config=confirm_existing_config,
                    )
            elif connector_id == "deepseek-harness" and paths[0].exists():
                value = _yaml_load(paths[0].read_bytes()) or {}
                if "apg" in value.get("llm-pi-ai", {}).get("providers", {}):
                    self._raise_collision(
                        "The reserved dsh provider 'apg' already exists. Confirm migration before APG replaces it.",
                        prepared,
                        confirm_existing_config=confirm_existing_config,
                    )
            elif connector_id == "nanobot" and paths[0].exists():
                value = self._load_json_object(paths[0])
                if "apg" in value.get("providers", {}) or "APG" in value.get("modelPresets", {}):
                    self._raise_collision(
                        "The reserved nanobot provider or preset already exists. Confirm migration before APG replaces it.",
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

    def _replace_all(self, prepared: list[PreparedFile], snapshots: list[dict[str, Any]]) -> None:
        for item, snapshot in zip(prepared, snapshots, strict=True):
            path = item.path
            if snapshot["existed"]:
                expected = (self.state_dir / snapshot["snapshot"]).read_bytes()
                if not path.exists() or path.is_symlink() or not path.is_file() or path.read_bytes() != expected:
                    raise ConnectorError(
                        "The Agent configuration changed while APG was preparing the connection.",
                        code="CONNECTOR_CONCURRENT_CHANGE",
                        status_code=409,
                        paths=[str(path)],
                    )
            elif path.exists():
                raise ConnectorError(
                    "The Agent configuration was created while APG was preparing the connection.",
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
                raw = (self.state_dir / item["snapshot"]).read_bytes()
                self._atomic_write(path, raw, int(item["mode"]))
            elif path.exists():
                path.unlink()

    def _restore_transaction(self, files: list[dict[str, Any]]) -> None:
        current = self._capture_current_files(files)
        for item in files:
            path = Path(item["path"])
            if item["existed"] and not (self.state_dir / item["snapshot"]).is_file():
                raise ConnectorError("A required Agent configuration snapshot is missing.", code="CONNECTOR_SNAPSHOT_MISSING", status_code=500)
        replaced = 0
        try:
            for item in files:
                path = Path(item["path"])
                if item["existed"]:
                    self._atomic_write(path, (self.state_dir / item["snapshot"]).read_bytes(), int(item["mode"]))
                elif path.exists():
                    path.unlink()
                replaced += 1
        except Exception:
            self._apply_captured_files(current[:replaced])
            raise

    def _capture_current_files(self, files: list[dict[str, Any]]) -> list[dict[str, Any]]:
        current: list[dict[str, Any]] = []
        for item in files:
            path = Path(item["path"])
            self._validate_target(path)
            current.append({
                "path": path,
                "existed": path.exists(),
                "content": path.read_bytes() if path.exists() else b"",
                "mode": stat.S_IMODE(path.stat().st_mode) if path.exists() else None,
            })
        return current

    def _apply_captured_files(self, files: list[dict[str, Any]]) -> None:
        for item in reversed(files):
            if item["existed"]:
                self._atomic_write(item["path"], item["content"], int(item["mode"]))
            elif item["path"].exists():
                item["path"].unlink()

    def _changed_paths(self, active: dict[str, Any]) -> list[str]:
        changed = []
        for item in active["files"]:
            path = Path(item["path"])
            try:
                is_changed = (
                    not path.exists()
                    or path.is_symlink()
                    or not path.is_file()
                    or _sha256(path.read_bytes()) != item["connected_sha256"]
                )
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
            if path.exists() and path.is_file() and not path.is_symlink():
                target = backup / f"{index}.backup"
                target.write_bytes(path.read_bytes())
                os.chmod(target, 0o600)
                manifest.append({"path": raw_path, "file": target.name, "mode": stat.S_IMODE(path.stat().st_mode)})
            else:
                manifest.append({"path": raw_path, "file": None, "mode": None})
        (backup / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        os.chmod(backup / "manifest.json", 0o600)
        backups = sorted((item for item in root.iterdir() if item.is_dir()), key=lambda item: item.name, reverse=True)
        for old in backups[5:]:
            shutil.rmtree(old)

    def _atomic_write(self, path: Path, content: bytes, mode: int) -> None:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        temporary = Path(name)
        try:
            os.fchmod(fd, mode)
            with os.fdopen(fd, "wb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)

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
            "detection": detection if executable else "not_found_on_apg_path",
            "status": status, "connected": bool(active), "external_changes": changed,
            "can_restore": bool(active), "model": active.get("model") if active else None,
        }

    def _executable(self, connector_id: str) -> str | None:
        """Resolve Agent CLIs using the APG process environment, not the shell UI.

        Desktop-launched APG processes often inherit a minimal PATH.  Include
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

        GUI-launched APG processes frequently miss the npm prefix inherited by
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
                        bin_spec = bin_spec.get("dsh") or bin_spec.get("deepseek-harness")
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
            if item.get("existed") and not (self.state_dir / str(item.get("snapshot", ""))).is_file():
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

    def _ensure_state_dirs(self) -> None:
        for path in (self.state_dir, self.transactions_dir):
            path.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.chmod(path, 0o700)

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
