from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
import tempfile
import threading
from contextlib import contextmanager
from collections.abc import Mapping, MutableMapping, Sequence
from functools import wraps
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlsplit, urlunparse

from gateway.compat import ensure_private_state_directory, get_env, legacy_cli_warning, set_pf_env
from gateway.migration import MigrationError, migrate_state, rollback_migration
from gateway.upstream_protocol import (
    OPENAI_CHAT_COMPLETIONS,
    SUPPORTED_UPSTREAM_PROTOCOLS,
    UPSTREAM_PROTOCOL_ENDPOINTS,
    canonical_upstream_protocol,
)

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows only
    fcntl = None

try:
    import msvcrt
except ImportError:  # pragma: no cover - POSIX only
    msvcrt = None


DEFAULT_LAUNCHER_PATH = Path(".privacyflow/launcher.json")
LEGACY_LAUNCHER_PATH = Path(".apg/launcher.json")
DEFAULT_UPSTREAM_PROFILE_NAME = "默认配置"
PERSISTED_LAUNCHER_KEYS = {
    "signing_secret",
    "local_api_key",
    "connector_api_keys",
    "strip_local_v1",
    "upstream_profiles",
    "active_upstream_profile_id",
}


class LauncherConfigError(RuntimeError):
    pass


_LAUNCHER_PROCESS_LOCKS: dict[str, threading.RLock] = {}
_LAUNCHER_PROCESS_LOCKS_GUARD = threading.Lock()
_HELD_LAUNCHER_LOCKS = threading.local()


def _launcher_process_lock(path: Path) -> threading.RLock:
    key = os.path.normcase(str(path.expanduser().resolve()))
    with _LAUNCHER_PROCESS_LOCKS_GUARD:
        return _LAUNCHER_PROCESS_LOCKS.setdefault(key, threading.RLock())


@contextmanager
def _launcher_transaction(path: Path):
    resolved = path.expanduser().resolve()
    key = os.path.normcase(str(resolved))
    process_lock = _launcher_process_lock(resolved)
    held = getattr(_HELD_LAUNCHER_LOCKS, "keys", set())
    process_lock.acquire()
    if key in held:
        try:
            yield
        finally:
            process_lock.release()
        return
    lock_fd: int | None = None
    file_locked = False
    try:
        ensure_private_state_directory(resolved.parent)
        flags = os.O_RDWR | os.O_CREAT
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        lock_fd = os.open(resolved.with_name(f"{resolved.name}.lock"), flags, 0o600)
        os.fchmod(lock_fd, 0o600)
        if fcntl is not None:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
        elif msvcrt is not None:  # pragma: no cover - Windows only
            if os.fstat(lock_fd).st_size == 0:
                os.write(lock_fd, b"\0")
                os.fsync(lock_fd)
            os.lseek(lock_fd, 0, os.SEEK_SET)
            msvcrt.locking(lock_fd, msvcrt.LK_LOCK, 1)
        else:  # pragma: no cover - unsupported platform
            raise OSError("No supported launcher file locking primitive is available")
        file_locked = True
        held.add(key)
        _HELD_LAUNCHER_LOCKS.keys = held
        yield
    finally:
        try:
            held.discard(key)
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
            process_lock.release()


def _launcher_locked(function):
    @wraps(function)
    def wrapped(path: Path, *args: Any, **kwargs: Any):
        with _launcher_transaction(path):
            return function(path, *args, **kwargs)

    return wrapped


def main(argv: Sequence[str] | None = None) -> None:
    legacy_cli = os.environ.get("PF_LEGACY_CLI") == "1"
    if legacy_cli:
        legacy_cli_warning()
    parser = argparse.ArgumentParser(prog="privacyflow", description="Start PrivacyFlow.")
    parser.add_argument("command", nargs="?", choices=["start", "credential", "migrate"], default="start")
    parser.add_argument("--connector", choices=["codex", "claude-code", "deepseek-harness", "nanobot"])
    parser.add_argument("--launcher-config", type=Path, default=_default_launcher_path(legacy_cli), help=argparse.SUPPRESS)
    args = parser.parse_args(argv)

    if args.command == "migrate":
        result = None
        try:
            result = migrate_state()
            from gateway.agent_connectors import AgentConnectorService

            connector_service = AgentConnectorService(
                result.destination,
                result.destination / "launcher.json",
            )
            connector_result = connector_service.migrate_legacy_namespace()
        except MigrationError as exc:
            parser.error(f"{exc} ({exc.code})")
        except Exception as exc:
            # The Connector transaction restores Agent files and its key ring.
            # Complete the outer state-directory rollback for both known
            # Connector conflicts and unexpected parser/I/O failures.
            if result is not None:
                rollback_migration(result)
            code = str(getattr(exc, "code", "PF_MIGRATION_FAILED"))
            parser.error(f"PrivacyFlow migration failed: {exc} ({code})")
        print(f"PrivacyFlow migration complete: {result.destination}")
        print(f"Legacy backup: {result.backup}")
        print(f"Agent configurations migrated: {connector_result['count']}")
        return

    if args.command == "credential":
        if not args.connector:
            parser.error("credential requires --connector")
        try:
            print(load_connector_api_key(args.launcher_config, args.connector))
        except LauncherConfigError as exc:
            parser.error(str(exc))
        return

    try:
        config = prepare_launcher_config(args.launcher_config)
    except LauncherConfigError as exc:
        parser.error(str(exc))

    apply_launcher_environment(config)
    host = str(get_env("HOST", default="127.0.0.1"))
    port = str(get_env("PORT", default="8765"))
    webui_url = f"http://{host}:{port}/ui/"
    print("PrivacyFlow")
    print(f"WebUI: {terminal_hyperlink(webui_url)}")
    if (
        config["_resolved_upstream_protocol"] not in SUPPORTED_UPSTREAM_PROTOCOLS
        or not config["_resolved_upstream_base_url"]
        or not config["_resolved_upstream_api_key"]
    ):
        print("Upstream connection: not configured (finish setup in the WebUI).")
    print("Press Ctrl+C to stop.")

    from gateway.server import main as server_main

    server_main()


def legacy_main(argv: Sequence[str] | None = None) -> None:
    """Compatibility entry point for the old ``apg`` executable."""

    previous = os.environ.get("PF_LEGACY_CLI")
    os.environ["PF_LEGACY_CLI"] = "1"
    try:
        main(argv)
    finally:
        if previous is None:
            os.environ.pop("PF_LEGACY_CLI", None)
        else:
            os.environ["PF_LEGACY_CLI"] = previous


def _default_launcher_path(legacy_cli: bool = False) -> Path:
    if legacy_cli and LEGACY_LAUNCHER_PATH.exists() and not DEFAULT_LAUNCHER_PATH.exists():
        return LEGACY_LAUNCHER_PATH
    return DEFAULT_LAUNCHER_PATH


def terminal_hyperlink(
    url: str,
    *,
    stream: Any | None = None,
    environ: Mapping[str, str] | None = None,
) -> str:
    """Render a clickable OSC 8 link in terminals, with a plain-text fallback."""
    output_stream = sys.stdout if stream is None else stream
    environment = os.environ if environ is None else environ
    safe_url = "".join(char if ord(char) >= 32 and ord(char) != 127 else "�" for char in url)
    is_tty = bool(getattr(output_stream, "isatty", lambda: False)())
    terminal_program = environment.get("TERM_PROGRAM", "").lower()
    if (
        safe_url != url
        or not is_tty
        or environment.get("TERM", "").lower() == "dumb"
        or terminal_program == "apple_terminal"
    ):
        return safe_url
    return f"\033]8;;{safe_url}\033\\{safe_url}\033]8;;\033\\"


@_launcher_locked
def prepare_launcher_config(
    path: Path,
    *,
    environ: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    environment = os.environ if environ is None else environ
    config = _read_launcher_config(path)
    changed = not path.exists()

    if not config.get("signing_secret"):
        config["signing_secret"] = secrets.token_urlsafe(32)
        changed = True
    if not config.get("local_api_key"):
        config["local_api_key"] = generate_local_api_key(legacy=_is_legacy_path(path))
        changed = True
    if "strip_local_v1" not in config:
        config["strip_local_v1"] = True
        changed = True
    if not isinstance(config.get("connector_api_keys"), dict):
        config["connector_api_keys"] = {}
        changed = True
    profiles, active_profile_id, profiles_changed = _normalize_upstream_profiles(config)
    changed = changed or profiles_changed
    changed = changed or any(
        key not in PERSISTED_LAUNCHER_KEYS and not key.startswith("_")
        for key in config
    )

    active_profile = next((profile for profile in profiles if profile["id"] == active_profile_id), None)
    provider_key = str(get_env("UPSTREAM_API_KEY", environ=environment, default="")).strip() or str(
        (active_profile or {}).get("api_key", "")
    ).strip()
    provider_base_url = str(get_env("UPSTREAM_BASE_URL", environ=environment, default="")).strip() or str(
        (active_profile or {}).get("base_url", "")
    ).strip()
    provider_protocol = canonical_upstream_protocol(
        str(get_env("UPSTREAM_PROTOCOL", environ=environment, default="")) or str((active_profile or {}).get("protocol", ""))
    )
    provider_proxy = str(get_env("UPSTREAM_PROXY", environ=environment, default="")).strip() or str(
        (active_profile or {}).get("proxy", "")
    ).strip()

    config["upstream_profiles"] = profiles
    config["active_upstream_profile_id"] = active_profile_id
    config["_resolved_upstream_api_key"] = provider_key
    config["_resolved_upstream_base_url"] = provider_base_url.rstrip("/")
    config["_resolved_upstream_protocol"] = provider_protocol
    config["_resolved_upstream_proxy"] = provider_proxy
    config["_launcher_config_path"] = str(path.resolve())
    if changed:
        _write_launcher_config(path, {key: value for key, value in config.items() if not key.startswith("_")})
    return config


def apply_launcher_environment(
    config: Mapping[str, Any],
    *,
    environ: MutableMapping[str, str] | None = None,
) -> None:
    environment = os.environ if environ is None else environ
    connector_keys = [str(value) for value in config.get("connector_api_keys", {}).values() if value]
    existing_local_keys = [value.strip() for value in str(get_env("LOCAL_API_KEYS", environ=environment, default="")).split(",") if value.strip()]
    primary_local_key = str(get_env("PRIMARY_LOCAL_API_KEY", environ=environment, default="")).strip()
    if existing_local_keys:
        primary_local_key = primary_local_key or existing_local_keys[0]
        merged_local_keys = list(dict.fromkeys([*existing_local_keys, *connector_keys]))
    else:
        primary_local_key = primary_local_key or str(config["local_api_key"])
        merged_local_keys = list(dict.fromkeys([str(config["local_api_key"]), *connector_keys]))
    merged_local_key_value = ",".join(merged_local_keys)
    legacy_local_keys_present = "APG_LOCAL_API_KEYS" in environment
    set_pf_env(environment, "LOCAL_API_KEYS", merged_local_key_value)
    if legacy_local_keys_present:
        # Keep an explicitly supplied legacy variable equal to PF so the
        # compatibility reader does not observe a conflict after Connector
        # keys are merged. New processes do not emit APG variables.
        environment["APG_LOCAL_API_KEYS"] = merged_local_key_value
    environment.setdefault("PF_PRIMARY_LOCAL_API_KEY", primary_local_key)
    if "APG_PRIMARY_LOCAL_API_KEY" in environment:
        environment["APG_PRIMARY_LOCAL_API_KEY"] = environment["PF_PRIMARY_LOCAL_API_KEY"]
    defaults = {
        "UPSTREAM_BASE_URL": str(config["_resolved_upstream_base_url"]),
        "UPSTREAM_API_KEY": str(config["_resolved_upstream_api_key"]),
        "UPSTREAM_PROTOCOL": str(config["_resolved_upstream_protocol"]),
        "UPSTREAM_PROXY": str(config.get("_resolved_upstream_proxy", "")),
        "UPSTREAM_STRIP_LOCAL_V1": "true" if config.get("strip_local_v1", True) else "false",
        "SIGNING_SECRET": str(config["signing_secret"]),
        "LAUNCHER_CONFIG_PATH": str(config["_launcher_config_path"]),
    }
    for key, value in defaults.items():
        canonical, legacy = (f"PF_{key}", f"APG_{key}")
        resolved = str(get_env(key, environ=environment, default=value))
        environment.setdefault(canonical, resolved)
        if legacy in environment:
            environment[legacy] = environment[canonical]


def generate_local_api_key(*, legacy: bool = False) -> str:
    return f"{'apg' if legacy else 'pf'}_local_{secrets.token_urlsafe(24)}"


def _is_legacy_path(path: Path) -> bool:
    return ".apg" in path.parts and ".privacyflow" not in path.parts


def load_connector_api_key(path: Path, connector_id: str) -> str:
    config = _read_launcher_config(path)
    keys = config.get("connector_api_keys", {})
    key = str(keys.get(connector_id, "")) if isinstance(keys, dict) else ""
    if not key:
        raise LauncherConfigError(f"No active PrivacyFlow credential exists for connector '{connector_id}'.")
    return key


def save_launcher_connector_api_key(path: Path, connector_id: str, api_key: str | None) -> None:
    save_launcher_connector_api_keys(path, {connector_id: api_key})


@_launcher_locked
def save_launcher_connector_api_keys(path: Path, updates: Mapping[str, str | None]) -> None:
    """Apply Connector credential changes in one atomic launcher write."""

    config = prepare_launcher_config(path, environ={})
    keys = dict(config.get("connector_api_keys", {}))
    for connector_id, api_key in updates.items():
        if api_key:
            keys[connector_id] = api_key
        else:
            keys.pop(connector_id, None)
    config["connector_api_keys"] = keys
    _write_launcher_config(path, _persistent_launcher_config(config))


@_launcher_locked
def save_launcher_local_api_key(path: Path, api_key: str) -> str:
    normalized = api_key.strip()
    if not normalized or len(normalized) > 4096:
        raise LauncherConfigError("The local API key must contain between 1 and 4096 characters.")
    if any(ord(char) < 32 or ord(char) == 127 for char in normalized):
        raise LauncherConfigError("The local API key contains unsupported control characters.")
    config = prepare_launcher_config(path, environ={})
    config["local_api_key"] = normalized
    _write_launcher_config(path, _persistent_launcher_config(config))
    return normalized


@_launcher_locked
def save_launcher_upstream_profile(
    path: Path,
    *,
    profile_id: str,
    name: str,
    protocol: str,
    base_url: str,
    api_key: str,
    endpoint_overrides: Mapping[str, str] | None = None,
    proxy: str | None = None,
    provider_type: str | None = None,
    models_url: str | None = None,
    user_agent: str | None = None,
    model_catalog: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    normalized_protocol = normalize_upstream_protocol(protocol)
    normalized_base_url = normalize_upstream_base_url(base_url)
    normalized_overrides = normalize_upstream_endpoint_overrides(endpoint_overrides or {})
    normalized_name = normalize_upstream_profile_name(name)
    config = prepare_launcher_config(path, environ={})
    profiles = [dict(profile) for profile in config["upstream_profiles"]]
    existing = next((profile for profile in profiles if profile["id"] == profile_id), None)
    normalized_proxy = normalize_upstream_proxy(
        proxy if proxy is not None else str((existing or {}).get("proxy", ""))
    )
    normalized_key = api_key.strip() or str((existing or {}).get("api_key", "")).strip()
    if not normalized_key or len(normalized_key) > 4096:
        raise LauncherConfigError("The upstream API key must contain between 1 and 4096 characters.")
    if any(ord(char) < 32 or ord(char) == 127 for char in normalized_key):
        raise LauncherConfigError("The upstream API key contains unsupported control characters.")
    resolved_id = profile_id if existing is not None else f"up_{secrets.token_urlsafe(12)}"
    normalized_provider_type = str(
        provider_type if provider_type is not None else (existing or {}).get("provider_type", "custom")
    ).strip() or "custom"
    if len(normalized_provider_type) > 64 or any(ord(char) < 32 or ord(char) == 127 for char in normalized_provider_type):
        raise LauncherConfigError("The upstream provider type is invalid.")
    normalized_models_url = normalize_upstream_models_url(str(
        models_url if models_url is not None else (existing or {}).get("models_url", "")
    ))
    normalized_user_agent = str(
        user_agent if user_agent is not None else (existing or {}).get("user_agent", "")
    ).strip()
    if len(normalized_user_agent) > 256 or any(ord(char) < 32 or ord(char) > 126 for char in normalized_user_agent):
        raise LauncherConfigError("The upstream User-Agent is invalid.")
    profile = {
        "id": resolved_id,
        "name": normalized_name,
        "protocol": normalized_protocol,
        "base_url": normalized_base_url,
        "api_key": normalized_key,
        "endpoint_overrides": normalized_overrides,
        "proxy": normalized_proxy,
        "provider_type": normalized_provider_type,
        "models_url": normalized_models_url,
        "user_agent": normalized_user_agent,
        "model_catalog": dict(model_catalog) if isinstance(model_catalog, Mapping) else dict((existing or {}).get("model_catalog", {})),
    }
    profiles = [profile if item["id"] == resolved_id else item for item in profiles]
    if existing is None:
        profiles.append(profile)
    config["upstream_profiles"] = profiles
    config["active_upstream_profile_id"] = resolved_id
    _write_launcher_config(path, _persistent_launcher_config(config))
    return profile


@_launcher_locked
def activate_launcher_upstream_profile(path: Path, profile_id: str) -> dict[str, Any]:
    config = prepare_launcher_config(path, environ={})
    profile = next(
        (profile for profile in config["upstream_profiles"] if profile["id"] == profile_id),
        None,
    )
    if profile is None:
        raise LauncherConfigError("The upstream profile does not exist.")
    config["active_upstream_profile_id"] = profile_id
    _write_launcher_config(path, _persistent_launcher_config(config))
    return dict(profile)


@_launcher_locked
def delete_launcher_upstream_profile(path: Path, profile_id: str) -> dict[str, Any] | None:
    config = prepare_launcher_config(path, environ={})
    profiles = [dict(profile) for profile in config["upstream_profiles"]]
    if not any(profile["id"] == profile_id for profile in profiles):
        raise LauncherConfigError("The upstream profile does not exist.")
    profiles = [profile for profile in profiles if profile["id"] != profile_id]
    active_id = str(config.get("active_upstream_profile_id", ""))
    if active_id == profile_id:
        active_id = str(profiles[0]["id"]) if profiles else ""
    config["upstream_profiles"] = profiles
    config["active_upstream_profile_id"] = active_id
    _write_launcher_config(path, _persistent_launcher_config(config))
    return next((profile for profile in profiles if profile["id"] == active_id), None)


def load_launcher_upstream_profiles(path: Path) -> tuple[list[dict[str, Any]], str]:
    config = prepare_launcher_config(path, environ={})
    return [dict(profile) for profile in config["upstream_profiles"]], str(
        config.get("active_upstream_profile_id", "")
    )


def normalize_upstream_profile_name(name: str) -> str:
    normalized = name.strip()
    if not normalized or len(normalized) > 80:
        raise LauncherConfigError("The upstream profile name must contain between 1 and 80 characters.")
    if any(ord(char) < 32 or ord(char) == 127 for char in normalized):
        raise LauncherConfigError("The upstream profile name contains unsupported control characters.")
    return normalized


def normalize_upstream_proxy(proxy: str) -> str:
    """Normalize an explicit upstream proxy URL; empty means no proxy."""
    normalized = proxy.strip()
    if not normalized:
        return ""
    parsed = urlsplit(normalized)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise LauncherConfigError("The upstream proxy must be an http:// or https:// URL.")
    return normalized


def normalize_upstream_protocol(protocol: str) -> str:
    normalized = canonical_upstream_protocol(protocol)
    if normalized not in SUPPORTED_UPSTREAM_PROTOCOLS:
        raise LauncherConfigError(
            "The upstream protocol must be 'openai_chat_completions', 'openai_responses', "
            "or 'anthropic_messages'."
        )
    return normalized


def normalize_upstream_base_url(base_url: str) -> str:
    normalized = _validate_upstream_url(base_url)
    parsed = urlparse(normalized)
    path = parsed.path.rstrip("/")
    terminal_suffixes = sorted(
        {endpoint.removeprefix("/v1") for endpoint in UPSTREAM_PROTOCOL_ENDPOINTS.values()} | {"/models"},
        key=len,
        reverse=True,
    )
    for suffix in terminal_suffixes:
        if path.endswith(suffix):
            path = path[: -len(suffix)].rstrip("/")
            break
    return urlunparse((parsed.scheme, parsed.netloc, path, "", "", "")).rstrip("/")


def normalize_upstream_endpoint_overrides(overrides: Mapping[str, str]) -> dict[str, str]:
    normalized: dict[str, str] = {}
    for raw_protocol, raw_url in overrides.items():
        url = str(raw_url).strip()
        if not url:
            continue
        protocol = normalize_upstream_protocol(str(raw_protocol))
        normalized[protocol] = _validate_upstream_url(url)
    return normalized


def normalize_upstream_models_url(models_url: str) -> str:
    normalized = models_url.strip().rstrip("/")
    if not normalized:
        return ""
    return _validate_upstream_url(normalized)


def _safe_normalize_models_url(value: Any) -> str:
    try:
        return normalize_upstream_models_url(str(value or ""))
    except LauncherConfigError:
        return ""


def _safe_normalize_provider_type(value: Any) -> str:
    normalized = str(value or "").strip() or "custom"
    if len(normalized) > 64 or any(ord(char) < 32 or ord(char) == 127 for char in normalized):
        return "custom"
    return normalized


def _safe_normalize_user_agent(value: Any) -> str:
    normalized = str(value or "").strip()
    if len(normalized) > 256 or any(ord(char) < 32 or ord(char) > 126 for char in normalized):
        return ""
    return normalized


def _validate_upstream_url(base_url: str) -> str:
    normalized = base_url.strip().rstrip("/")
    if not normalized or len(normalized) > 2048:
        raise LauncherConfigError("The upstream Base URL must contain between 1 and 2048 characters.")
    if any(ord(char) < 32 or ord(char) == 127 for char in normalized):
        raise LauncherConfigError("The upstream Base URL contains unsupported control characters.")
    try:
        parsed = urlparse(normalized)
        hostname = parsed.hostname
        _ = parsed.port
    except ValueError as exc:
        raise LauncherConfigError("The upstream Base URL is malformed.") from exc
    if parsed.scheme not in {"http", "https"} or not hostname or any(char.isspace() for char in hostname):
        raise LauncherConfigError("The upstream Base URL must be an absolute HTTP or HTTPS URL.")
    if parsed.username is not None or parsed.password is not None:
        raise LauncherConfigError("The upstream Base URL must not contain embedded credentials.")
    if parsed.query or parsed.fragment:
        raise LauncherConfigError("The upstream Base URL must not contain a query string or fragment.")
    return normalized


def _normalize_upstream_profiles(config: dict[str, Any]) -> tuple[list[dict[str, Any]], str, bool]:
    changed = False
    raw_profiles = config.get("upstream_profiles")
    profiles: list[dict[str, Any]] = []
    if isinstance(raw_profiles, list):
        for index, raw in enumerate(raw_profiles):
            if not isinstance(raw, dict):
                changed = True
                continue
            profile_id = str(raw.get("id") or f"up_{secrets.token_urlsafe(12)}")
            name = str(raw.get("name") or f"配置 {index + 1}")
            protocol = canonical_upstream_protocol(str(raw.get("protocol", "")))
            if protocol not in SUPPORTED_UPSTREAM_PROTOCOLS:
                protocol = OPENAI_CHAT_COMPLETIONS
            raw_overrides = raw.get("endpoint_overrides", {})
            if not isinstance(raw_overrides, dict):
                raw_overrides = {}
                changed = True
            endpoint_overrides = {
                canonical_upstream_protocol(str(key)): str(value).strip().rstrip("/")
                for key, value in raw_overrides.items()
                if canonical_upstream_protocol(str(key)) in SUPPORTED_UPSTREAM_PROTOCOLS
                and str(value).strip()
            }
            profile = {
                "id": profile_id,
                "name": name,
                "protocol": protocol,
                "base_url": str(raw.get("base_url", "")).rstrip("/"),
                "api_key": str(raw.get("api_key", "")).strip(),
                "endpoint_overrides": endpoint_overrides,
                "proxy": str(raw.get("proxy", "")).strip(),
                "provider_type": _safe_normalize_provider_type(raw.get("provider_type", "custom")),
                "models_url": _safe_normalize_models_url(raw.get("models_url", "")),
                "user_agent": _safe_normalize_user_agent(raw.get("user_agent", "")),
                "model_catalog": dict(raw.get("model_catalog", {})) if isinstance(raw.get("model_catalog"), dict) else {},
            }
            if profile != raw:
                changed = True
            profiles.append(profile)
    else:
        changed = True
    active_id = str(config.get("active_upstream_profile_id", ""))
    if not any(profile["id"] == active_id for profile in profiles):
        active_id = str(profiles[0]["id"]) if profiles else ""
        changed = True
    config["upstream_profiles"] = profiles
    config["active_upstream_profile_id"] = active_id
    return profiles, active_id, changed


def _read_launcher_config(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise LauncherConfigError(f"Cannot read {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise LauncherConfigError(f"{path} must contain a JSON object.")
    return raw


def _persistent_launcher_config(config: Mapping[str, Any]) -> dict[str, Any]:
    return {key: config[key] for key in PERSISTED_LAUNCHER_KEYS if key in config}


def _write_launcher_config(path: Path, config: Mapping[str, Any]) -> None:
    ensure_private_state_directory(path.parent)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(config, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    finally:
        temporary.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
