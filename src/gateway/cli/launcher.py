from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
import tempfile
from collections.abc import Mapping, MutableMapping, Sequence
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlsplit, urlunparse

from gateway.upstream_protocol import (
    OPENAI_CHAT_COMPLETIONS,
    SUPPORTED_UPSTREAM_PROTOCOLS,
    UPSTREAM_PROTOCOL_ENDPOINTS,
    canonical_upstream_protocol,
)


DEFAULT_LAUNCHER_PATH = Path(".apg/launcher.json")
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


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="apg", description="Start Agent Privacy Gateway.")
    parser.add_argument("command", nargs="?", choices=["start", "credential"], default="start")
    parser.add_argument("--connector", choices=["codex", "claude-code", "deepseek-harness", "nanobot"])
    parser.add_argument("--launcher-config", type=Path, default=DEFAULT_LAUNCHER_PATH, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)

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
    host = os.environ.get("APG_HOST", "127.0.0.1")
    port = os.environ.get("APG_PORT", "8765")
    webui_url = f"http://{host}:{port}/ui/"
    print("Agent Privacy Gateway")
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
        config["local_api_key"] = generate_local_api_key()
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
    provider_key = environment.get("APG_UPSTREAM_API_KEY", "").strip() or str(
        (active_profile or {}).get("api_key", "")
    ).strip()
    provider_base_url = environment.get("APG_UPSTREAM_BASE_URL", "").strip() or str(
        (active_profile or {}).get("base_url", "")
    ).strip()
    provider_protocol = canonical_upstream_protocol(
        environment.get("APG_UPSTREAM_PROTOCOL", "") or str((active_profile or {}).get("protocol", ""))
    )
    provider_proxy = environment.get("APG_UPSTREAM_PROXY", "").strip() or str(
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
    existing_local_keys = [value.strip() for value in environment.get("APG_LOCAL_API_KEYS", "").split(",") if value.strip()]
    primary_local_key = environment.get("APG_PRIMARY_LOCAL_API_KEY", "").strip()
    if existing_local_keys:
        primary_local_key = primary_local_key or existing_local_keys[0]
        merged_local_keys = list(dict.fromkeys([*existing_local_keys, *connector_keys]))
    else:
        primary_local_key = primary_local_key or str(config["local_api_key"])
        merged_local_keys = list(dict.fromkeys([str(config["local_api_key"]), *connector_keys]))
    environment["APG_LOCAL_API_KEYS"] = ",".join(merged_local_keys)
    environment.setdefault("APG_PRIMARY_LOCAL_API_KEY", primary_local_key)
    defaults = {
        "APG_UPSTREAM_BASE_URL": str(config["_resolved_upstream_base_url"]),
        "APG_UPSTREAM_API_KEY": str(config["_resolved_upstream_api_key"]),
        "APG_UPSTREAM_PROTOCOL": str(config["_resolved_upstream_protocol"]),
        "APG_UPSTREAM_PROXY": str(config.get("_resolved_upstream_proxy", "")),
        "APG_UPSTREAM_STRIP_LOCAL_V1": "true" if config.get("strip_local_v1", True) else "false",
        "APG_SIGNING_SECRET": str(config["signing_secret"]),
        "APG_LAUNCHER_CONFIG_PATH": str(config["_launcher_config_path"]),
    }
    for key, value in defaults.items():
        environment.setdefault(key, value)


def generate_local_api_key() -> str:
    return f"apg_local_{secrets.token_urlsafe(24)}"


def load_connector_api_key(path: Path, connector_id: str) -> str:
    config = _read_launcher_config(path)
    keys = config.get("connector_api_keys", {})
    key = str(keys.get(connector_id, "")) if isinstance(keys, dict) else ""
    if not key:
        raise LauncherConfigError(f"No active APG credential exists for connector '{connector_id}'.")
    return key


def save_launcher_connector_api_key(path: Path, connector_id: str, api_key: str | None) -> None:
    config = prepare_launcher_config(path, environ={})
    keys = dict(config.get("connector_api_keys", {}))
    if api_key:
        keys[connector_id] = api_key
    else:
        keys.pop(connector_id, None)
    config["connector_api_keys"] = keys
    _write_launcher_config(path, _persistent_launcher_config(config))


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
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        pass
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
