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
from urllib.parse import urlparse, urlunparse

from gateway.upstream_protocol import (
    DEFAULT_UPSTREAM_PROTOCOLS,
    OPENAI_CHAT_COMPLETIONS,
    SUPPORTED_UPSTREAM_PROTOCOLS,
    UPSTREAM_PROTOCOL_ENDPOINTS,
    canonical_upstream_protocol,
)


DEFAULT_LAUNCHER_PATH = Path(".apg/launcher.json")
DEFAULT_UPSTREAM_PROFILE_NAME = "默认配置"


class LauncherConfigError(RuntimeError):
    pass


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="apg", description="Start Agent Privacy Gateway.")
    parser.add_argument("command", nargs="?", choices=["start"], default="start")
    parser.add_argument("--launcher-config", type=Path, default=DEFAULT_LAUNCHER_PATH, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)

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
    if safe_url != url or not is_tty or environment.get("TERM", "").lower() == "dumb":
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
    if "admin_api_key" in config:
        config.pop("admin_api_key", None)
        changed = True
    if "strip_local_v1" not in config:
        config["strip_local_v1"] = True
        changed = True
    profiles, active_profile_id, profiles_changed = _normalize_upstream_profiles(config)
    changed = changed or profiles_changed

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

    config["upstream_profiles"] = profiles
    config["active_upstream_profile_id"] = active_profile_id
    config["_resolved_upstream_api_key"] = provider_key
    config["_resolved_upstream_base_url"] = provider_base_url.rstrip("/")
    config["_resolved_upstream_protocol"] = provider_protocol
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
    defaults = {
        "APG_UPSTREAM_BASE_URL": str(config["_resolved_upstream_base_url"]),
        "APG_UPSTREAM_API_KEY": str(config["_resolved_upstream_api_key"]),
        "APG_UPSTREAM_PROTOCOL": str(config["_resolved_upstream_protocol"]),
        "APG_UPSTREAM_STRIP_LOCAL_V1": "true" if config.get("strip_local_v1", True) else "false",
        "APG_LOCAL_API_KEYS": str(config["local_api_key"]),
        "APG_SIGNING_SECRET": str(config["signing_secret"]),
        "APG_LAUNCHER_CONFIG_PATH": str(config["_launcher_config_path"]),
    }
    for key, value in defaults.items():
        environment.setdefault(key, value)


def generate_local_api_key() -> str:
    return f"apg_local_{secrets.token_urlsafe(24)}"


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


def save_launcher_upstream_api_key(path: Path, api_key: str) -> None:
    config = prepare_launcher_config(path, environ={})
    active = next(
        (
            profile
            for profile in config["upstream_profiles"]
            if profile["id"] == config["active_upstream_profile_id"]
        ),
        None,
    )
    save_launcher_upstream_profile(
        path,
        profile_id=str((active or {}).get("id", "")),
        name=str((active or {}).get("name") or DEFAULT_UPSTREAM_PROFILE_NAME),
        protocol=str((active or {}).get("protocol", "")),
        protocols=(active or {}).get("protocols"),
        base_url=str((active or {}).get("base_url", "")),
        api_key=api_key,
        endpoint_overrides=(active or {}).get("endpoint_overrides"),
    )


def save_launcher_upstream_configuration(path: Path, protocol: str, base_url: str, api_key: str) -> tuple[str, str, str]:
    config = prepare_launcher_config(path, environ={})
    active_id = str(config.get("active_upstream_profile_id", ""))
    active = next(
        (profile for profile in config["upstream_profiles"] if profile["id"] == active_id),
        None,
    )
    profile = save_launcher_upstream_profile(
        path,
        profile_id=active_id,
        name=str((active or {}).get("name") or DEFAULT_UPSTREAM_PROFILE_NAME),
        protocol=protocol,
        base_url=base_url,
        api_key=api_key,
    )
    return str(profile["protocol"]), str(profile["base_url"]), str(profile["api_key"])


def save_launcher_upstream_profile(
    path: Path,
    *,
    profile_id: str,
    name: str,
    protocol: str,
    base_url: str,
    api_key: str,
    protocols: Sequence[str] | None = None,
    endpoint_overrides: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    normalized_protocol = normalize_upstream_protocol(protocol)
    normalized_protocols = list(DEFAULT_UPSTREAM_PROTOCOLS)
    normalized_base_url = normalize_upstream_base_url(base_url)
    normalized_overrides = normalize_upstream_endpoint_overrides(endpoint_overrides or {})
    normalized_name = normalize_upstream_profile_name(name)
    config = prepare_launcher_config(path, environ={})
    profiles = [dict(profile) for profile in config["upstream_profiles"]]
    existing = next((profile for profile in profiles if profile["id"] == profile_id), None)
    normalized_key = api_key.strip() or str((existing or {}).get("api_key", "")).strip()
    if not normalized_key or len(normalized_key) > 4096:
        raise LauncherConfigError("The upstream API key must contain between 1 and 4096 characters.")
    if any(ord(char) < 32 or ord(char) == 127 for char in normalized_key):
        raise LauncherConfigError("The upstream API key contains unsupported control characters.")
    resolved_id = profile_id if existing is not None else f"up_{secrets.token_urlsafe(12)}"
    profile = {
        "id": resolved_id,
        "name": normalized_name,
        "protocol": normalized_protocol,
        "protocols": normalized_protocols,
        "base_url": normalized_base_url,
        "api_key": normalized_key,
        "endpoint_overrides": normalized_overrides,
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


def normalize_upstream_protocol(protocol: str) -> str:
    normalized = canonical_upstream_protocol(protocol)
    if normalized not in SUPPORTED_UPSTREAM_PROTOCOLS:
        raise LauncherConfigError(
            "The upstream protocol must be 'openai_chat_completions', 'openai_responses', "
            "or 'anthropic_messages'."
        )
    return normalized


def normalize_upstream_protocols(protocols: Sequence[str]) -> list[str]:
    normalized: list[str] = []
    for protocol in protocols:
        value = normalize_upstream_protocol(str(protocol))
        if value not in normalized:
            normalized.append(value)
    if not normalized:
        raise LauncherConfigError("Select at least one upstream API format.")
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
            protocols = list(DEFAULT_UPSTREAM_PROTOCOLS)
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
                "protocols": protocols,
                "base_url": str(raw.get("base_url", "")).rstrip("/"),
                "api_key": str(raw.get("api_key", "")).strip(),
                "endpoint_overrides": endpoint_overrides,
            }
            if profile != raw:
                changed = True
            profiles.append(profile)
    else:
        legacy_base_url = str(config.get("upstream_base_url", "")).rstrip("/")
        legacy_api_key = str(config.get("upstream_api_key", "")).strip()
        legacy_protocol = canonical_upstream_protocol(
            str(
                config.get("upstream_protocol")
                or (OPENAI_CHAT_COMPLETIONS if legacy_base_url or legacy_api_key else "")
            )
        )
        if legacy_base_url or legacy_api_key:
            profiles.append(
                {
                    "id": f"up_{secrets.token_urlsafe(12)}",
                    "name": DEFAULT_UPSTREAM_PROFILE_NAME,
                    "protocol": legacy_protocol,
                    "protocols": list(DEFAULT_UPSTREAM_PROTOCOLS),
                    "base_url": legacy_base_url,
                    "api_key": legacy_api_key,
                    "endpoint_overrides": {},
                }
            )
        changed = True
    active_id = str(config.get("active_upstream_profile_id", ""))
    if not any(profile["id"] == active_id for profile in profiles):
        active_id = str(profiles[0]["id"]) if profiles else ""
        changed = True
    for key in ("upstream_protocol", "upstream_base_url", "upstream_api_key"):
        if key in config:
            config.pop(key, None)
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
    return {key: value for key, value in config.items() if not key.startswith("_")}


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
