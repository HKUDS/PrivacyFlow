from __future__ import annotations

import argparse
import json
import os
import secrets
import tempfile
from collections.abc import Mapping, MutableMapping, Sequence
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


DEFAULT_LAUNCHER_PATH = Path(".apg/launcher.json")


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
    admin_key = os.environ["APG_ADMIN_API_KEYS"].split(",", 1)[0]
    print("Agent Privacy Gateway")
    print(f"WebUI: http://{host}:{port}/ui/")
    print(f"Admin key: {admin_key}")
    if not config["_resolved_upstream_base_url"] or not config["_resolved_upstream_api_key"]:
        print("Upstream connection: not configured (finish setup in the WebUI).")
    print("Press Ctrl+C to stop.")

    from gateway.server import main as server_main

    server_main()


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
        config["local_api_key"] = "apg-local"
        changed = True
    if not config.get("admin_api_key"):
        config["admin_api_key"] = config["local_api_key"]
        changed = True
    if "upstream_base_url" not in config:
        config["upstream_base_url"] = ""
        changed = True
    if "strip_local_v1" not in config:
        config["strip_local_v1"] = True
        changed = True

    provider_key = environment.get("APG_UPSTREAM_API_KEY", "").strip() or str(config.get("upstream_api_key", "")).strip()
    provider_base_url = environment.get("APG_UPSTREAM_BASE_URL", "").strip() or str(config.get("upstream_base_url", "")).strip()

    config["_resolved_upstream_api_key"] = provider_key
    config["_resolved_upstream_base_url"] = provider_base_url.rstrip("/")
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
        "APG_UPSTREAM_STRIP_LOCAL_V1": "true" if config.get("strip_local_v1", True) else "false",
        "APG_LOCAL_API_KEYS": str(config["local_api_key"]),
        "APG_ADMIN_API_KEYS": str(config["admin_api_key"]),
        "APG_SIGNING_SECRET": str(config["signing_secret"]),
        "APG_LAUNCHER_CONFIG_PATH": str(config["_launcher_config_path"]),
    }
    for key, value in defaults.items():
        environment.setdefault(key, value)


def save_launcher_upstream_api_key(path: Path, api_key: str) -> None:
    config = _read_launcher_config(path)
    save_launcher_upstream_configuration(path, str(config.get("upstream_base_url", "")), api_key)


def save_launcher_upstream_configuration(path: Path, base_url: str, api_key: str) -> tuple[str, str]:
    normalized_base_url = normalize_upstream_base_url(base_url)
    normalized = api_key.strip()
    if not normalized or len(normalized) > 4096:
        raise LauncherConfigError("The upstream API key must contain between 1 and 4096 characters.")
    if any(ord(char) < 32 or ord(char) == 127 for char in normalized):
        raise LauncherConfigError("The upstream API key contains unsupported control characters.")
    config = _read_launcher_config(path)
    config["upstream_base_url"] = normalized_base_url
    config["upstream_api_key"] = normalized
    _write_launcher_config(path, config)
    return normalized_base_url, normalized


def normalize_upstream_base_url(base_url: str) -> str:
    normalized = base_url.strip().rstrip("/")
    if not normalized or len(normalized) > 2048:
        raise LauncherConfigError("The upstream Base URL must contain between 1 and 2048 characters.")
    if any(ord(char) < 32 or ord(char) == 127 for char in normalized):
        raise LauncherConfigError("The upstream Base URL contains unsupported control characters.")
    try:
        parsed = urlparse(normalized)
        hostname = parsed.hostname
        parsed.port
    except ValueError as exc:
        raise LauncherConfigError("The upstream Base URL is malformed.") from exc
    if parsed.scheme not in {"http", "https"} or not hostname or any(char.isspace() for char in hostname):
        raise LauncherConfigError("The upstream Base URL must be an absolute HTTP or HTTPS URL.")
    if parsed.username is not None or parsed.password is not None:
        raise LauncherConfigError("The upstream Base URL must not contain embedded credentials.")
    if parsed.query or parsed.fragment:
        raise LauncherConfigError("The upstream Base URL must not contain a query string or fragment.")
    return normalized


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
