from __future__ import annotations

import os
import secrets
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class UpstreamConfig:
    base_url: str = "https://api.openai.com"
    api_key: str = ""
    timeout_seconds: float = 60.0
    strip_local_v1: bool = False


@dataclass(frozen=True)
class GatewayConfig:
    bind_host: str = "127.0.0.1"
    bind_port: int = 8765
    database_path: str = ".apg/state.sqlite3"
    audit_log_path: str = ".apg/audit.jsonl"
    signing_secret: str = "dev-only-change-me"
    local_api_keys: set[str] = field(default_factory=lambda: {"apg-local"})
    workspace_id: str = "default"
    strict_mode: bool = True
    pii_mode: str = "pseudonymize"
    detectors_config: dict[str, Any] = field(default_factory=dict)
    upstream: UpstreamConfig = field(default_factory=UpstreamConfig)


def _load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        import yaml
    except ModuleNotFoundError as exc:  # pragma: no cover - install-time guard
        raise RuntimeError("PyYAML is required to load YAML config files") from exc
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def load_config(path: str | None = None) -> GatewayConfig:
    config_path = Path(path or os.getenv("APG_CONFIG_PATH", "")) if path or os.getenv("APG_CONFIG_PATH") else None
    raw = _load_yaml(config_path) if config_path else {}
    base_dir = config_path.parent if config_path else Path.cwd()
    upstream_raw = raw.get("upstream", {})
    detectors_raw = dict(raw.get("detectors", {}))
    upstream = UpstreamConfig(
        base_url=os.getenv("APG_UPSTREAM_BASE_URL", upstream_raw.get("base_url", "https://api.openai.com")).rstrip("/"),
        api_key=os.getenv("APG_UPSTREAM_API_KEY", upstream_raw.get("api_key", "")),
        timeout_seconds=float(os.getenv("APG_UPSTREAM_TIMEOUT", upstream_raw.get("timeout_seconds", 60.0))),
        strip_local_v1=_env_bool("APG_UPSTREAM_STRIP_LOCAL_V1", upstream_raw.get("strip_local_v1", False)),
    )
    keys = os.getenv("APG_LOCAL_API_KEYS")
    local_api_keys = set(keys.split(",")) if keys else set(raw.get("local_api_keys", ["apg-local"]))
    signing_secret = os.getenv("APG_SIGNING_SECRET", raw.get("signing_secret", "dev-only-change-me"))
    strict_mode = _env_bool("APG_STRICT", raw.get("strict_mode", True))

    if "apg-local" in local_api_keys and not os.getenv("APG_LOCAL_API_KEYS"):
        _warn_or_raise(
            strict_mode,
            "Using default API key 'apg-local' under strict_mode=True. "
            "Set APG_LOCAL_API_KEYS (comma-separated) or pass strict_mode: false.",
            "APG_STRICT_LOCAL_KEY",
        )
    if signing_secret == "dev-only-change-me":
        _warn_or_raise(
            strict_mode,
            "Using default signing secret under strict_mode=True. "
            "Set APG_SIGNING_SECRET to a random value, or pass strict_mode: false for dev.",
            "APG_STRICT_SIGNING_SECRET",
        )
    pii_mode = os.getenv("APG_PII_MODE", raw.get("pii_mode", "pseudonymize"))
    return GatewayConfig(
        bind_host=os.getenv("APG_HOST", raw.get("bind_host", "127.0.0.1")),
        bind_port=int(os.getenv("APG_PORT", raw.get("bind_port", 8765))),
        database_path=os.getenv("APG_DATABASE_PATH", raw.get("database_path", ".apg/state.sqlite3")),
        audit_log_path=os.getenv("APG_AUDIT_LOG_PATH", raw.get("audit_log_path", ".apg/audit.jsonl")),
        signing_secret=signing_secret,
        local_api_keys=local_api_keys,
        workspace_id=os.getenv("APG_WORKSPACE_ID", raw.get("workspace_id", "default")),
        strict_mode=strict_mode,
        pii_mode=pii_mode,
        detectors_config=detectors_raw,
        upstream=upstream,
    )


def _warn_or_raise(strict: bool, msg: str, reason_code: str) -> None:
    """In ``strict_mode`` we fail-closed startup; otherwise issue a warning."""
    if strict:
        raise RuntimeError(f"{msg} ({reason_code})")
    warnings.warn(msg, RuntimeWarning, stacklevel=2)


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return bool(default)
    return value.strip().lower() in {"1", "true", "yes", "on"}

