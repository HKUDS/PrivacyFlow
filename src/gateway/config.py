from __future__ import annotations

import os
import re
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from gateway.upstream_protocol import (
    OPENAI_CHAT_COMPLETIONS,
    SUPPORTED_UPSTREAM_PROTOCOLS,
    canonical_upstream_protocol,
)


@dataclass(frozen=True)
class UpstreamConfig:
    base_url: str = "https://api.openai.com"
    api_key: str = ""
    protocol: str = OPENAI_CHAT_COMPLETIONS
    timeout_seconds: float = 60.0
    strip_local_v1: bool = False
    endpoint_overrides: dict[str, str] = field(default_factory=dict)
    proxy: str | None = None


@dataclass(frozen=True)
class GatewayConfig:
    bind_host: str = "127.0.0.1"
    bind_port: int = 8765
    database_path: str = ".apg/state.sqlite3"
    audit_log_path: str = ".apg/audit.jsonl"
    signing_secret: str = "dev-only-change-me"
    local_api_keys: set[str] = field(default_factory=lambda: {"apg-local"})
    admin_api_keys: set[str] = field(default_factory=set)
    admin_enabled: bool = True
    workspace_id: str = "default"
    strict_mode: bool = True
    pii_mode: str = "pseudonymize"
    gc_interval_seconds: float = 60.0
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
    strict_mode = _env_bool("APG_STRICT", raw.get("strict_mode", True))
    raw = _expand_env_refs(raw, strict_mode)
    upstream_raw = raw.get("upstream", {})
    detectors_raw = dict(raw.get("detectors", {}))
    upstream_protocol = canonical_upstream_protocol(
        os.getenv("APG_UPSTREAM_PROTOCOL", upstream_raw.get("protocol", OPENAI_CHAT_COMPLETIONS))
    )
    upstream = UpstreamConfig(
        base_url=os.getenv("APG_UPSTREAM_BASE_URL", upstream_raw.get("base_url", "https://api.openai.com")).rstrip("/"),
        api_key=os.getenv("APG_UPSTREAM_API_KEY", upstream_raw.get("api_key", "")),
        protocol=upstream_protocol,
        timeout_seconds=float(os.getenv("APG_UPSTREAM_TIMEOUT", upstream_raw.get("timeout_seconds", 60.0))),
        strip_local_v1=_env_bool("APG_UPSTREAM_STRIP_LOCAL_V1", upstream_raw.get("strip_local_v1", False)),
        endpoint_overrides={
            canonical_upstream_protocol(str(key)): str(value).strip().rstrip("/")
            for key, value in dict(upstream_raw.get("endpoint_overrides", {})).items()
            if canonical_upstream_protocol(str(key)) in SUPPORTED_UPSTREAM_PROTOCOLS and str(value).strip()
        }
        if isinstance(upstream_raw.get("endpoint_overrides", {}), dict)
        else {},
        proxy=str(os.getenv("APG_UPSTREAM_PROXY") or upstream_raw.get("proxy") or "").strip() or None,
    )
    if upstream.protocol not in {"", *SUPPORTED_UPSTREAM_PROTOCOLS}:
        raise RuntimeError(
            "upstream.protocol must be 'openai_chat_completions', 'openai_responses', "
            "or 'anthropic_messages'. (APG_UPSTREAM_PROTOCOL_INVALID)"
        )
    keys = os.getenv("APG_LOCAL_API_KEYS")
    local_api_keys = set(keys.split(",")) if keys else set(raw.get("local_api_keys", ["apg-local"]))
    admin_keys = os.getenv("APG_ADMIN_API_KEYS")
    admin_api_keys = set(admin_keys.split(",")) if admin_keys else set(raw.get("admin_api_keys", []))
    signing_secret = os.getenv("APG_SIGNING_SECRET", raw.get("signing_secret", "dev-only-change-me"))

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
    if strict_mode and pii_mode == "allow":
        raise RuntimeError("pii_mode=allow is not permitted under strict_mode=True. (APG_STRICT_PII_ALLOW)")
    return GatewayConfig(
        bind_host=os.getenv("APG_HOST", raw.get("bind_host", "127.0.0.1")),
        bind_port=int(os.getenv("APG_PORT", raw.get("bind_port", 8765))),
        database_path=os.getenv("APG_DATABASE_PATH", raw.get("database_path", ".apg/state.sqlite3")),
        audit_log_path=os.getenv("APG_AUDIT_LOG_PATH", raw.get("audit_log_path", ".apg/audit.jsonl")),
        signing_secret=signing_secret,
        local_api_keys=local_api_keys,
        admin_api_keys=admin_api_keys,
        admin_enabled=_env_bool("APG_ADMIN_ENABLED", raw.get("admin_enabled", True)),
        workspace_id=os.getenv("APG_WORKSPACE_ID", raw.get("workspace_id", "default")),
        strict_mode=strict_mode,
        pii_mode=pii_mode,
        gc_interval_seconds=float(os.getenv("APG_GC_INTERVAL_SECONDS", raw.get("gc_interval_seconds", 60.0))),
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


_ENV_REF_RE = re.compile(r"^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$")


def _expand_env_refs(value: Any, strict: bool) -> Any:
    if isinstance(value, dict):
        return {key: _expand_env_refs(item, strict) for key, item in value.items()}
    if isinstance(value, list):
        return [_expand_env_refs(item, strict) for item in value]
    if not isinstance(value, str):
        return value
    match = _ENV_REF_RE.fullmatch(value)
    if match is None:
        return value
    name = match.group(1)
    resolved = os.getenv(name)
    if resolved is not None:
        return resolved
    _warn_or_raise(strict, f"Configuration references unset environment variable {name}.", "APG_CONFIG_ENV_UNRESOLVED")
    return ""
