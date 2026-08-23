from __future__ import annotations

import os
import re
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from gateway.compat import get_env, legacy_code
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
    provider_type: str = "custom"
    models_url: str = ""
    user_agent: str = ""
    timeout_seconds: float = 60.0
    strip_local_v1: bool = False
    endpoint_overrides: dict[str, str] = field(default_factory=dict)
    proxy: str | None = None


@dataclass(frozen=True)
class GatewayConfig:
    bind_host: str = "127.0.0.1"
    bind_port: int = 8765
    database_path: str = ".privacyflow/state.sqlite3"
    audit_log_path: str = ".privacyflow/audit.jsonl"
    audit_log_max_bytes: int = 16 * 1024 * 1024
    audit_log_backups: int = 5
    history_retention_seconds: int = 30 * 86_400
    signing_secret: str = "dev-only-change-me"
    local_api_keys: set[str] = field(default_factory=lambda: {"pf-local"})
    primary_local_api_key: str = ""
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
        value = yaml.safe_load(f) or {}
    if not isinstance(value, dict):
        raise RuntimeError(
            "PrivacyFlow configuration root must be a YAML object. "
            "(PF_CONFIG_ROOT_INVALID; legacy APG_CONFIG_ROOT_INVALID)"
        )
    return value


def _safe_optional_upstream_url(value: Any) -> str:
    normalized = str(value or "").strip().rstrip("/")
    if not normalized or len(normalized) > 2048 or any(ord(char) < 32 or ord(char) == 127 for char in normalized):
        return ""
    try:
        parsed = urlparse(normalized)
        _ = parsed.port
    except ValueError:
        return ""
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        return ""
    return normalized


def _safe_optional_user_agent(value: Any) -> str:
    normalized = str(value or "").strip()
    if len(normalized) > 256 or any(ord(char) < 32 or ord(char) > 126 for char in normalized):
        return ""
    return normalized


def _safe_provider_type(value: Any) -> str:
    normalized = str(value or "").strip() or "custom"
    if len(normalized) > 64 or any(ord(char) < 32 or ord(char) == 127 for char in normalized):
        return "custom"
    return normalized


def load_config(path: str | None = None) -> GatewayConfig:
    configured_path = path or get_env("CONFIG_PATH", default="")
    config_path = Path(configured_path) if configured_path else None
    raw = _load_yaml(config_path) if config_path else {}
    strict_mode = _env_bool("STRICT", raw.get("strict_mode", True))
    raw = _expand_env_refs(raw, strict_mode)
    upstream_raw = raw.get("upstream", {})
    detectors_raw = dict(raw.get("detectors", {}))
    upstream_protocol = canonical_upstream_protocol(
        get_env("UPSTREAM_PROTOCOL", default=upstream_raw.get("protocol", OPENAI_CHAT_COMPLETIONS))
    )
    upstream = UpstreamConfig(
        base_url=str(get_env("UPSTREAM_BASE_URL", default=upstream_raw.get("base_url", "https://api.openai.com"))).rstrip("/"),
        api_key=str(get_env("UPSTREAM_API_KEY", default=upstream_raw.get("api_key", ""))),
        protocol=upstream_protocol,
        provider_type=_safe_provider_type(get_env("UPSTREAM_PROVIDER_TYPE", default=upstream_raw.get("provider_type", "custom"))),
        models_url=_safe_optional_upstream_url(get_env("UPSTREAM_MODELS_URL", default=upstream_raw.get("models_url", ""))),
        user_agent=_safe_optional_user_agent(get_env("UPSTREAM_USER_AGENT", default=upstream_raw.get("user_agent", ""))),
        timeout_seconds=float(get_env("UPSTREAM_TIMEOUT", default=upstream_raw.get("timeout_seconds", 60.0))),
        strip_local_v1=_env_bool("UPSTREAM_STRIP_LOCAL_V1", upstream_raw.get("strip_local_v1", False)),
        endpoint_overrides={
            canonical_upstream_protocol(str(key)): str(value).strip().rstrip("/")
            for key, value in dict(upstream_raw.get("endpoint_overrides", {})).items()
            if canonical_upstream_protocol(str(key)) in SUPPORTED_UPSTREAM_PROTOCOLS and str(value).strip()
        }
        if isinstance(upstream_raw.get("endpoint_overrides", {}), dict)
        else {},
        proxy=str(get_env("UPSTREAM_PROXY", default=upstream_raw.get("proxy") or "") or "").strip() or None,
    )
    if upstream.protocol not in {"", *SUPPORTED_UPSTREAM_PROTOCOLS}:
        raise RuntimeError(
            "upstream.protocol must be 'openai_chat_completions', 'openai_responses', "
            "or 'anthropic_messages'. (PF_UPSTREAM_PROTOCOL_INVALID)"
        )
    keys = get_env("LOCAL_API_KEYS")
    raw_keys = keys.split(",") if keys is not None else raw.get("local_api_keys", ["pf-local"])
    if not isinstance(raw_keys, (list, tuple, set)):
        raw_keys = [raw_keys]
    local_api_keys = {str(key).strip() for key in raw_keys if str(key).strip()}
    primary_local_api_key = str(get_env("PRIMARY_LOCAL_API_KEY", default=raw.get("primary_local_api_key", ""))).strip()
    signing_secret = str(get_env("SIGNING_SECRET", default=raw.get("signing_secret", "dev-only-change-me")))

    if not local_api_keys:
        _warn_or_raise(
            strict_mode,
            "No local Agent API key is configured. Set PF_LOCAL_API_KEYS to at least one non-empty key.",
            "PF_STRICT_LOCAL_KEY_EMPTY",
        )
    elif "pf-local" in local_api_keys and keys is None:
        _warn_or_raise(
            strict_mode,
            "Using default API key 'pf-local' under strict_mode=True. "
            "Set PF_LOCAL_API_KEYS (comma-separated) or pass strict_mode: false.",
            "PF_STRICT_LOCAL_KEY",
        )
    if signing_secret == "dev-only-change-me":
        _warn_or_raise(
            strict_mode,
            "Using default signing secret under strict_mode=True. "
            "Set PF_SIGNING_SECRET to a random value, or pass strict_mode: false for dev.",
            "PF_STRICT_SIGNING_SECRET",
        )
    pii_mode = get_env("PII_MODE", default=raw.get("pii_mode", "pseudonymize"))
    if strict_mode and pii_mode == "allow":
        raise RuntimeError(
            "pii_mode=allow is not permitted under strict_mode=True. "
            "(PF_STRICT_PII_ALLOW; legacy APG_STRICT_PII_ALLOW)"
        )
    return GatewayConfig(
        bind_host=str(get_env("HOST", default=raw.get("bind_host", "127.0.0.1"))),
        bind_port=int(get_env("PORT", default=raw.get("bind_port", 8765))),
        database_path=str(get_env("DATABASE_PATH", default=raw.get("database_path", ".privacyflow/state.sqlite3"))),
        audit_log_path=str(get_env("AUDIT_LOG_PATH", default=raw.get("audit_log_path", ".privacyflow/audit.jsonl"))),
        audit_log_max_bytes=_bounded_int(
            get_env("AUDIT_LOG_MAX_BYTES", default=raw.get("audit_log_max_bytes", 16 * 1024 * 1024)),
            name="audit_log_max_bytes",
            minimum=64 * 1024,
            maximum=1024 * 1024 * 1024,
        ),
        audit_log_backups=_bounded_int(
            get_env("AUDIT_LOG_BACKUPS", default=raw.get("audit_log_backups", 5)),
            name="audit_log_backups",
            minimum=1,
            maximum=20,
        ),
        history_retention_seconds=_bounded_int(
            get_env("HISTORY_RETENTION_SECONDS", default=raw.get("history_retention_seconds", 30 * 86_400)),
            name="history_retention_seconds",
            minimum=3600,
            maximum=365 * 86_400,
        ),
        signing_secret=signing_secret,
        local_api_keys=local_api_keys,
        primary_local_api_key=primary_local_api_key,
        admin_enabled=_env_bool("ADMIN_ENABLED", raw.get("admin_enabled", True)),
        workspace_id=str(get_env("WORKSPACE_ID", default=raw.get("workspace_id", "default"))),
        strict_mode=strict_mode,
        pii_mode=pii_mode,
        gc_interval_seconds=float(get_env("GC_INTERVAL_SECONDS", default=raw.get("gc_interval_seconds", 60.0))),
        detectors_config=detectors_raw,
        upstream=upstream,
    )


def _warn_or_raise(strict: bool, msg: str, reason_code: str) -> None:
    """In ``strict_mode`` we fail-closed startup; otherwise issue a warning."""
    if strict:
        raise RuntimeError(f"{msg} ({reason_code}; legacy {legacy_code(reason_code)})")
    warnings.warn(msg, RuntimeWarning, stacklevel=2)


def _bounded_int(value: Any, *, name: str, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise RuntimeError(f"{name} must be an integer. (PF_CONFIG_VALUE_INVALID)") from exc
    if parsed < minimum or parsed > maximum:
        raise RuntimeError(
            f"{name} must be between {minimum} and {maximum}. (PF_CONFIG_VALUE_INVALID)"
        )
    return parsed


def _env_bool(name: str, default: bool) -> bool:
    value = get_env(name)
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
    if name.startswith(("PF_", "APG_")):
        resolved = get_env(name)
    else:
        resolved = os.getenv(name)
    if resolved is not None:
        return resolved
    _warn_or_raise(strict, f"Configuration references unset environment variable {name}.", "PF_CONFIG_ENV_UNRESOLVED")
    return ""
