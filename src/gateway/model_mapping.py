"""Explicit, UI-facing model-role mapping helpers.

cc-switch maps Claude roles (haiku/sonnet/opus/fable/subagent) to upstream
identifiers.  PrivacyFlow intentionally does not apply those mappings inside proxy
traffic: the selected *actual* identifier is written to an Agent configuration
and is sent unchanged.  These helpers only build/validate mapping data for a
future explicit mapping mode and for previews.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any


MODEL_ROLES = ("haiku", "sonnet", "opus", "fable", "subagent", "default")


def strip_large_context_suffix(model_id: str) -> str:
    """Return the request identifier represented by a ``[1M]`` display label."""
    value = str(model_id or "").strip()
    return value[:-4].rstrip() if value[-4:].lower() == "[1m]" else value


def normalize_model_mapping(mapping: Mapping[str, Any] | None) -> dict[str, str]:
    result: dict[str, str] = {}
    if not isinstance(mapping, Mapping):
        return result
    for role in MODEL_ROLES:
        value = mapping.get(role)
        if isinstance(value, str) and value.strip():
            result[role] = strip_large_context_suffix(value)
    return result


def infer_model_role(model_id: str) -> str:
    """Infer a display role from common Claude naming conventions."""
    value = str(model_id or "").lower()
    if "haiku" in value:
        return "haiku"
    if "sonnet" in value:
        return "sonnet"
    if "fable" in value:
        return "fable"
    if "opus" in value:
        return "opus"
    return "default"


def build_role_mapping(model_ids: Sequence[str], overrides: Mapping[str, Any] | None = None) -> dict[str, str]:
    """Build deterministic role defaults without changing any model ID."""
    normalized = [strip_large_context_suffix(item) for item in model_ids if str(item).strip()]
    mapping = normalize_model_mapping(overrides)
    for model_id in normalized:
        role = infer_model_role(model_id)
        mapping.setdefault(role, model_id)
    fallback = mapping.get("default") or (normalized[0] if normalized else "")
    if fallback:
        mapping.setdefault("default", fallback)
        mapping.setdefault("subagent", mapping.get("sonnet", fallback))
        mapping.setdefault("fable", mapping.get("opus", fallback))
    return {role: mapping[role] for role in MODEL_ROLES if mapping.get(role)}


def resolve_role_model(role: str, mapping: Mapping[str, Any] | None, fallback: str = "") -> str:
    """Resolve one role for a preview; no proxy-time rewrite is performed."""
    normalized = normalize_model_mapping(mapping)
    role = role if role in MODEL_ROLES else "default"
    return normalized.get(role) or normalized.get("default") or strip_large_context_suffix(fallback)
