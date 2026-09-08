"""PrivacyFlow namespace helpers used during the APG migration release.

The public name is PrivacyFlow, but a migration release must be able to read
installations that still use the old APG namespace.  Keeping this logic in one
small module prevents every configuration reader from implementing subtly
different precedence or warning behaviour.
"""

from __future__ import annotations

import os
import re
import sys
import warnings
from collections.abc import Mapping
from pathlib import Path
from typing import Any


LEGACY_COMPATIBILITY = True
CANONICAL_STATE_DIR = ".privacyflow"
LEGACY_STATE_DIR = ".apg"
CANONICAL_NAMESPACE = "PF"
LEGACY_NAMESPACE = "APG"
SUPPORTED_NAMESPACES = {CANONICAL_NAMESPACE, LEGACY_NAMESPACE}


def normalize_namespace(namespace: str | None) -> str:
    """Return PF unless the caller explicitly requested the APG migration namespace."""

    return namespace if namespace in SUPPORTED_NAMESPACES else CANONICAL_NAMESPACE


_warned_legacy_names: set[str] = set()


class NamespaceConflictError(RuntimeError):
    """Raised when canonical and legacy values are both set differently."""

    code = "PF_CONFIG_CONFLICT"


class LegacyNamespaceWarning(FutureWarning):
    """Visible one-release warning for APG-only configuration."""


def ensure_private_state_directory(path: Path, *, always_owned: bool = False) -> None:
    """Create a private state directory without chmod-ing arbitrary parents."""

    if path.is_symlink():
        raise OSError(f"Refusing symbolic-link state directory: {path}")
    existed = path.exists()
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not existed or always_owned or path.name in {CANONICAL_STATE_DIR, LEGACY_STATE_DIR}:
        os.chmod(path, 0o700)


def pf_env(suffix: str) -> tuple[str, str]:
    """Return the canonical and legacy environment variable names."""

    normalized = suffix.removeprefix("PF_").removeprefix("APG_")
    return f"PF_{normalized}", f"APG_{normalized}"


def get_env(
    suffix: str,
    *,
    default: Any = None,
    environ: Mapping[str, str] | None = None,
    warn_legacy: bool = True,
) -> Any:
    """Read a PF environment variable with one-release APG fallback.

    PF wins when only one namespace is present.  If both are present, equal
    values are accepted; differing values fail closed so a deployment cannot
    silently use the wrong credential or endpoint.
    """

    environment = os.environ if environ is None else environ
    canonical, legacy = pf_env(suffix)
    has_canonical = canonical in environment
    has_legacy = legacy in environment
    canonical_value = environment.get(canonical)
    legacy_value = environment.get(legacy)
    if has_canonical and has_legacy and canonical_value != legacy_value:
        raise NamespaceConflictError(
            f"Both {canonical} and {legacy} are set with different values. "
            f"Remove the legacy variable or make the values identical. ({NamespaceConflictError.code})"
        )
    if has_canonical:
        return canonical_value
    if has_legacy:
        if warn_legacy and legacy not in _warned_legacy_names:
            warnings.warn(
                f"{legacy} is deprecated; use {canonical} instead.",
                LegacyNamespaceWarning,
                stacklevel=2,
            )
            _warned_legacy_names.add(legacy)
        return legacy_value
    return default


def set_pf_env(environ: dict[str, str], suffix: str, value: str, *, mirror_legacy: bool = False) -> None:
    """Set a canonical PF variable, optionally mirroring the legacy name."""

    canonical, legacy = pf_env(suffix)
    environ[canonical] = value
    if mirror_legacy:
        environ[legacy] = value


def legacy_cli_warning() -> None:
    """Emit the CLI deprecation warning once per process."""

    if "__cli__" in _warned_legacy_names:
        return
    print(
        "Warning: the 'apg' command is deprecated during the PrivacyFlow migration; use 'privacyflow'.",
        file=sys.stderr,
    )
    _warned_legacy_names.add("__cli__")


def legacy_code(code: str) -> str:
    """Return the APG spelling of a PF error code for migration diagnostics."""

    return code.replace("PF_", "APG_", 1) if code.startswith("PF_") else code


_NAMESPACE_VALUE_KEYS = {
    "code",
    "error_code",
    "result_code",
    "reason_code",
    "status_code",
    "unavailable_reason",
    "detector",
    "detector_id",
    "rule_id",
    "provider",
    "provider_id",
    "modelPreset",
    "apiKeyEnv",
    "type",
    "id",
    "detail",
}
_PF_ERROR_RE = re.compile(r"(?<![A-Za-z0-9_])PF_[A-Z0-9_]+")
_APG_ERROR_RE = re.compile(r"(?<![A-Za-z0-9_])APG_[A-Z0-9_]+")


def translate_value(value: Any, *, legacy: bool, _key: str | None = None) -> Any:
    """Translate protocol identifiers without rewriting arbitrary user text.

    Response bodies also contain model-generated prose and tool arguments. A
    blanket ``str.replace("APG_", "PF_")`` would silently corrupt that data.
    Namespace conversion is therefore limited to known protocol fields and
    exact persisted identifiers; signed placeholder delimiters are converted
    only for legacy responses, where the old client expects the APG spelling.
    """

    if isinstance(value, dict):
        translated: dict[Any, Any] = {}
        for raw_key, raw_value in value.items():
            key = str(raw_key)
            if legacy:
                key = {"pf_enabled": "apg_enabled"}.get(key, key)
            else:
                key = {"apg_enabled": "pf_enabled"}.get(key, key)
            translated[key] = translate_value(raw_value, legacy=legacy, _key=key)
        return translated
    if isinstance(value, list):
        return [translate_value(item, legacy=legacy, _key=_key) for item in value]
    if not isinstance(value, str):
        return value
    if legacy:
        converted = value.replace("<PF:v1:", "<APG:v1:").replace("<PF_DETECTED:", "<APG_DETECTED:")
        if _key in _NAMESPACE_VALUE_KEYS:
            converted = _PF_ERROR_RE.sub(lambda match: "APG_" + match.group(0)[3:], converted)
            converted = converted.replace("rules.pf_markers", "rules.apg_markers").replace("pf_core", "apg_core")
            if _key in {"rule_id", "id", "detector", "detector_id"}:
                converted = converted.replace("pf.", "apg.")
            if _key == "type":
                converted = converted.replace("PF_MARKER", "APG_MARKER")
        return converted
    if _key not in _NAMESPACE_VALUE_KEYS:
        return value
    converted = _APG_ERROR_RE.sub(lambda match: "PF_" + match.group(0)[4:], value)
    converted = converted.replace("rules.apg_markers", "rules.pf_markers").replace("apg_core", "pf_core")
    if _key in {"rule_id", "id", "detector", "detector_id"}:
        converted = converted.replace("apg.", "pf.")
    if _key == "type":
        converted = converted.replace("APG_MARKER", "PF_MARKER")
    return converted


def rewrite_legacy_text(value: str) -> str:
    """Rewrite identifiers that are safe to migrate in state JSON text."""

    return (
        value.replace("rules.apg_markers", "rules.pf_markers")
        .replace("APG_DSH_API_KEY", "PF_DSH_API_KEY")
        .replace("apg-runtime.json", "pf-runtime.json")
    )


def map_state_value(value: Any, *, key: str | None = None) -> Any:
    """Map persisted APG state keys without rewriting arbitrary user text."""

    if isinstance(value, dict):
        mapped: dict[Any, Any] = {}
        for raw_key, raw_value in value.items():
            child_key = str(raw_key)
            next_key = {
                "apg_enabled": "pf_enabled",
                "apg_core": "pf_core",
            }.get(child_key, child_key)
            if key in {"model_providers", "providers"} and child_key == "apg":
                next_key = "pf"
            elif key == "modelPresets" and child_key == "APG":
                next_key = "PF"
            elif key in {"env", "credentials", "environment"} and child_key.startswith("APG_"):
                next_key = "PF_" + child_key[4:]
            mapped_value = map_state_value(raw_value, key=next_key)
            if next_key in mapped:
                if mapped[next_key] != mapped_value:
                    raise NamespaceConflictError(
                        f"Canonical and legacy values conflict for '{next_key}'. "
                        f"({NamespaceConflictError.code})"
                    )
                continue
            mapped[next_key] = mapped_value
        return mapped
    if isinstance(value, list):
        return [map_state_value(item, key=key) for item in value]
    if isinstance(value, str):
        if key in {"provider", "provider_id"} and value == "apg":
            return "pf"
        if key == "modelPreset" and value == "APG":
            return "PF"
        if key == "type" and value == "APG_MARKER":
            return "PF_MARKER"
        if key in {"id", "rule_id", "detector", "detector_id"} and value.startswith("apg."):
            return value.replace("apg.", "pf.", 1)
        if value in {"apg_core", "rules.apg_markers", "APG_DSH_API_KEY"}:
            return rewrite_legacy_text(value)
    return value
