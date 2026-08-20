from __future__ import annotations

import copy
import json
import os
import threading
from pathlib import Path
from typing import Any, Callable

from gateway.detector_manager import DetectorManager
from gateway.detectors.rules import builtin_rules


BUILTIN_RULESET_REVISION = 4
FIXED_CONFIGURATION_ID = "builtin.comprehensive"


class DetectorControlError(ValueError):
    pass


def _rule_dict(rule: Any) -> dict[str, Any]:
    value = copy.deepcopy(rule.__dict__)
    value["flags"] = list(value.get("flags", ()))
    value["validators"] = list(value.get("validators", ()))
    value["require_validators"] = list(value.get("require_validators", ()))
    value["reject_validators"] = list(value.get("reject_validators", ()))
    value["metadata"] = dict(value.get("metadata", {}))
    return value


BUILTIN_RULE_VALUES = tuple(_rule_dict(rule) for rule in builtin_rules())
CORE_RULES = tuple(
    copy.deepcopy(rule)
    for rule in BUILTIN_RULE_VALUES
    if str(rule["id"]).startswith(("pf.", "apg."))
)
CREDENTIAL_RULES = tuple(
    copy.deepcopy(rule)
    for rule in BUILTIN_RULE_VALUES
    if str(rule["id"]).startswith("secret.")
)
PII_RULES = tuple(
    copy.deepcopy(rule)
    for rule in BUILTIN_RULE_VALUES
    if str(rule["id"]).startswith("pii.")
)


def _fixed_modules() -> list[dict[str, Any]]:
    return [
        {
            "id": "credentials",
            "name": "凭据与密钥规则",
            "type": "regex",
            "enabled": True,
            "failure_mode": "closed",
            "config": {"rules": copy.deepcopy(CREDENTIAL_RULES)},
        },
        {
            "id": "personal_data",
            "name": "个人信息规则",
            "type": "regex",
            "enabled": True,
            "failure_mode": "open",
            "config": {"rules": copy.deepcopy(PII_RULES)},
        },
        {
            "id": "local_paths",
            "name": "本地路径",
            "type": "path",
            "enabled": True,
            "failure_mode": "closed",
            "config": {
                "detect_unix_home": True,
                "detect_macos_private": True,
                "detect_shell_config": True,
                "detect_windows_user": True,
                "exclude_patterns": [],
                "path_risk": "medium",
            },
        },
    ]


def _fixed_configuration() -> dict[str, Any]:
    return {
        "id": FIXED_CONFIGURATION_ID,
        "name": "全面保护",
        "description": "凭据、个人信息与本地开发环境",
        "revision": BUILTIN_RULESET_REVISION,
        "source_template_id": None,
        "core_guard_enabled": True,
        "flow_timeout_ms": 1500,
        "modules": _fixed_modules(),
        "content_tags": ["credentials", "pii", "paths"],
        "readonly": True,
        "template": True,
        "is_active": True,
    }


def _fixed_runtime_config(namespace: str) -> dict[str, Any]:
    modules = [
        {
            "id": f"{namespace.lower()}_core",
            "type": "regex_rules",
            "rules": copy.deepcopy(CORE_RULES),
            "enabled": True,
            "fail_open": False,
            "stream_safe": True,
        },
        {
            "id": "credentials",
            "type": "regex_rules",
            "rules": copy.deepcopy(CREDENTIAL_RULES),
            "enabled": True,
            "fail_open": False,
            "stream_safe": True,
        },
        {
            "id": "personal_data",
            "type": "regex_rules",
            "rules": copy.deepcopy(PII_RULES),
            "enabled": True,
            "fail_open": True,
            "stream_safe": True,
        },
        {
            "id": "local_paths",
            "type": "path_detector",
            "enabled": True,
            "fail_open": False,
            "stream_safe": True,
            "detect_unix_home": True,
            "detect_macos_private": True,
            "detect_shell_config": True,
            "detect_windows_user": True,
            "exclude_patterns": [],
            "path_risk": "medium",
        },
    ]
    return {
        "core_guard_enabled": True,
        "flow": {
            "id": FIXED_CONFIGURATION_ID,
            "flow_timeout_ms": 1500,
            "modules": modules,
        },
    }


class DetectorControlPlane:
    """Own the fixed built-in protection pipeline and its master switch."""

    def __init__(
        self,
        state_path: str,
        apply_manager: Callable[[DetectorManager], None],
        namespace: str = "PF",
    ) -> None:
        self.state_path = Path(state_path)
        self.namespace = namespace if namespace in {"PF", "APG"} else "PF"
        self._lock = threading.RLock()
        self._enabled = self._load_enabled()
        self._manager = DetectorManager(detectors_config=_fixed_runtime_config(self.namespace))
        apply_manager(self._manager)

    def catalog(self) -> dict[str, Any]:
        """Return a read-only summary for internal compatibility."""

        with self._lock:
            configuration = self.active_configuration()
            return {
                "active_configuration_id": FIXED_CONFIGURATION_ID,
                "pf_enabled": self._enabled,
                "configuration_available": True,
                "templates": [],
                "configurations": [configuration],
                "module_types": [],
            }

    def active_configuration(self) -> dict[str, Any]:
        return _fixed_configuration()

    def active_configuration_available(self) -> bool:
        return True

    def local_model_references(self) -> list[dict[str, Any]]:
        """Local models are managed artifacts, not part of the fixed pipeline."""

        return []

    def pf_enabled(self) -> bool:
        with self._lock:
            return self._enabled

    def set_pf_enabled(self, enabled: bool) -> bool:
        if not isinstance(enabled, bool):
            raise DetectorControlError("Expected boolean PrivacyFlow enabled state")
        with self._lock:
            self._persist_enabled(enabled)
            self._enabled = enabled
            return enabled

    def _load_enabled(self) -> bool:
        if not self.state_path.exists() or self.state_path.is_symlink():
            return True
        try:
            data = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return True
        if not isinstance(data, dict):
            return True
        enabled = data.get("pf_enabled", data.get("apg_enabled", True))
        return enabled if isinstance(enabled, bool) else True

    def _persist_enabled(self, enabled: bool) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": 3,
            "builtin_ruleset_revision": BUILTIN_RULESET_REVISION,
            "pf_enabled": enabled,
        }
        temp = self.state_path.with_suffix(self.state_path.suffix + ".tmp")
        temp.write_text(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
        os.chmod(temp, 0o600)
        temp.replace(self.state_path)
