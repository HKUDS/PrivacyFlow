from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import re
import shutil
import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable

from gateway.detector_manager import DetectorManager
from gateway.detectors.flow import compile_flow_config
from gateway.detectors.rules import VALIDATORS, builtin_rules
from gateway.local_models import local_model_id


MODULE_TYPE_LABELS = {
    "regex": "正则检测",
    "entropy": "熵值检测",
    "path": "路径检测",
    "local_model": "本地小模型",
}

LEGACY_PRESETS = {"fast", "default", "strict", "model_enhanced"}
RISK_LEVELS = {"low", "medium", "high", "critical"}
ACTIONS = {"warn", "redact", "block", "pseudonymize", "alias"}
FINDING_TYPES = {"MACHINE_SECRET", "PII", "LOCAL_CONTEXT", "CREDENTIAL_FILE", "APG_MARKER", "UNKNOWN_SECRET_CANDIDATE"}
FAILURE_MODES = {"open", "closed"}
REGEX_FLAGS = {"I", "IGNORECASE", "M", "MULTILINE", "S", "DOTALL"}

_CONFIG_ID_RE = re.compile(r"^(?:builtin|deployment)\.[a-z][a-z0-9_.-]{1,63}$|^dcfg_[a-f0-9]{12,32}$")
_MODULE_ID_RE = re.compile(r"^[a-z][a-z0-9_.-]{1,63}$|^mod_[a-f0-9]{8,32}$")
_RULE_ID_RE = re.compile(r"^[a-z][a-z0-9_.-]{1,95}$")
_SUBTYPE_RE = re.compile(r"^[a-z][a-z0-9_.-]{1,63}$")
_UNSAFE_GROUP_REPEAT_RE = re.compile(r"\([^)]*\)\s*(?:[+*]|\{)")
_UNSAFE_REGEX_FEATURE_RE = re.compile(r"\(\?(?:[=!<]|P=)|\\[1-9]|\.\*|\.\+")


class DetectorControlError(ValueError):
    pass


class DetectorConfigurationNotFound(DetectorControlError):
    pass


class DetectorConfigurationConflict(DetectorControlError):
    pass


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _rule_dict(rule: Any) -> dict[str, Any]:
    value = copy.deepcopy(rule.__dict__)
    value["flags"] = list(value.get("flags", ()))
    value["validators"] = list(value.get("validators", ()))
    value["require_validators"] = list(value.get("require_validators", ()))
    value["reject_validators"] = list(value.get("reject_validators", ()))
    value["metadata"] = dict(value.get("metadata", {}))
    return value


BUILTIN_RULE_VALUES = tuple(_rule_dict(rule) for rule in builtin_rules())
BUILTIN_RULESET_REVISION = 4
BUILTIN_RULESET_REVISION_2_ADDITIONS = {
    "secret.credential_pair_password",
    "secret.ip_access_url_token",
    "pii.phone_labeled",
}
BUILTIN_RULESET_REVISION_2_REMOVALS = {
    "secret.database_test_password",
    "secret.github_apg_test_token",
    "secret.jwt_prefix",
    "secret.openai_apg_test_key",
}
BUILTIN_RULESET_REVISION_3_SUBTYPES = {
    "secret.openai_api_key": ("openai_api_key", "api_key"),
    "secret.credential_pair_password": ("password", "credential_password"),
}
BUILTIN_RULESET_REVISION_4_ADDITIONS = {
    "secret.hex_dump_jwt_fragment",
}
_CURRENT_RULE_PATTERNS = {str(rule["id"]): str(rule["pattern"]) for rule in BUILTIN_RULE_VALUES}
_ENV_ASSIGNMENT_V1_PATTERN = (
    r"^\s*[A-Z0-9_]*(?:API_KEY|TOKEN|SECRET|PASSWORD|PASSWD|PASS|CREDENTIAL|PRIVATE_KEY|DATABASE_URL)"
    r"[A-Z0-9_]*\s*=\s*(?P<value>.+)$"
)
_ENV_ASSIGNMENT_V2_PATTERN = (
    r"(?<![A-Z0-9_])(?:export\s+)?[A-Z0-9_]*(?:API_KEY|TOKEN|SECRET|PASSWORD|PASSWD|PASS|CREDENTIAL|PRIVATE_KEY|DATABASE_URL)"
    r"[A-Z0-9_]*\s*=\s*(?P<value>[^\r\n]+)$"
)
_ENV_ASSIGNMENT_V3_PATTERN = (
    r"(?<![A-Z0-9_])(?:export[ \t]+)?[A-Z0-9_]*(?:API_KEY|TOKEN|SECRET|PASSWORD|PASSWD|PASS|CREDENTIAL|PRIVATE_KEY|DATABASE_URL)"
    r"[A-Z0-9_]*[ \t]*=[ \t]*(?P<value>\"(?:\\.|[^\"\\\r\n])*\"|'(?:\\.|[^'\\\r\n])*'|[^\s;]+)"
)
_ENV_ASSIGNMENT_V4_PATTERN = (
    r"(?<![A-Z0-9_])(?:export[ \t]+)?(?:[A-Z0-9]+_)*(?:API_KEY|APIKEY|TOKEN|SECRET|PASSWORD|PASSWD|PASS|CREDENTIAL|PRIVATE_KEY|DATABASE_URL)"
    r"(?:_[A-Z0-9]+)*[ \t]*=[ \t]*(?P<value>\"(?:\\.|[^\"\\\r\n])*\"|'(?:\\.|[^'\\\r\n])*'|[^\s;]+)"
)
_ENV_ASSIGNMENT_V5_PATTERN = (
    r"(?<![A-Z0-9_])(?:export[ \t]+)?(?P<name>[A-Z][A-Z0-9_]*)[ \t]*=[ \t]*"
    r"(?P<value>\"(?:\\.|[^\"\\\r\n])*\"|'(?:\\.|[^'\\\r\n])*'|[^\s;]+)"
)
_BEARER_TOKEN_V1_PATTERN = r"\bAuthorization\s*:\s*Bearer\s+[A-Za-z0-9._~+/=-]{16,}"
_BEARER_TOKEN_V2_PATTERN = r"\bAuthorization\s*:\s*Bearer\s+(?P<value>[A-Za-z0-9._~+/=-]{16,})"
_COOKIE_V1_PATTERN = r"\b(?:cookie|sessionid|sid|connect\.sid)\s*[:=]\s*[A-Za-z0-9._~+/=-]{16,}"
TRUSTED_RULE_PATTERN_UPGRADES = {
    ("secret.env_assignment", _ENV_ASSIGNMENT_V1_PATTERN): _CURRENT_RULE_PATTERNS["secret.env_assignment"],
    ("secret.env_assignment", _ENV_ASSIGNMENT_V2_PATTERN): _CURRENT_RULE_PATTERNS["secret.env_assignment"],
    ("secret.env_assignment", _ENV_ASSIGNMENT_V3_PATTERN): _CURRENT_RULE_PATTERNS["secret.env_assignment"],
    ("secret.env_assignment", _ENV_ASSIGNMENT_V4_PATTERN): _CURRENT_RULE_PATTERNS["secret.env_assignment"],
    ("secret.env_assignment", _ENV_ASSIGNMENT_V5_PATTERN): _CURRENT_RULE_PATTERNS["secret.env_assignment"],
    ("secret.bearer_token", _BEARER_TOKEN_V1_PATTERN): _CURRENT_RULE_PATTERNS["secret.bearer_token"],
    ("secret.bearer_token", _BEARER_TOKEN_V2_PATTERN): _CURRENT_RULE_PATTERNS["secret.bearer_token"],
    ("secret.cookie", _COOKIE_V1_PATTERN): _CURRENT_RULE_PATTERNS["secret.cookie"],
}
TRUSTED_RULE_PATTERNS = {
    (str(rule["id"]), str(rule["pattern"])) for rule in BUILTIN_RULE_VALUES
} | set(TRUSTED_RULE_PATTERN_UPGRADES)
CORE_RULES = [copy.deepcopy(rule) for rule in BUILTIN_RULE_VALUES if str(rule["id"]).startswith("apg.")]
CREDENTIAL_RULES = [copy.deepcopy(rule) for rule in BUILTIN_RULE_VALUES if str(rule["id"]).startswith("secret.")]
PII_RULES = [copy.deepcopy(rule) for rule in BUILTIN_RULE_VALUES if str(rule["id"]).startswith("pii.")]


def _module(
    module_id: str,
    name: str,
    module_type: str,
    config: dict[str, Any],
    *,
    enabled: bool = True,
    timeout_ms: int | None = None,
    failure_mode: str = "open",
    editable: bool = True,
) -> dict[str, Any]:
    return {
        "id": module_id,
        "name": name,
        "type": module_type,
        "enabled": enabled,
        "timeout_ms": timeout_ms,
        "failure_mode": failure_mode,
        "editable": editable,
        "config": copy.deepcopy(config),
    }


def _entropy_config() -> dict[str, Any]:
    return {
        "min_length": 20,
        "min_entropy": 3.5,
        "risk": "medium",
    }


def _path_config() -> dict[str, Any]:
    return {
        "detect_unix_home": True,
        "detect_macos_private": True,
        "detect_shell_config": True,
        "detect_windows_user": True,
        "exclude_patterns": [],
        "path_risk": "medium",
    }


def _model_config() -> dict[str, Any]:
    return {
        "adapter": "transformers_token_classification",
        "model_name": "iiiorg/piiranha-v1-detect-personal-information",
        "threshold": 0.75,
        "device": "cpu",
        "aggregation_strategy": "simple",
        "labels": ["email", "phone_number", "user_name"],
    }


def _builtin_templates() -> dict[str, dict[str, Any]]:
    created = _now()

    def template(template_id: str, name: str, description: str, tags: list[str], modules: list[dict[str, Any]]) -> dict[str, Any]:
        return {
            "id": template_id,
            "name": name,
            "description": description,
            "revision": 0,
            "source_template_id": None,
            "core_guard_enabled": True,
            "flow_timeout_ms": 1500,
            "modules": modules,
            "content_tags": tags,
            "created_at": created,
            "updated_at": created,
            "readonly": True,
            "template": True,
        }

    credentials = [
        _module("credentials", "凭据与密钥规则", "regex", {"rules": CREDENTIAL_RULES}, failure_mode="closed"),
        _module("entropy", "高熵 Token", "entropy", _entropy_config(), enabled=False, timeout_ms=100),
    ]
    personal = [
        _module("personal_data", "个人信息规则", "regex", {"rules": PII_RULES}),
        _module("personal_model", "个人信息小模型", "local_model", _model_config(), enabled=False, timeout_ms=800),
    ]
    local_context = [_module("local_paths", "本地路径", "path", _path_config(), failure_mode="closed")]
    comprehensive = [
        copy.deepcopy(credentials[0]),
        copy.deepcopy(personal[0]),
        copy.deepcopy(local_context[0]),
        copy.deepcopy(credentials[1]),
        copy.deepcopy(personal[1]),
    ]
    return {
        "builtin.credentials": template("builtin.credentials", "凭据与密钥", "API key、密码、Token、私钥和数据库凭据", ["credentials", "secrets"], credentials),
        "builtin.personal": template("builtin.personal", "个人信息", "联系方式、身份与财务类个人信息", ["pii", "identity"], personal),
        "builtin.local_context": template("builtin.local_context", "本地开发环境", "本机路径、配置目录和凭据文件位置", ["paths", "local"], local_context),
        "builtin.comprehensive": template("builtin.comprehensive", "全面保护", "凭据、个人信息与本地开发环境", ["credentials", "pii", "paths"], comprehensive),
    }


class DetectorControlPlane:
    """Own complete detector configurations and atomically swap active flows."""

    def __init__(
        self,
        base_config: dict[str, Any],
        state_path: str,
        apply_manager: Callable[[DetectorManager], None],
        model_path_resolver: Callable[[str, str, str], str | None] | None = None,
        model_runner: Callable[..., list[dict[str, Any]]] | None = None,
    ) -> None:
        self.base_config = copy.deepcopy(base_config)
        self.state_path = Path(state_path)
        self.apply_manager = apply_manager
        self.model_path_resolver = model_path_resolver
        self.model_runner = model_runner
        self._lock = threading.RLock()
        self._templates = _builtin_templates()
        self._templates.update(self._deployment_templates())
        self._state = self._load_state()
        self._manager = self._build_manager(self._configuration(self._state["active_configuration_id"]))
        self.apply_manager(self._manager)

    def catalog(self) -> dict[str, Any]:
        with self._lock:
            active_id = self._state["active_configuration_id"]
            return {
                "active_configuration_id": active_id,
                "apg_enabled": bool(self._state.get("apg_enabled", True)),
                "configuration_available": self._active_configuration_available(),
                "templates": [self._summary(item, active_id) for item in self._templates.values()],
                "configurations": [self._summary(item, active_id) for item in self._state["configurations"]],
                "module_types": self._module_type_catalog(),
            }

    def get_configuration(self, configuration_id: str) -> dict[str, Any]:
        with self._lock:
            return self._public_configuration(self._configuration(configuration_id))

    def local_model_references(self) -> list[dict[str, Any]]:
        """Expose only local-model references without invoking runtime availability checks."""
        with self._lock:
            active_id = self._state["active_configuration_id"]
            configurations = [
                *self._templates.values(),
                *self._state["configurations"],
            ]
            references: list[dict[str, Any]] = []
            for configuration in configurations:
                for module in configuration.get("modules", []):
                    if module.get("type") != "local_model":
                        continue
                    references.append({
                        "configuration_id": configuration["id"],
                        "configuration_name": configuration["name"],
                        "module_id": module["id"],
                        "module_name": module["name"],
                        "active": configuration["id"] == active_id,
                        "enabled": bool(module.get("enabled", True)),
                        "config": copy.deepcopy(module.get("config", {})),
                    })
            return references

    def create_configuration(self, payload: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            source_id = str(payload.get("source_id", "")).strip()
            source = self._configuration(source_id) if source_id else None
            now = _now()
            configuration = {
                "id": f"dcfg_{uuid.uuid4().hex[:16]}",
                "name": str(payload.get("name") or (f"{source['name']} - 自定义" if source else "新检测配置")),
                "description": str(payload.get("description") or (source.get("description", "") if source else "")),
                "revision": 1,
                "source_template_id": source_id if source and source.get("template") else source.get("source_template_id") if source else None,
                "core_guard_enabled": True,
                "flow_timeout_ms": source.get("flow_timeout_ms", 1500) if source else 1500,
                "modules": copy.deepcopy(source.get("modules", [])) if source else [],
                "content_tags": list(source.get("content_tags", [])) if source else [],
                "created_at": now,
                "updated_at": now,
                "readonly": False,
                "template": False,
            }
            configuration = self._validate_configuration(configuration, trusted=bool(source))
            next_state = copy.deepcopy(self._state)
            next_state["configurations"].append(configuration)
            self._persist_state(next_state)
            self._state = next_state
            return self._public_configuration(configuration)

    def save_configuration(self, configuration_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            current = self._user_configuration(configuration_id)
            try:
                revision = int(payload.get("revision"))
            except (TypeError, ValueError) as exc:
                raise DetectorControlError("Expected integer revision") from exc
            if revision != current["revision"]:
                raise DetectorConfigurationConflict("Configuration revision is stale")
            candidate = {
                **copy.deepcopy(current),
                "name": payload.get("name", current["name"]),
                "description": payload.get("description", current.get("description", "")),
                "core_guard_enabled": True,
                "flow_timeout_ms": payload.get("flow_timeout_ms", current.get("flow_timeout_ms")),
                "modules": payload.get("modules", current["modules"]),
                "content_tags": payload.get("content_tags", current.get("content_tags", [])),
                "revision": current["revision"] + 1,
                "updated_at": _now(),
            }
            candidate = self._validate_configuration(candidate, existing=current)
            candidate_manager = self._build_manager(candidate) if configuration_id == self._state["active_configuration_id"] else None
            next_state = copy.deepcopy(self._state)
            index = next(i for i, item in enumerate(next_state["configurations"]) if item["id"] == configuration_id)
            next_state["configurations"][index] = candidate
            self._persist_state(next_state)
            self._state = next_state
            if candidate_manager is not None:
                self._manager = candidate_manager
                self.apply_manager(candidate_manager)
            return self._public_configuration(candidate)

    def activate_configuration(self, configuration_id: str) -> dict[str, Any]:
        with self._lock:
            configuration = self._configuration(configuration_id)
            manager = self._build_manager(configuration)
            next_state = copy.deepcopy(self._state)
            next_state["active_configuration_id"] = configuration_id
            self._persist_state(next_state)
            self._state = next_state
            self._manager = manager
            self.apply_manager(manager)
            return self._public_configuration(configuration)

    def set_template_module_enabled(self, configuration_id: str, module_id: str, enabled: bool) -> dict[str, Any]:
        if not isinstance(enabled, bool):
            raise DetectorControlError("Expected boolean module enabled state")
        with self._lock:
            template = self._templates.get(configuration_id)
            if template is None:
                raise DetectorControlError("Only preset module switches can be updated directly")
            module = next((item for item in template["modules"] if item["id"] == module_id), None)
            if module is None:
                raise DetectorConfigurationNotFound("Unknown detector module")
            next_state = copy.deepcopy(self._state)
            overrides = next_state.setdefault("template_module_overrides", {})
            template_overrides = overrides.setdefault(configuration_id, {})
            if enabled == bool(module.get("enabled", True)):
                template_overrides.pop(module_id, None)
                if not template_overrides:
                    overrides.pop(configuration_id, None)
            else:
                template_overrides[module_id] = enabled
            configuration = self._template_configuration(configuration_id, next_state)
            manager = self._build_manager(configuration) if configuration_id == next_state["active_configuration_id"] else None
            self._persist_state(next_state)
            self._state = next_state
            if manager is not None:
                self._manager = manager
                self.apply_manager(manager)
            return self._public_configuration(configuration)

    def delete_configuration(self, configuration_id: str) -> dict[str, Any]:
        with self._lock:
            if configuration_id == self._state["active_configuration_id"]:
                raise DetectorConfigurationConflict("Activate another configuration before deleting this one")
            self._user_configuration(configuration_id)
            next_state = copy.deepcopy(self._state)
            next_state["configurations"] = [item for item in next_state["configurations"] if item["id"] != configuration_id]
            self._persist_state(next_state)
            self._state = next_state
            return self.catalog()

    def manager_for_configuration(self, configuration_id: str) -> DetectorManager:
        with self._lock:
            return self._build_manager(self._configuration(configuration_id))

    def active_configuration(self) -> dict[str, Any]:
        with self._lock:
            return self._public_configuration(self._configuration(self._state["active_configuration_id"]))

    def apg_enabled(self) -> bool:
        with self._lock:
            return bool(self._state.get("apg_enabled", True))

    def set_apg_enabled(self, enabled: bool) -> bool:
        if not isinstance(enabled, bool):
            raise DetectorControlError("Expected boolean APG enabled state")
        with self._lock:
            next_state = copy.deepcopy(self._state)
            next_state["apg_enabled"] = enabled
            self._persist_state(next_state)
            self._state = next_state
            return enabled

    def active_configuration_available(self) -> bool:
        with self._lock:
            return self._active_configuration_available()

    def _active_configuration_available(self) -> bool:
        try:
            self._configuration(str(self._state.get("active_configuration_id", "")))
        except DetectorConfigurationNotFound:
            return False
        return True

    def _configuration(self, configuration_id: str) -> dict[str, Any]:
        if configuration_id in self._templates:
            return self._template_configuration(configuration_id)
        for item in self._state.get("configurations", []):
            if item.get("id") == configuration_id:
                return item
        raise DetectorConfigurationNotFound("Unknown detector configuration")

    def _template_configuration(self, configuration_id: str, state: dict[str, Any] | None = None) -> dict[str, Any]:
        configuration = copy.deepcopy(self._templates[configuration_id])
        overrides = (state or self._state).get("template_module_overrides", {}).get(configuration_id, {})
        for module in configuration["modules"]:
            enabled = overrides.get(module["id"])
            if isinstance(enabled, bool):
                module["enabled"] = enabled
        return configuration

    def _user_configuration(self, configuration_id: str) -> dict[str, Any]:
        configuration = self._configuration(configuration_id)
        if configuration.get("readonly"):
            raise DetectorControlError("Built-in and deployment templates are read-only")
        return configuration

    def _build_manager(self, configuration: dict[str, Any]) -> DetectorManager:
        return DetectorManager(detectors_config=self._runtime_config(configuration))

    def _runtime_config(self, configuration: dict[str, Any]) -> dict[str, Any]:
        modules: list[dict[str, Any]] = []
        modules.append({
            "id": "apg_core",
            "type": "regex_rules",
            "rules": copy.deepcopy(CORE_RULES),
            "enabled": True,
            "fail_open": False,
            "stream_safe": True,
        })
        modules.extend(self._runtime_module(module) for module in configuration["modules"])
        return {
            "core_guard_enabled": True,
            "allow_model_download": bool(self.base_config.get("allow_model_download", False)),
            "model_path_resolver": self.model_path_resolver,
            "model_runner": self.model_runner,
            "allow_external_tools": copy.deepcopy(self.base_config.get("allow_external_tools", [])),
            "allow_python_plugins": copy.deepcopy(self.base_config.get("allow_python_plugins", [])),
            "flow": {
                "id": configuration["id"],
                "flow_timeout_ms": configuration.get("flow_timeout_ms"),
                "modules": modules,
            },
        }

    def _runtime_module(self, module: dict[str, Any]) -> dict[str, Any]:
        common = {
            "id": module["id"],
            "enabled": module["enabled"],
            "timeout_ms": module.get("timeout_ms"),
            "fail_open": module.get("failure_mode", "open") == "open",
        }
        config = copy.deepcopy(module.get("config", {}))
        if module["type"] == "regex":
            rules = config.get("rules", [])
            stream_safe = all((str(rule.get("id")), str(rule.get("pattern"))) in TRUSTED_RULE_PATTERNS for rule in rules)
            return {**common, "type": "regex_rules", "rules": rules, "stream_safe": stream_safe}
        if module["type"] == "entropy":
            return {**common, "type": "entropy_context", "stream_safe": True, **config}
        if module["type"] == "path":
            return {**common, "type": "path_detector", "stream_safe": True, **config}
        if module["type"] == "local_model":
            return {**common, "type": "local_model", **config}
        if module["type"] == "deployment":
            legacy = copy.deepcopy(config["legacy"])
            legacy.update({key: value for key, value in common.items() if value is not None})
            return legacy
        raise DetectorControlError("Unknown module type")

    def _validate_configuration(
        self,
        raw: dict[str, Any],
        *,
        existing: dict[str, Any] | None = None,
        trusted: bool = False,
    ) -> dict[str, Any]:
        value = copy.deepcopy(raw)
        configuration_id = str(value.get("id", ""))
        if not _CONFIG_ID_RE.fullmatch(configuration_id):
            raise DetectorControlError("Invalid configuration id")
        name = str(value.get("name", "")).strip()
        if not 1 <= len(name) <= 80:
            raise DetectorControlError("Configuration name must be between 1 and 80 characters")
        value["name"] = name
        value["description"] = str(value.get("description", "")).strip()[:240]
        value["core_guard_enabled"] = True
        timeout = value.get("flow_timeout_ms")
        value["flow_timeout_ms"] = self._bounded_int(timeout, 10, 120_000, "flow_timeout_ms", allow_none=True)
        modules = value.get("modules")
        if not isinstance(modules, list) or len(modules) > 64:
            raise DetectorControlError("Configuration modules must be a list with at most 64 entries")
        locked = {module["id"]: module for module in (existing or {}).get("modules", []) if module.get("type") == "deployment"}
        seen: set[str] = set()
        validated: list[dict[str, Any]] = []
        for module in modules:
            normalized = self._validate_module(module, locked=locked, trusted=trusted)
            if normalized["id"] in seen:
                raise DetectorControlError("Module ids must be unique within a configuration")
            seen.add(normalized["id"])
            validated.append(normalized)
        if set(locked) - seen:
            raise DetectorControlError("Deployment-managed modules cannot be removed")
        value["modules"] = validated
        tags = value.get("content_tags", [])
        if not isinstance(tags, list) or len(tags) > 16:
            raise DetectorControlError("content_tags must be a short list")
        value["content_tags"] = [str(tag).strip()[:32] for tag in tags if str(tag).strip()]
        value["readonly"] = bool(value.get("readonly", False))
        value["template"] = bool(value.get("template", False))
        return value

    def _validate_module(self, raw: Any, *, locked: dict[str, dict[str, Any]], trusted: bool) -> dict[str, Any]:
        if not isinstance(raw, dict):
            raise DetectorControlError("Each module must be an object")
        module = copy.deepcopy(raw)
        module_id = str(module.get("id", ""))
        if not _MODULE_ID_RE.fullmatch(module_id):
            raise DetectorControlError("Invalid module id")
        module_type = str(module.get("type", ""))
        if module_type == "deployment":
            if trusted:
                return module
            if module_id not in locked or module != locked[module_id]:
                raise DetectorControlError("Deployment-managed modules cannot be edited")
            return module
        if module_type not in MODULE_TYPE_LABELS:
            raise DetectorControlError("Unknown module type")
        name = str(module.get("name", "")).strip()
        if module_type == "path" and name == "本地路径与凭据文件":
            name = "本地路径"
        if not 1 <= len(name) <= 80:
            raise DetectorControlError("Module name must be between 1 and 80 characters")
        failure_mode = str(module.get("failure_mode", "open"))
        if failure_mode not in FAILURE_MODES:
            raise DetectorControlError("failure_mode must be open or closed")
        config = module.get("config")
        if not isinstance(config, dict):
            raise DetectorControlError("Module config must be an object")
        if module_type == "regex":
            normalized_config = self._validate_regex_config(config)
        elif module_type == "entropy":
            normalized_config = self._validate_entropy_config(config)
        elif module_type == "path":
            normalized_config = self._validate_path_config(config)
        else:
            normalized_config = self._validate_model_config(config)
        return {
            "id": module_id,
            "name": name,
            "type": module_type,
            "enabled": bool(module.get("enabled", True)),
            "timeout_ms": self._bounded_int(module.get("timeout_ms"), 1, 60_000, "timeout_ms", allow_none=True),
            "failure_mode": failure_mode,
            "editable": True,
            "config": normalized_config,
        }

    def _validate_regex_config(self, config: dict[str, Any]) -> dict[str, Any]:
        rules = config.get("rules")
        if not isinstance(rules, list) or len(rules) > 200:
            raise DetectorControlError("Regex modules support at most 200 rules")
        seen: set[str] = set()
        out: list[dict[str, Any]] = []
        for raw in rules:
            if not isinstance(raw, dict):
                raise DetectorControlError("Each regex rule must be an object")
            rule_id = str(raw.get("id", "")).strip().lower()
            if not _RULE_ID_RE.fullmatch(rule_id) or rule_id in seen:
                raise DetectorControlError("Regex rule ids must be valid and unique")
            seen.add(rule_id)
            pattern = str(raw.get("pattern", ""))
            if not pattern or len(pattern) > 512:
                raise DetectorControlError("Pattern must be between 1 and 512 characters")
            upgraded_builtin = (rule_id, pattern) in TRUSTED_RULE_PATTERN_UPGRADES
            pattern = TRUSTED_RULE_PATTERN_UPGRADES.get((rule_id, pattern), pattern)
            if (rule_id, pattern) not in TRUSTED_RULE_PATTERNS and (
                _UNSAFE_GROUP_REPEAT_RE.search(pattern) or _UNSAFE_REGEX_FEATURE_RE.search(pattern)
            ):
                raise DetectorControlError("Backreferences, lookarounds, wildcards, and repeating groups are not allowed")
            try:
                compiled = re.compile(pattern)
            except re.error as exc:
                raise DetectorControlError(f"Invalid regular expression: {exc.msg}") from exc
            if compiled.match(""):
                raise DetectorControlError("Pattern must not match empty text")
            subtype = str(raw.get("subtype", rule_id.rsplit(".", 1)[-1])).strip().lower()
            if not _SUBTYPE_RE.fullmatch(subtype):
                raise DetectorControlError("Invalid rule subtype")
            finding_type = str(raw.get("type", "MACHINE_SECRET"))
            risk = str(raw.get("risk", "high"))
            action = str(raw.get("suggested_action", "redact"))
            if finding_type not in FINDING_TYPES or risk not in RISK_LEVELS or action not in ACTIONS:
                raise DetectorControlError("Invalid rule type, risk, or action")
            raw_flags = raw.get("flags", [])
            if isinstance(raw_flags, str):
                raw_flags = [raw_flags]
            if not isinstance(raw_flags, (list, tuple)):
                raise DetectorControlError("flags must be a list")
            flags = [str(flag).upper() for flag in raw_flags]
            if any(flag not in REGEX_FLAGS for flag in flags):
                raise DetectorControlError("Invalid regex flag")
            validators = self._validator_names(raw.get("validators", []))
            require_validators = self._validator_names(raw.get("require_validators", []))
            reject_validators = self._validator_names(raw.get("reject_validators", []))
            if upgraded_builtin and rule_id == "secret.env_assignment":
                validators = list(dict.fromkeys([*validators, "credential_assignment_value"]))
                require_validators = list(dict.fromkeys([*require_validators, "credential_assignment_value"]))
            required_builtin_validators = {
                "pii.email": "email_structure",
                "pii.phone": "phone_shape",
            }
            required_validator = required_builtin_validators.get(rule_id)
            if (rule_id, pattern) in TRUSTED_RULE_PATTERNS and required_validator is not None:
                validators = list(dict.fromkeys([*validators, required_validator]))
                require_validators = list(dict.fromkeys([*require_validators, required_validator]))
            out.append({
                "id": rule_id,
                "pattern": pattern,
                "type": finding_type,
                "subtype": subtype,
                "risk": risk,
                "suggested_action": action,
                "flags": flags,
                "validators": validators,
                "require_validators": require_validators,
                "reject_validators": reject_validators,
                "preview_keep": self._bounded_int(raw.get("preview_keep", 0), 0, 16, "preview_keep"),
                "enabled": bool(raw.get("enabled", True)),
                "metadata": copy.deepcopy(raw.get("metadata", {})) if isinstance(raw.get("metadata", {}), dict) else {},
            })
        return {"rules": out}

    def _validate_entropy_config(self, config: dict[str, Any]) -> dict[str, Any]:
        return {
            "min_length": self._bounded_int(config.get("min_length", 20), 8, 512, "min_length"),
            "min_entropy": self._bounded_float(config.get("min_entropy", 3.5), 0.0, 8.0, "min_entropy"),
            "risk": self._choice(config.get("risk", "medium"), RISK_LEVELS, "risk"),
        }

    def _validate_path_config(self, config: dict[str, Any]) -> dict[str, Any]:
        return {
            "detect_unix_home": bool(config.get("detect_unix_home", True)),
            "detect_macos_private": bool(config.get("detect_macos_private", True)),
            "detect_shell_config": bool(config.get("detect_shell_config", True)),
            "detect_windows_user": bool(config.get("detect_windows_user", True)),
            "exclude_patterns": self._string_list(config.get("exclude_patterns", []), "exclude_patterns", 128),
            "path_risk": self._choice(config.get("path_risk", "medium"), RISK_LEVELS, "path_risk"),
        }

    def _validate_model_config(self, config: dict[str, Any]) -> dict[str, Any]:
        adapter = str(config.get("adapter", "transformers_token_classification"))
        if adapter not in {"transformers_token_classification", "gliner"}:
            raise DetectorControlError("Unknown local model adapter")
        model_name = str(config.get("model_name", "")).strip()
        prefix = "https://huggingface.co/"
        if model_name.startswith(prefix):
            model_name = model_name[len(prefix):].strip("/").split("/tree/", 1)[0]
        if not model_name or len(model_name) > 256 or any(char in model_name for char in "\r\n\0"):
            raise DetectorControlError("Invalid Hugging Face model name or local path")
        device = str(config.get("device", "cpu")).strip().lower()
        if not re.fullmatch(r"cpu|mps|cuda(?::[0-9]+)?", device):
            raise DetectorControlError("device must be cpu, mps, cuda, or cuda:N")
        aggregation = str(config.get("aggregation_strategy", "simple"))
        if aggregation not in {"simple", "first", "average", "max"}:
            raise DetectorControlError("Invalid aggregation strategy")
        labels = self._string_list(config.get("labels", []), "labels", 128)
        if adapter == "gliner" and not labels:
            raise DetectorControlError("GLiNER modules require at least one label")
        return {
            "adapter": adapter,
            "model_name": model_name,
            "threshold": self._bounded_float(config.get("threshold", 0.75), 0.0, 1.0, "threshold"),
            "device": device,
            "aggregation_strategy": aggregation,
            "labels": labels,
        }

    @staticmethod
    def _validator_names(value: Any) -> list[str]:
        if isinstance(value, str):
            value = [value]
        if not isinstance(value, (list, tuple)):
            raise DetectorControlError("validators must be a list")
        names = [str(item) for item in value]
        if any(name not in VALIDATORS for name in names):
            raise DetectorControlError("Unknown validator")
        return names

    @staticmethod
    def _string_list(value: Any, field: str, limit: int) -> list[str]:
        if not isinstance(value, (list, tuple)) or len(value) > limit:
            raise DetectorControlError(f"{field} must be a list with at most {limit} items")
        out = [str(item).strip() for item in value if str(item).strip()]
        if any(len(item) > 256 for item in out):
            raise DetectorControlError(f"{field} entries are too long")
        return out

    @staticmethod
    def _choice(value: Any, choices: set[str], field: str) -> str:
        normalized = str(value)
        if normalized not in choices:
            raise DetectorControlError(f"Invalid {field}")
        return normalized

    @staticmethod
    def _bounded_int(value: Any, minimum: int, maximum: int, field: str, *, allow_none: bool = False) -> int | None:
        if value is None and allow_none:
            return None
        try:
            result = int(value)
        except (TypeError, ValueError) as exc:
            raise DetectorControlError(f"{field} must be an integer") from exc
        if not minimum <= result <= maximum:
            raise DetectorControlError(f"{field} must be between {minimum} and {maximum}")
        return result

    @staticmethod
    def _bounded_float(value: Any, minimum: float, maximum: float, field: str) -> float:
        try:
            result = float(value)
        except (TypeError, ValueError) as exc:
            raise DetectorControlError(f"{field} must be a number") from exc
        if not minimum <= result <= maximum:
            raise DetectorControlError(f"{field} must be between {minimum} and {maximum}")
        return result

    def _module_type_catalog(self) -> list[dict[str, Any]]:
        transformers = self._module_available("transformers")
        gliner = self._module_available("gliner")
        return [
            {"id": "regex", "label": MODULE_TYPE_LABELS["regex"], "description": "多条安全正则与格式验证器", "available": True},
            {
                "id": "entropy",
                "label": MODULE_TYPE_LABELS["entropy"],
                "description": "按长度和熵值检测随机 Token（可选，代码场景可能误报）",
                "available": True,
            },
            {"id": "path", "label": MODULE_TYPE_LABELS["path"], "description": "本地路径位置", "available": True},
            {
                "id": "local_model",
                "label": MODULE_TYPE_LABELS["local_model"],
                "description": "延迟加载的本地 PII 模型",
                "available": transformers or gliner,
                "adapters": {
                    "transformers_token_classification": {"available": transformers},
                    "gliner": {"available": gliner},
                },
                "download_allowed": bool(self.base_config.get("allow_model_download", False)),
            },
        ]

    @staticmethod
    def _module_available(name: str) -> bool:
        try:
            return importlib.util.find_spec(name) is not None
        except (ImportError, ValueError):
            return False

    def _summary(self, configuration: dict[str, Any], active_id: str) -> dict[str, Any]:
        return {
            "id": configuration["id"],
            "name": configuration["name"],
            "description": configuration.get("description", ""),
            "revision": configuration["revision"],
            "source_template_id": configuration.get("source_template_id"),
            "module_count": len(configuration.get("modules", [])),
            "content_tags": list(configuration.get("content_tags", [])),
            "readonly": bool(configuration.get("readonly")),
            "template": bool(configuration.get("template")),
            "is_active": configuration["id"] == active_id,
            "updated_at": configuration.get("updated_at"),
        }

    def _public_configuration(self, configuration: dict[str, Any]) -> dict[str, Any]:
        value = copy.deepcopy(configuration)
        value["is_active"] = configuration["id"] == self._state["active_configuration_id"]
        for module in value.get("modules", []):
            if module.get("type") == "local_model":
                config = module.get("config", {})
                adapter = config.get("adapter", "transformers_token_classification")
                model_name = str(config.get("model_name", ""))
                device = str(config.get("device", "cpu"))
                if self.model_path_resolver is not None:
                    runtime_available = self.model_path_resolver(model_name, str(adapter), device) is not None
                else:
                    package = "gliner" if adapter == "gliner" else "transformers"
                    runtime_available = self._module_available(package)
                module["runtime_available"] = runtime_available
                module["local_model_id"] = local_model_id(model_name, str(adapter), device)
        return value

    def _deployment_templates(self) -> dict[str, dict[str, Any]]:
        templates: dict[str, dict[str, Any]] = {}
        custom = self.base_config.get("presets", {})
        if isinstance(custom, dict):
            for name in custom:
                if str(name) in LEGACY_PRESETS:
                    continue
                compiled = compile_flow_config({**copy.deepcopy(self.base_config), "preset": str(name)})
                template_id = f"deployment.{self._slug(str(name))}"
                templates[template_id] = self._deployment_template(template_id, str(name), compiled)
        flow = self.base_config.get("flow")
        if isinstance(flow, dict) and flow.get("modules"):
            compiled = compile_flow_config(copy.deepcopy(self.base_config))
            templates["deployment.current"] = self._deployment_template("deployment.current", str(flow.get("id", "Deployment flow")), compiled)
        elif self.base_config.get("overrides") or (
            "preset" in self.base_config and str(self.base_config.get("preset")) in LEGACY_PRESETS
        ):
            compiled = compile_flow_config(copy.deepcopy(self.base_config))
            templates["deployment.current"] = self._deployment_template(
                "deployment.current",
                str(self.base_config.get("preset", "Configured detector flow")),
                compiled,
            )
        return templates

    def _deployment_template(self, template_id: str, name: str, compiled: dict[str, Any]) -> dict[str, Any]:
        now = _now()
        return {
            "id": template_id,
            "name": name,
            "description": "由 YAML 管理的只读检测配置",
            "revision": 0,
            "source_template_id": None,
            "core_guard_enabled": True,
            "flow_timeout_ms": compiled.get("flow_timeout_ms"),
            "modules": self._legacy_modules_to_unified(compiled.get("modules", [])),
            "content_tags": ["deployment"],
            "created_at": now,
            "updated_at": now,
            "readonly": True,
            "template": True,
        }

    def _legacy_modules_to_unified(self, modules: list[dict[str, Any]]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for index, raw in enumerate(modules):
            module_type = str(raw.get("type", "regex_rules"))
            module_id = str(raw.get("id", f"legacy_{index}"))
            enabled = bool(raw.get("enabled", True))
            timeout = raw.get("timeout_ms")
            failure_mode = "open" if bool(raw.get("fail_open", True)) else "closed"
            if module_type in {"regex_rules", "rule_validator"}:
                rules = [copy.deepcopy(rule) for rule in raw.get("rules", []) if not str(rule.get("id", "")).startswith("apg.")]
                if rules:
                    out.append(_module(module_id, module_id.replace("_", " ").title(), "regex", {"rules": rules}, enabled=enabled, timeout_ms=timeout, failure_mode=failure_mode))
            elif module_type == "entropy_context":
                config = _entropy_config()
                config.update({key: raw[key] for key in config if key in raw})
                out.append(_module(module_id, module_id.replace("_", " ").title(), "entropy", config, enabled=enabled, timeout_ms=timeout, failure_mode=failure_mode))
            elif module_type == "path_detector":
                config = _path_config()
                config.update({key: raw[key] for key in config if key in raw})
                out.append(_module(module_id, module_id.replace("_", " ").title(), "path", config, enabled=enabled, timeout_ms=timeout, failure_mode=failure_mode))
            elif module_type in {"hf_token_classification", "gliner", "local_model"}:
                config = _model_config()
                config.update({key: raw[key] for key in config if key in raw})
                config["adapter"] = "gliner" if module_type == "gliner" else str(raw.get("adapter", "transformers_token_classification"))
                if config.get("device") == -1:
                    config["device"] = "cpu"
                elif isinstance(config.get("device"), int):
                    config["device"] = f"cuda:{config['device']}"
                out.append(_module(module_id, module_id.replace("_", " ").title(), "local_model", config, enabled=enabled, timeout_ms=timeout, failure_mode=failure_mode))
            else:
                out.append(_module(module_id, module_id.replace("_", " ").title(), "deployment", {"legacy": copy.deepcopy(raw)}, enabled=enabled, timeout_ms=timeout, failure_mode=failure_mode, editable=False))
        return out

    def _load_state(self) -> dict[str, Any]:
        empty = {
            "version": 2,
            "builtin_ruleset_revision": BUILTIN_RULESET_REVISION,
            "active_configuration_id": self._default_active_id(),
            "apg_enabled": True,
            "template_module_overrides": {},
            "configurations": [],
        }
        if not self.state_path.exists():
            return empty
        try:
            text = self.state_path.read_text(encoding="utf-8")
            data = json.loads(text)
        except (OSError, ValueError):
            return empty
        if not isinstance(data, dict):
            return empty
        if data.get("version") == 2:
            try:
                configurations = [self._validate_configuration(item, trusted=True) for item in data.get("configurations", [])]
                active = str(data.get("active_configuration_id", self._default_active_id()))
                stored_enabled = data.get("apg_enabled", True)
                state = {
                    "version": 2,
                    "builtin_ruleset_revision": int(data.get("builtin_ruleset_revision", 1)),
                    "active_configuration_id": active,
                    "apg_enabled": stored_enabled if isinstance(stored_enabled, bool) else True,
                    "template_module_overrides": self._validate_template_module_overrides(data.get("template_module_overrides", {})),
                    "configurations": configurations,
                }
                if active not in self._templates and not any(item["id"] == active for item in configurations):
                    state["active_configuration_id"] = self._default_active_id()
                if state["builtin_ruleset_revision"] < BUILTIN_RULESET_REVISION:
                    self._upgrade_builtin_ruleset(state)
                    try:
                        self._persist_state(state)
                    except OSError:
                        pass
                return state
            except DetectorControlError:
                return empty
        if data.get("version") == 1:
            try:
                migrated = self._migrate_v1(data)
            except (DetectorControlError, TypeError, ValueError):
                return self._v1_fallback_state(data)
            try:
                backup = self.state_path.with_suffix(self.state_path.suffix + ".apg.bak")
                shutil.copyfile(self.state_path, backup)
                os.chmod(backup, 0o600)
                self._persist_state(migrated)
            except OSError:
                pass
            return migrated
        return empty

    def _default_active_id(self) -> str:
        if isinstance(self.base_config.get("flow"), dict) and self.base_config["flow"].get("modules"):
            return "deployment.current"
        if self.base_config.get("overrides") or (
            "preset" in self.base_config and str(self.base_config.get("preset")) in LEGACY_PRESETS
        ):
            return "deployment.current"
        preset = str(self.base_config.get("preset", "default"))
        deployment_id = f"deployment.{self._slug(preset)}"
        return deployment_id if deployment_id in self._templates else "builtin.comprehensive"

    def _migrate_v1(self, data: dict[str, Any]) -> dict[str, Any]:
        effective = self._effective_v1_config(data)
        compiled = compile_flow_config(effective)
        now = _now()
        configuration = {
            "id": "dcfg_6d69677261746564",
            "name": "迁移的检测配置",
            "description": "由旧版检测器预设和覆盖项自动迁移",
            "revision": 1,
            "source_template_id": None,
            "core_guard_enabled": True,
            "flow_timeout_ms": compiled.get("flow_timeout_ms"),
            "modules": self._legacy_modules_to_unified(compiled.get("modules", [])),
            "content_tags": ["migrated"],
            "created_at": now,
            "updated_at": now,
            "readonly": False,
            "template": False,
        }
        configuration = self._validate_configuration(configuration, trusted=True)
        return {
            "version": 2,
            "builtin_ruleset_revision": BUILTIN_RULESET_REVISION,
            "active_configuration_id": configuration["id"],
            "apg_enabled": True,
            "template_module_overrides": {},
            "configurations": [configuration],
        }

    def _effective_v1_config(self, data: dict[str, Any]) -> dict[str, Any]:
        effective = copy.deepcopy(self.base_config)
        if isinstance(data.get("preset"), str) and data["preset"]:
            effective["preset"] = data["preset"]
            effective.pop("flow", None)
        overrides = effective.setdefault("overrides", {})
        module_overrides = overrides.setdefault("modules", {})
        if isinstance(data.get("module_overrides"), dict):
            for module_id, values in data["module_overrides"].items():
                if isinstance(values, dict):
                    module_overrides.setdefault(module_id, {}).update(copy.deepcopy(values))
        rules = overrides.setdefault("rules", {})
        custom_rules = data.get("custom_rules", []) if isinstance(data.get("custom_rules"), list) else []
        rules.setdefault("add", []).extend(copy.deepcopy(custom_rules))
        return effective

    def _v1_fallback_state(self, data: dict[str, Any]) -> dict[str, Any]:
        compiled = compile_flow_config(self._effective_v1_config(data))
        now = _now()
        modules: list[dict[str, Any]] = []
        for index, raw in enumerate(compiled.get("modules", [])):
            legacy = copy.deepcopy(raw)
            if legacy.get("type") in {"regex_rules", "rule_validator"}:
                legacy["rules"] = [
                    rule for rule in legacy.get("rules", []) if not str(rule.get("id", "")).startswith("apg.")
                ]
                if not legacy["rules"]:
                    continue
            module_id = str(legacy.get("id", f"legacy_{index}"))
            modules.append(
                _module(
                    module_id,
                    module_id.replace("_", " ").title(),
                    "deployment",
                    {"legacy": legacy},
                    enabled=bool(legacy.get("enabled", True)),
                    timeout_ms=legacy.get("timeout_ms"),
                    failure_mode="open" if bool(legacy.get("fail_open", True)) else "closed",
                    editable=False,
                )
            )
        configuration = {
            "id": "dcfg_6c65676163796662",
            "name": "旧版检测配置（兼容模式）",
            "description": "新版迁移校验失败；继续使用未写回的旧版流水线",
            "revision": 1,
            "source_template_id": None,
            "core_guard_enabled": True,
            "flow_timeout_ms": compiled.get("flow_timeout_ms"),
            "modules": modules,
            "content_tags": ["legacy", "fallback"],
            "created_at": now,
            "updated_at": now,
            "readonly": False,
            "template": False,
        }
        return {
            "version": 2,
            "builtin_ruleset_revision": BUILTIN_RULESET_REVISION,
            "active_configuration_id": configuration["id"],
            "apg_enabled": True,
            "template_module_overrides": {},
            "configurations": [configuration],
        }

    def _upgrade_builtin_ruleset(self, state: dict[str, Any]) -> None:
        previous_revision = int(state.get("builtin_ruleset_revision", 1))
        for configuration in state.get("configurations", []):
            changed = False
            if previous_revision < 2:
                for module in configuration.get("modules", []):
                    if module.get("type") != "regex":
                        continue
                    rules = module.get("config", {}).get("rules", [])
                    retained = [
                        rule
                        for rule in rules
                        if str(rule.get("id")) not in BUILTIN_RULESET_REVISION_2_REMOVALS
                    ]
                    if len(retained) != len(rules):
                        rules[:] = retained
                        changed = True
            source_id = str(configuration.get("source_template_id") or "")
            source = self._templates.get(source_id)
            if previous_revision < 2 and source is not None:
                source_modules = {str(module["id"]): module for module in source.get("modules", [])}
                for module in configuration.get("modules", []):
                    if module.get("type") != "regex":
                        continue
                    source_module = source_modules.get(str(module.get("id")))
                    if source_module is None or source_module.get("type") != "regex":
                        continue
                    rules = module.get("config", {}).get("rules", [])
                    existing_ids = {str(rule.get("id")) for rule in rules}
                    additions = [
                        copy.deepcopy(rule)
                        for rule in source_module.get("config", {}).get("rules", [])
                        if str(rule.get("id")) in BUILTIN_RULESET_REVISION_2_ADDITIONS
                        and str(rule.get("id")) not in existing_ids
                    ]
                    if additions:
                        rules.extend(additions)
                        changed = True
            if previous_revision < 3:
                for module in configuration.get("modules", []):
                    if module.get("type") != "regex":
                        continue
                    for rule in module.get("config", {}).get("rules", []):
                        rule_id = str(rule.get("id"))
                        subtype_update = BUILTIN_RULESET_REVISION_3_SUBTYPES.get(rule_id)
                        if subtype_update is None or str(rule.get("pattern")) != _CURRENT_RULE_PATTERNS.get(rule_id):
                            continue
                        old_subtype, new_subtype = subtype_update
                        if str(rule.get("subtype")) != old_subtype:
                            continue
                        builtin = next(item for item in BUILTIN_RULE_VALUES if str(item["id"]) == rule_id)
                        rule["subtype"] = new_subtype
                        if not rule.get("metadata") and builtin.get("metadata"):
                            rule["metadata"] = copy.deepcopy(builtin["metadata"])
                        changed = True
            if previous_revision < 4 and source is not None:
                source_modules = {str(module["id"]): module for module in source.get("modules", [])}
                for module in configuration.get("modules", []):
                    if module.get("type") != "regex":
                        continue
                    source_module = source_modules.get(str(module.get("id")))
                    if source_module is None or source_module.get("type") != "regex":
                        continue
                    rules = module.get("config", {}).get("rules", [])
                    existing_ids = {str(rule.get("id")) for rule in rules}
                    additions = [
                        copy.deepcopy(rule)
                        for rule in source_module.get("config", {}).get("rules", [])
                        if str(rule.get("id")) in BUILTIN_RULESET_REVISION_4_ADDITIONS
                        and str(rule.get("id")) not in existing_ids
                    ]
                    if additions:
                        rules.extend(additions)
                        changed = True
            if changed:
                configuration["revision"] = int(configuration.get("revision", 0)) + 1
                configuration["updated_at"] = _now()
        state["builtin_ruleset_revision"] = BUILTIN_RULESET_REVISION

    def _validate_template_module_overrides(self, value: Any) -> dict[str, dict[str, bool]]:
        if not isinstance(value, dict):
            return {}
        out: dict[str, dict[str, bool]] = {}
        for configuration_id, raw_modules in value.items():
            template = self._templates.get(str(configuration_id))
            if template is None or not isinstance(raw_modules, dict):
                continue
            module_ids = {str(module["id"]) for module in template["modules"]}
            modules = {
                str(module_id): enabled
                for module_id, enabled in raw_modules.items()
                if str(module_id) in module_ids and isinstance(enabled, bool)
            }
            if modules:
                out[str(configuration_id)] = modules
        return out

    def _persist_state(self, state: dict[str, Any]) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        temp = self.state_path.with_suffix(self.state_path.suffix + ".tmp")
        temp.write_text(json.dumps(state, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
        os.chmod(temp, 0o600)
        temp.replace(self.state_path)

    @staticmethod
    def _slug(value: str) -> str:
        slug = re.sub(r"[^a-z0-9_.-]+", "-", value.lower()).strip("-.")
        if not slug or not slug[0].isalpha():
            slug = "config-" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:8]
        return slug[:48]
