from __future__ import annotations

import copy
import json
import os
import re
import threading
from pathlib import Path
from typing import Any, Callable

from gateway.detector_manager import DetectorManager
from gateway.detectors.flow import compile_flow_config
from gateway.detectors.rules import RuleBasedDetector


PRESET_LABELS = {
    "fast": "Fast",
    "default": "Balanced",
    "strict": "Strict",
    "model_enhanced": "Model enhanced",
}

MODULE_DESCRIPTIONS = {
    "regex_rules": "Deterministic patterns and format validators",
    "rule_validator": "Deterministic patterns with validators",
    "path_detector": "Local paths and credential-file context",
    "entropy_context": "Random-looking tokens near sensitive names",
    "hf_token_classification": "Local token-classification PII model",
    "gliner": "Local GLiNER semantic PII model",
    "external_tool": "Allowlisted local scanner process",
    "python_plugin": "Allowlisted local Python detector plugin",
}

_RULE_ID_RE = re.compile(r"^custom\.[a-z][a-z0-9_.-]{1,63}$")
_UNSAFE_GROUP_REPEAT_RE = re.compile(r"\([^)]*\)\s*(?:[+*]|\{)")
_UNSAFE_REGEX_FEATURE_RE = re.compile(r"\(\?(?:[=!<]|P=)|\\[1-9]|\.\*|\.\+")


class DetectorControlError(ValueError):
    pass


class DetectorControlPlane:
    """Persist small WebUI overrides and atomically rebuild detector flows."""

    def __init__(
        self,
        base_config: dict[str, Any],
        state_path: str,
        apply_manager: Callable[[DetectorManager], None],
    ) -> None:
        self.base_config = copy.deepcopy(base_config)
        self.state_path = Path(state_path)
        self.apply_manager = apply_manager
        self._lock = threading.RLock()
        self._state = self._load_state()
        self._manager = self._build_manager()
        self.apply_manager(self._manager)

    def catalog(self) -> dict[str, Any]:
        with self._lock:
            compiled = compile_flow_config(self._effective_config())
            modules: list[dict[str, Any]] = []
            runtime_by_id = {module.id: module for module in self._manager.hierarchical.flow.modules}
            for raw in compiled["modules"]:
                module_id = str(raw.get("id", raw.get("type", "module")))
                module_type = str(raw.get("type", "regex_rules"))
                runtime = runtime_by_id.get(module_id)
                rule_count = 0
                if runtime and isinstance(runtime.detector, RuleBasedDetector):
                    rule_count = len(runtime.detector.rules)
                status = "ready"
                error = None
                if runtime is None:
                    status = "unavailable"
                elif not runtime.enabled:
                    status = "disabled"
                elif runtime.config_error:
                    status = "error"
                    error = runtime.config_error
                modules.append(
                    {
                        "id": module_id,
                        "type": module_type,
                        "enabled": bool(runtime.enabled if runtime else raw.get("enabled", True)),
                        "status": status,
                        "error": error,
                        "timeout_ms": runtime.timeout_ms if runtime else raw.get("timeout_ms"),
                        "fail_open": runtime.fail_open if runtime else bool(raw.get("fail_open", True)),
                        "rule_count": rule_count,
                        "category": _module_category(module_type),
                        "description": MODULE_DESCRIPTIONS.get(module_type, "Local detector module"),
                    }
                )
            presets = list(PRESET_LABELS)
            for name in self.base_config.get("presets", {}):
                if name not in presets:
                    presets.append(str(name))
            return {
                "preset": compiled["preset"],
                "presets": [{"id": name, "label": PRESET_LABELS.get(name, name.replace("_", " ").title())} for name in presets],
                "flow_timeout_ms": compiled.get("flow_timeout_ms"),
                "modules": modules,
                "custom_rules": [self._public_rule(rule) for rule in self._state["custom_rules"]],
            }

    def set_preset(self, preset: str) -> dict[str, Any]:
        allowed = set(PRESET_LABELS) | set(self.base_config.get("presets", {}))
        if preset not in allowed:
            raise DetectorControlError("Unknown detector preset")
        return self._mutate(lambda state: state.__setitem__("preset", preset))

    def set_module_enabled(self, module_id: str, enabled: bool) -> dict[str, Any]:
        known = {str(module.get("id", module.get("type", "module"))) for module in compile_flow_config(self._effective_config())["modules"]}
        if module_id not in known:
            raise DetectorControlError("Unknown detector module")

        def update(state: dict[str, Any]) -> None:
            state["module_overrides"].setdefault(module_id, {})["enabled"] = bool(enabled)

        return self._mutate(update)

    def add_rule(self, payload: dict[str, Any]) -> dict[str, Any]:
        rule = self._validate_rule(payload)
        effective = compile_flow_config(self._effective_config())
        known_ids = {
            str(item.get("id"))
            for module in effective["modules"]
            for item in module.get("rules", [])
            if isinstance(item, dict)
        }
        if rule["id"] in known_ids:
            raise DetectorControlError("A rule with this id already exists")

        def update(state: dict[str, Any]) -> None:
            state["custom_rules"].append(rule)

        return self._mutate(update)

    def remove_rule(self, rule_id: str) -> dict[str, Any]:
        if not any(rule.get("id") == rule_id for rule in self._state["custom_rules"]):
            raise DetectorControlError("Unknown WebUI custom rule")

        def update(state: dict[str, Any]) -> None:
            state["custom_rules"] = [rule for rule in state["custom_rules"] if rule.get("id") != rule_id]

        return self._mutate(update)

    def _mutate(self, operation: Callable[[dict[str, Any]], None]) -> dict[str, Any]:
        with self._lock:
            next_state = copy.deepcopy(self._state)
            operation(next_state)
            previous = self._state
            self._state = next_state
            try:
                manager = self._build_manager()
                self._persist_state()
            except Exception:
                self._state = previous
                raise
            self._manager = manager
            self.apply_manager(manager)
            return self.catalog()

    def _effective_config(self) -> dict[str, Any]:
        config = copy.deepcopy(self.base_config)
        if self._state.get("preset"):
            config["preset"] = self._state["preset"]
            config.pop("flow", None)
        overrides = config.setdefault("overrides", {})
        modules = overrides.setdefault("modules", {})
        for module_id, values in self._state["module_overrides"].items():
            modules.setdefault(module_id, {}).update(values)
        rules = overrides.setdefault("rules", {})
        rules.setdefault("add", []).extend(copy.deepcopy(self._state["custom_rules"]))
        return config

    def _build_manager(self) -> DetectorManager:
        return DetectorManager(detectors_config=self._effective_config())

    def _load_state(self) -> dict[str, Any]:
        empty = {"version": 1, "preset": None, "module_overrides": {}, "custom_rules": []}
        if not self.state_path.exists():
            return empty
        try:
            data = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return empty
        if not isinstance(data, dict) or data.get("version") != 1:
            return empty
        return {
            "version": 1,
            "preset": data.get("preset") if isinstance(data.get("preset"), str) else None,
            "module_overrides": data.get("module_overrides") if isinstance(data.get("module_overrides"), dict) else {},
            "custom_rules": data.get("custom_rules") if isinstance(data.get("custom_rules"), list) else [],
        }

    def _persist_state(self) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        temp = self.state_path.with_suffix(self.state_path.suffix + ".tmp")
        temp.write_text(json.dumps(self._state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.chmod(temp, 0o600)
        temp.replace(self.state_path)

    def _validate_rule(self, payload: dict[str, Any]) -> dict[str, Any]:
        rule_id = str(payload.get("id", "")).strip().lower()
        if not _RULE_ID_RE.fullmatch(rule_id):
            raise DetectorControlError("Rule id must look like custom.partner_token")
        mode = str(payload.get("mode", "regex"))
        pattern = str(payload.get("pattern", ""))
        if mode == "prefix":
            prefix = str(payload.get("prefix", "")).strip()
            if not prefix or len(prefix) > 64 or not re.fullmatch(r"[A-Za-z0-9_.:-]+", prefix):
                raise DetectorControlError("Prefix must use letters, numbers, dot, colon, dash, or underscore")
            min_length = max(4, min(int(payload.get("min_length", 12)), 128))
            pattern = rf"\b{re.escape(prefix)}[A-Za-z0-9_-]{{{min_length},}}\b"
        if not pattern or len(pattern) > 512:
            raise DetectorControlError("Pattern must be between 1 and 512 characters")
        if _UNSAFE_GROUP_REPEAT_RE.search(pattern) or _UNSAFE_REGEX_FEATURE_RE.search(pattern):
            raise DetectorControlError("Backreferences, lookarounds, wildcards, and repeating groups are not allowed")
        try:
            compiled = re.compile(pattern)
        except re.error as exc:
            raise DetectorControlError(f"Invalid regular expression: {exc.msg}") from exc
        if compiled.match(""):
            raise DetectorControlError("Pattern must not match empty text")
        risk = str(payload.get("risk", "high"))
        action = str(payload.get("suggested_action", "redact"))
        finding_type = str(payload.get("type", "MACHINE_SECRET"))
        if risk not in {"low", "medium", "high", "critical"}:
            raise DetectorControlError("Invalid risk level")
        if action not in {"warn", "redact", "block", "pseudonymize", "alias"}:
            raise DetectorControlError("Invalid action")
        if finding_type not in {"MACHINE_SECRET", "PII", "LOCAL_CONTEXT", "CREDENTIAL_FILE", "UNKNOWN_SECRET_CANDIDATE"}:
            raise DetectorControlError("Invalid finding type")
        subtype = str(payload.get("subtype", rule_id.removeprefix("custom."))).strip().lower()
        if not re.fullmatch(r"[a-z][a-z0-9_.-]{1,63}", subtype):
            raise DetectorControlError("Invalid subtype")
        return {
            "id": rule_id,
            "pattern": pattern,
            "type": finding_type,
            "subtype": subtype,
            "confidence": max(0.5, min(float(payload.get("confidence", 0.9)), 0.99)),
            "risk": risk,
            "suggested_action": action,
            "preview_keep": 0,
            "metadata": {"source": "webui", "mode": mode},
        }

    @staticmethod
    def _public_rule(rule: dict[str, Any]) -> dict[str, Any]:
        return {
            key: value
            for key, value in rule.items()
            if key in {"id", "pattern", "type", "subtype", "confidence", "risk", "suggested_action", "metadata"}
        }


def _module_category(module_type: str) -> str:
    if module_type in {"regex_rules", "rule_validator"}:
        return "deterministic"
    if module_type in {"path_detector"}:
        return "context"
    if module_type in {"entropy_context"}:
        return "heuristic"
    if module_type in {"hf_token_classification", "gliner"}:
        return "model"
    if module_type == "external_tool":
        return "external"
    return "plugin"
