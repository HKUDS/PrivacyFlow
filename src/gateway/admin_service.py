from __future__ import annotations

import hashlib
import hmac
import json
import time
from collections import Counter
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from gateway.audit_logger import AuditLogger, scrub_audit_value
from gateway.config import GatewayConfig
from gateway.detector_control import DetectorControlPlane
from gateway.mapping_store import AuditOperationRecord, MappingRecord, MappingRetentionPolicy, MappingStore
from gateway.placeholder_parser import PlaceholderSigner


class AdminNotFoundError(LookupError):
    pass


class AdminService:
    def __init__(
        self,
        config: GatewayConfig,
        store: MappingStore,
        audit: AuditLogger,
        detector_control: DetectorControlPlane,
    ) -> None:
        self.config = config
        self.store = store
        self.audit = audit
        self.detector_control = detector_control
        self.signer = PlaceholderSigner(config.signing_secret, config.workspace_id)

    def overview(self) -> dict[str, Any]:
        events, truncated = self._read_events(max_events=5000)
        now = int(time.time())
        recent = [event for event in events if int(event.get("timestamp", 0)) >= now - 86_400]
        requests = sum(1 for event in recent if event.get("phase") == "request")
        detections = [d for event in recent for d in event.get("detections", []) if isinstance(d, dict)]
        interceptions = sum(1 for item in detections if item.get("action") not in {None, "allow"})
        materializations = sum(
            1
            for item in detections
            if item.get("type") == "materialization" and item.get("action") == "materialize"
        ) + sum(int(event.get("materialized", event.get("materialized_count", 0)) or 0) for event in recent)
        active = self.store.list_records(workspace_id=self.config.workspace_id, state="active", limit=2000)
        active = [record for record in active if not _record_expired(record, now)]

        day_counts: Counter[str] = Counter()
        for event in events:
            timestamp = int(event.get("timestamp", 0) or 0)
            if timestamp < now - 7 * 86_400:
                continue
            count = sum(1 for item in event.get("detections", []) if isinstance(item, dict) and item.get("action") != "allow")
            if count:
                day_counts[time.strftime("%Y-%m-%d", time.localtime(timestamp))] += count
        trend = []
        for days_ago in range(6, -1, -1):
            day = time.strftime("%Y-%m-%d", time.localtime(now - days_ago * 86_400))
            trend.append({"day": day, "count": day_counts[day]})

        risk = Counter(str(item.get("risk", "unknown")) for item in detections if item.get("action") != "allow")
        safe_recent = [self._safe_event(event) for event in reversed(events[-100:]) if event.get("detections")][:8]
        upstream = urlparse(self.config.upstream.base_url)
        active_detector_configuration = self.detector_control.active_configuration()
        return {
            "metrics": {
                "requests_24h": requests,
                "interceptions_24h": interceptions,
                "materializations_24h": materializations,
                "active_protected_values": len(active),
            },
            "trend": trend,
            "risk": {level: risk.get(level, 0) for level in ("critical", "high", "medium", "low")},
            "recent": safe_recent,
            "system": {
                "workspace": self.config.workspace_id,
                "upstream": upstream.hostname or "not configured",
                "detector_configuration": active_detector_configuration["name"],
                "pii_mode": self.config.pii_mode,
                "strict_mode": self.config.strict_mode,
                "local_only": self.config.bind_host in {"127.0.0.1", "localhost", "::1"},
                "audit_window_truncated": truncated,
            },
        }

    def connection_info(self) -> dict[str, Any]:
        local_keys = sorted(self.config.local_api_keys)
        self.audit.log(
            {
                "phase": "admin_action",
                "workspace_id": self.config.workspace_id,
                "action": "view_agent_connection_info",
                "available_key_count": len(local_keys),
                "result_code": "OK",
            }
        )
        return {
            "api_key": local_keys[0] if local_keys else "",
            "available_key_count": len(local_keys),
            "protocols": {
                "openai": {"base_path": "/v1"},
                "anthropic": {"base_path": ""},
            },
        }

    def audit_events(
        self,
        *,
        limit: int = 100,
        query: str = "",
        phase: str = "",
        risk: str = "",
        endpoint: str = "",
    ) -> dict[str, Any]:
        events, truncated = self._read_events(max_events=10_000)
        query_lower = query.strip().lower()
        results: list[dict[str, Any]] = []
        for event in reversed(events):
            if phase and event.get("phase") != phase:
                continue
            if endpoint and event.get("endpoint") != endpoint:
                continue
            detections = event.get("detections", [])
            if risk and not any(isinstance(item, dict) and item.get("risk") == risk for item in detections):
                continue
            safe = self._safe_event(event)
            if query_lower and query_lower not in json.dumps(safe, ensure_ascii=False).lower():
                continue
            results.append(safe)
            if len(results) >= max(1, min(limit, 250)):
                break
        return {
            "events": results,
            "count": len(results),
            "truncated": truncated,
            "filters": {
                "phases": sorted({str(event.get("phase")) for event in events if event.get("phase")}),
                "endpoints": sorted({str(event.get("endpoint")) for event in events if event.get("endpoint")}),
            },
        }

    def audit_requests(
        self,
        *,
        limit: int = 100,
        query: str = "",
        activity: str = "privacy",
        risk: str = "",
        endpoint: str = "",
    ) -> dict[str, Any]:
        events, truncated = self._read_events(max_events=10_000)
        groups = self._request_groups(events)
        operation_counts = self.store.audit_operation_counts(list(groups), self.config.workspace_id)
        query_lower = query.strip().lower()
        results: list[dict[str, Any]] = []
        for group in sorted(groups.values(), key=lambda item: (item["last_timestamp"], item["request_id"]), reverse=True):
            counts = operation_counts.get(group["request_id"], {})
            replacement_count = max(int(group["replacement_count"]), int(counts.get("replacement_count", 0)))
            materialization_count = max(int(group["materialization_count"]), int(counts.get("materialization_count", 0)))
            failed_count = max(int(group["materialization_failed_count"]), int(counts.get("materialization_failed_count", 0)))
            error = bool(
                group["parse_errors"]
                or group["status_code"] >= 400
                or group["termination"] in {
                    "failed",
                    "protocol_error",
                    "client_disconnected",
                    "upstream_disconnected",
                }
                or group["error_phase"]
            )
            if error:
                status = "error"
            elif group["termination"] == "completed":
                status = "completed"
            elif group["saw_stream"]:
                status = "in_progress"
            elif 200 <= group["status_code"] < 300:
                status = "completed"
            else:
                status = "recorded"
            item = {
                "id": group["request_id"],
                "request_id": group["request_id"],
                "timestamp": group["first_timestamp"],
                "completed_at": group["last_timestamp"],
                "endpoint": group["endpoint"] or None,
                "session": _short_identifier(group["session_id"], "Session"),
                "status": status,
                "status_code": group["status_code"] or None,
                "termination": group["termination"] or None,
                "risk": _highest_risk(group["risks"]),
                "replacement_count": replacement_count,
                "replacement_unique_count": int(counts.get("replacement_unique", 0)),
                "materialization_count": materialization_count,
                "materialization_unique_count": int(counts.get("materialization_unique", 0)),
                "materialization_failed_count": failed_count,
                "parse_errors": group["parse_errors"],
                "details_available": bool(counts),
                "details_truncated": bool(counts.get("omitted_count", 0) or group["operation_details_omitted"]),
                "omitted_count": int(counts.get("omitted_count", 0)) + group["operation_details_omitted"],
            }
            if activity == "privacy" and not (replacement_count or materialization_count or failed_count or error):
                continue
            if activity == "replacement" and not replacement_count:
                continue
            if activity == "materialization" and not materialization_count:
                continue
            if activity == "error" and not error:
                continue
            if endpoint and item["endpoint"] != endpoint:
                continue
            if risk and risk not in group["risks"]:
                continue
            if query_lower and query_lower not in json.dumps(item, ensure_ascii=False).lower():
                continue
            results.append(item)
            if len(results) >= max(1, min(limit, 250)):
                break
        return {
            "requests": results,
            "count": len(results),
            "truncated": truncated,
            "activity": activity,
            "filters": {
                "endpoints": sorted({str(group["endpoint"]) for group in groups.values() if group["endpoint"]}),
                "risks": [level for level in ("critical", "high", "medium", "low") if any(level in group["risks"] for group in groups.values())],
            },
        }

    def audit_operations(
        self,
        *,
        direction: str,
        limit: int = 250,
        query: str = "",
        risk: str = "",
        endpoint: str = "",
        include_raw: bool = False,
    ) -> dict[str, Any]:
        operations, total, occurrence_count = self.store.list_audit_operations(
            workspace_id=self.config.workspace_id,
            direction=direction,
            query=query,
            risk=risk,
            endpoint=endpoint,
            limit=limit,
        )
        details = [self._audit_operation_detail(operation, include_raw=include_raw) for operation in operations]
        if include_raw:
            self.audit.log(
                {
                    "phase": "admin_action",
                    "workspace_id": self.config.workspace_id,
                    "action": "view_audit_raw_values",
                    "target_direction": direction,
                    "returned_operation_count": len(details),
                    "available_value_count": sum(1 for detail in details if detail["value_state"] == "active"),
                    "result_code": "OK",
                }
            )
        return {
            "direction": direction,
            "operations": details,
            "count": total,
            "occurrence_count": occurrence_count,
            "truncated": total > len(details),
            "raw_values_included": include_raw,
            "filters": self.store.audit_operation_filter_values(self.config.workspace_id, direction),
        }

    def audit_request_detail(self, request_id: str, *, include_raw: bool = False) -> dict[str, Any]:
        events, _ = self._read_events(max_events=10_000)
        groups = self._request_groups(events)
        group = groups.get(request_id)
        if group is None:
            raise AdminNotFoundError("Audit request not found")
        operations = self.store.audit_operations_for_request(request_id, self.config.workspace_id)
        details = [self._audit_operation_detail(operation, include_raw=include_raw) for operation in operations]
        replacements = [detail for detail in details if detail["direction"] == "replacement"]
        materializations = [detail for detail in details if detail["direction"] == "materialization"]
        failures = [detail for detail in details if detail["direction"] == "materialization_failed"]
        failure_reasons = dict(group["materialization_failures"])
        if include_raw:
            self.audit.log(
                {
                    "phase": "admin_action",
                    "workspace_id": self.config.workspace_id,
                    "action": "view_audit_raw_values",
                    "target_request_id": request_id,
                    "available_value_count": sum(1 for detail in details if detail["value_state"] == "active"),
                    "result_code": "OK",
                }
            )
        return {
            "request_id": request_id,
            "timestamp": group["first_timestamp"],
            "completed_at": group["last_timestamp"],
            "endpoint": group["endpoint"] or None,
            "session": _short_identifier(group["session_id"], "Session"),
            "status_code": group["status_code"] or None,
            "termination": group["termination"] or None,
            "upstream_error_event": group["upstream_error_event"] or None,
            "upstream_error_type": group["upstream_error_type"] or None,
            "upstream_error_code": group["upstream_error_code"] or None,
            "upstream_trace_headers": dict(group["upstream_trace_headers"]),
            "parse_errors": group["parse_errors"],
            "raw_values_included": include_raw,
            "details_available": bool(operations),
            "legacy_summary_only": not operations,
            "details_truncated": bool(self.store.audit_operation_omitted_count(request_id, self.config.workspace_id) or group["operation_details_omitted"]),
            "omitted_count": self.store.audit_operation_omitted_count(request_id, self.config.workspace_id) + group["operation_details_omitted"],
            "replacements": replacements,
            "materializations": materializations,
            "materialization_failures": failures,
            "failure_reasons": failure_reasons,
        }

    def protected_values(self, *, state: str = "", kind: str = "", include_raw: bool = False) -> dict[str, Any]:
        now = int(time.time())
        retention = self.store.mapping_retention_policy(self.config.workspace_id)
        records = self.store.list_records(
            workspace_id=self.config.workspace_id,
            state=state or None,
            kind=kind or None,
            limit=1000,
        )
        safe_records = [self._safe_mapping(record, now, include_raw=include_raw) for record in records]
        if include_raw:
            self.audit.log(
                {
                    "phase": "admin_action",
                    "workspace_id": self.config.workspace_id,
                    "action": "view_protected_raw_values",
                    "returned_record_count": len(safe_records),
                    "available_value_count": sum(1 for item in safe_records if item["original"] is not None),
                    "result_code": "OK",
                }
            )
        counts = Counter(item["display_state"] for item in safe_records)
        kind_counts = Counter(item["kind"] for item in safe_records)
        return {
            "records": safe_records,
            "counts": {"total": len(safe_records), "active": counts["active"], "expired": counts["expired"], "revoked": counts["revoked"]},
            "kinds": dict(kind_counts),
            "retention_policy": self._safe_retention_policy(retention),
            "raw_values_included": include_raw,
        }

    def update_mapping_retention_policy(
        self,
        *,
        enabled: bool,
        idle_ttl_seconds: int,
        revision: int,
    ) -> dict[str, Any]:
        policy = self.store.set_mapping_retention_policy(
            workspace_id=self.config.workspace_id,
            enabled=enabled,
            idle_ttl_seconds=idle_ttl_seconds,
            expected_revision=revision,
        )
        self.audit.log(
            {
                "phase": "admin_action",
                "workspace_id": self.config.workspace_id,
                "action": "update_mapping_retention_policy",
                "enabled": policy.enabled,
                "idle_ttl_seconds": policy.idle_ttl_seconds,
                "revision": policy.revision,
                "result_code": "OK",
            }
        )
        return self._safe_retention_policy(policy)

    def _request_groups(self, events: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
        groups: dict[str, dict[str, Any]] = {}
        replacement_actions = {"redact", "pseudonymize", "alias"}
        for event in events:
            request_id = str(event.get("request_id") or "")
            if not request_id:
                continue
            timestamp = int(event.get("timestamp", 0) or 0)
            group = groups.setdefault(
                request_id,
                {
                    "request_id": request_id,
                    "session_id": str(event.get("session_id") or ""),
                    "endpoint": str(event.get("endpoint") or ""),
                    "first_timestamp": timestamp,
                    "last_timestamp": timestamp,
                    "status_code": 0,
                    "termination": "",
                    "upstream_error_event": "",
                    "upstream_error_type": "",
                    "upstream_error_code": "",
                    "upstream_trace_headers": {},
                    "risks": set(),
                    "replacement_count": 0,
                    "materialization_count": 0,
                    "materialization_failed_count": 0,
                    "materialization_failures": Counter(),
                    "parse_errors": 0,
                    "operation_details_omitted": 0,
                    "saw_stream": False,
                    "error_phase": False,
                },
            )
            group["first_timestamp"] = min(group["first_timestamp"], timestamp)
            group["last_timestamp"] = max(group["last_timestamp"], timestamp)
            if event.get("session_id"):
                group["session_id"] = str(event["session_id"])
            if event.get("endpoint"):
                group["endpoint"] = str(event["endpoint"])
            status = int(event.get("status", 0) or 0)
            if status:
                group["status_code"] = status
            if event.get("termination"):
                group["termination"] = str(event["termination"])
            for field in ("upstream_error_event", "upstream_error_type", "upstream_error_code"):
                if event.get(field):
                    group[field] = str(event[field])
            trace_headers = event.get("upstream_trace_headers")
            if isinstance(trace_headers, dict):
                for key, value in trace_headers.items():
                    if isinstance(key, str) and isinstance(value, str):
                        group["upstream_trace_headers"][key] = value
            group["saw_stream"] = bool(group["saw_stream"] or event.get("stream") or event.get("phase") == "response_stream_complete")
            group["parse_errors"] = max(group["parse_errors"], int(event.get("parse_errors", 0) or 0))
            group["operation_details_omitted"] += int(event.get("audit_operations_omitted", 0) or 0)
            group["error_phase"] = bool(group["error_phase"] or "error" in str(event.get("phase") or ""))
            failures = event.get("materialization_failures")
            if isinstance(failures, dict):
                for code, count in failures.items():
                    group["materialization_failures"][str(code)] += int(count or 0)
            detections = event.get("detections") if isinstance(event.get("detections"), list) else []
            for detection in detections:
                if not isinstance(detection, dict):
                    continue
                risk = str(detection.get("risk") or "")
                if risk:
                    group["risks"].add(risk)
                if event.get("phase") == "request" and detection.get("action") in replacement_actions:
                    group["replacement_count"] += 1
                if detection.get("type") == "materialization":
                    if detection.get("action") == "materialize":
                        group["materialization_count"] += 1
                    elif detection.get("action") == "preserve":
                        group["materialization_failed_count"] += 1
                        group["materialization_failures"][str(detection.get("result_code") or "APG_MATERIALIZATION_FAILED")] += 1
            group["materialization_count"] += int(event.get("materialized", event.get("materialized_count", 0)) or 0)
        return groups

    def _audit_operation_detail(self, operation: AuditOperationRecord, *, include_raw: bool) -> dict[str, Any]:
        record = self.store.get(operation.handle_id)
        now = int(time.time())
        if record is None:
            value_state = "unavailable"
        elif record.state == "tombstoned":
            value_state = _tombstone_state(record, now)
        elif _record_expired(record, now):
            value_state = "expired"
        elif record.value is None:
            value_state = "unavailable"
        elif record.session_id != operation.session_id or record.workspace_id != operation.workspace_id:
            value_state = "unavailable"
        else:
            value_state = "active"
        if operation.representation_type == "signed_placeholder":
            representation = self.signer.issue(
                operation.kind,
                operation.handle_id,
                operation.placeholder_session_id or operation.session_id,
                operation.issued_at,
            ) + operation.suffix
        else:
            representation = operation.alias
        if include_raw:
            original = record.value if record is not None and value_state == "active" else None
        else:
            original = "***"
        return {
            "id": f"aop_{operation.id}",
            "request_id": operation.request_id,
            "endpoint": operation.endpoint or None,
            "session": _short_identifier(operation.session_id, "Session"),
            "direction": operation.direction,
            "protected_value_id": self._public_mapping_id(operation.handle_id),
            "kind": operation.kind,
            "subtype": operation.subtype,
            "risk": operation.risk or None,
            "detector": operation.detector or None,
            "action": operation.action,
            "sink": operation.sink or None,
            "result_code": operation.result_code or None,
            "tool_name": operation.tool_name or None,
            "original": original,
            "representation": representation,
            "value_state": value_state,
            "occurrence_count": operation.occurrence_count,
            "timestamp": operation.timestamp,
        }

    def revoke(self, public_id: str) -> dict[str, Any]:
        record = self._resolve_record(public_id)
        self.store.tombstone(record.handle_id)
        self.audit.log(
            {
                "phase": "admin_action",
                "workspace_id": self.config.workspace_id,
                "action": "revoke_protected_value",
                "kind": record.kind,
                "subtype": record.subtype,
                "result_code": "OK",
            }
        )
        return {"ok": True, "id": public_id, "state": "revoked"}

    def purge_expired(self) -> dict[str, Any]:
        count = self.store.tombstone_expired()
        self.audit.log(
            {
                "phase": "admin_action",
                "workspace_id": self.config.workspace_id,
                "action": "purge_expired_protected_values",
                "affected_count": count,
                "result_code": "OK",
            }
        )
        return {"ok": True, "affected_count": count}

    def _safe_mapping(self, record: MappingRecord, now: int, *, include_raw: bool = False) -> dict[str, Any]:
        if record.state == "tombstoned":
            display_state = _tombstone_state(record, now)
        elif _record_expired(record, now):
            display_state = "expired"
        else:
            display_state = "active"
        public_id = self._public_mapping_id(record.handle_id)
        if include_raw:
            original = record.value if display_state == "active" and record.value is not None else None
        else:
            original = "***"
        return {
            "id": public_id,
            "label": f"{record.kind.upper()}-{public_id[-6:].upper()}",
            "kind": record.kind,
            "subtype": record.subtype,
            "scope": record.scope,
            "display_state": display_state,
            "stored_locally": record.value is not None,
            "materialization_class": record.materialization_class,
            "created_at": record.created_at,
            "last_seen_at": record.last_seen_at,
            "expires_at": _mapping_expiry(record),
            "auto_expires": bool(record.idle_expires_at or record.max_expires_at),
            "session": _short_identifier(record.session_id, "Session"),
            "original": original,
        }

    @staticmethod
    def _safe_retention_policy(policy: MappingRetentionPolicy) -> dict[str, Any]:
        return {
            "enabled": policy.enabled,
            "idle_ttl_seconds": policy.idle_ttl_seconds,
            "revision": policy.revision,
            "updated_at": policy.updated_at,
        }

    def _resolve_record(self, public_id: str) -> MappingRecord:
        if not public_id.startswith("pv_") or len(public_id) != 19:
            raise AdminNotFoundError("Protected value not found")
        for record in self.store.list_records(workspace_id=self.config.workspace_id, limit=2000):
            if hmac.compare_digest(self._public_mapping_id(record.handle_id), public_id):
                return record
        raise AdminNotFoundError("Protected value not found")

    def _public_mapping_id(self, handle_id: str) -> str:
        digest = hmac.new(self.config.signing_secret.encode("utf-8"), f"admin:{handle_id}".encode("utf-8"), hashlib.sha256).hexdigest()
        return f"pv_{digest[:16]}"

    def _safe_event(self, event: dict[str, Any]) -> dict[str, Any]:
        scrubbed = scrub_audit_value(event)
        detections = []
        for item in scrubbed.get("detections", []) if isinstance(scrubbed, dict) else []:
            if not isinstance(item, dict):
                continue
            detections.append(
                {
                    key: item.get(key)
                    for key in ("type", "subtype", "detector", "risk", "action", "sink", "result_code")
                    if item.get(key) is not None
                }
            )
        timestamp = int(scrubbed.get("timestamp", 0) or 0)
        event_seed = json.dumps(scrubbed, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        return {
            "id": f"evt_{hashlib.sha256(event_seed.encode()).hexdigest()[:12]}",
            "timestamp": timestamp,
            "request_id": scrubbed.get("request_id"),
            "session": _short_identifier(str(scrubbed.get("session_id", "")), "Session"),
            "endpoint": scrubbed.get("endpoint"),
            "phase": scrubbed.get("phase", "event"),
            "status": scrubbed.get("status"),
            "stream": bool(scrubbed.get("stream", False)),
            "termination": scrubbed.get("termination"),
            "upstream_error_event": scrubbed.get("upstream_error_event"),
            "upstream_error_type": scrubbed.get("upstream_error_type"),
            "upstream_error_code": scrubbed.get("upstream_error_code"),
            "upstream_trace_headers": scrubbed.get("upstream_trace_headers")
            if isinstance(scrubbed.get("upstream_trace_headers"), dict)
            else {},
            "action": scrubbed.get("action"),
            "result_code": scrubbed.get("result_code") or scrubbed.get("code"),
            "detections": detections,
            "detection_count": len(detections),
            "folded_count": int(scrubbed.get("folded", scrubbed.get("folded_count", 0)) or 0),
            "materialized_count": int(scrubbed.get("materialized", scrubbed.get("materialized_count", 0)) or 0),
            "parse_errors": int(scrubbed.get("parse_errors", 0) or 0),
        }

    def _read_events(self, *, max_events: int) -> tuple[list[dict[str, Any]], bool]:
        path = Path(self.config.audit_log_path)
        if not path.exists():
            return [], False
        max_bytes = 16 * 1024 * 1024
        try:
            size = path.stat().st_size
            start = max(0, size - max_bytes)
            with path.open("rb") as stream:
                if start:
                    stream.seek(start - 1)
                    if stream.read(1) != b"\n":
                        stream.readline()
                raw_lines = stream.readlines()
        except OSError:
            return [], False
        truncated = start > 0 or len(raw_lines) > max_events
        lines = [line.decode("utf-8", errors="replace") for line in raw_lines[-max_events:]]
        events: list[dict[str, Any]] = []
        for line in lines:
            try:
                event = json.loads(line)
            except (ValueError, TypeError):
                continue
            if isinstance(event, dict):
                events.append(event)
        return events, truncated


def _short_identifier(value: str, prefix: str) -> str:
    if not value:
        return "-"
    return f"{prefix} {hashlib.sha256(value.encode()).hexdigest()[:6].upper()}"


def _record_expired(record: MappingRecord, now: int) -> bool:
    return record.state == "active" and (
        (record.idle_expires_at > 0 and record.idle_expires_at < now)
        or (record.max_expires_at > 0 and record.max_expires_at < now)
    )


def _mapping_expiry(record: MappingRecord) -> int | None:
    expiries = [value for value in (record.idle_expires_at, record.max_expires_at) if value > 0]
    return min(expiries) if expiries else None


def _tombstone_state(record: MappingRecord, now: int) -> str:
    if record.tombstone_reason == "expired":
        return "expired"
    if record.tombstone_reason == "revoked":
        return "revoked"
    expiry = _mapping_expiry(record)
    return "expired" if expiry is not None and expiry < now else "revoked"


def _highest_risk(risks: set[str]) -> str:
    for risk in ("critical", "high", "medium", "low"):
        if risk in risks:
            return risk
    return "low"
