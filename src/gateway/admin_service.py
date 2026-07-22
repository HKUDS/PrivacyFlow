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
from gateway.mapping_store import MappingRecord, MappingStore


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
        ) + sum(int(event.get("materialized_count", 0) or 0) for event in recent)
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

    def protected_values(self, *, state: str = "", kind: str = "") -> dict[str, Any]:
        now = int(time.time())
        records = self.store.list_records(
            workspace_id=self.config.workspace_id,
            state=state or None,
            kind=kind or None,
            limit=1000,
        )
        safe_records = [self._safe_mapping(record, now) for record in records]
        counts = Counter(item["display_state"] for item in safe_records)
        kind_counts = Counter(item["kind"] for item in safe_records)
        return {
            "records": safe_records,
            "counts": {"total": len(safe_records), "active": counts["active"], "expired": counts["expired"], "revoked": counts["revoked"]},
            "kinds": dict(kind_counts),
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

    def _safe_mapping(self, record: MappingRecord, now: int) -> dict[str, Any]:
        if record.state == "tombstoned":
            display_state = "revoked"
        elif _record_expired(record, now):
            display_state = "expired"
        else:
            display_state = "active"
        public_id = self._public_mapping_id(record.handle_id)
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
            "expires_at": min(record.idle_expires_at, record.max_expires_at),
            "session": _short_identifier(record.session_id, "Session"),
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
            "action": scrubbed.get("action"),
            "result_code": scrubbed.get("result_code") or scrubbed.get("code"),
            "detections": detections,
            "detection_count": len(detections),
            "folded_count": int(scrubbed.get("folded_count", 0) or 0),
            "materialized_count": int(scrubbed.get("materialized_count", 0) or 0),
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
    return record.state == "active" and (record.idle_expires_at < now or record.max_expires_at < now)
