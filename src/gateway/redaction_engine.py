from __future__ import annotations

import codecs
import copy
import json
import re
import time
from collections import Counter
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Any, Callable

from gateway.detector_manager import DetectorManager
from gateway.mapping_store import MappingRecord, MappingStore
from gateway.materialization_engine import MaterializationEngine
from gateway.path_alias_manager import PathAliasManager
from gateway.placeholder_parser import APG_PLACEHOLDER_FORMAT_EXAMPLE, PlaceholderSigner
from gateway.policy_engine import PolicyEngine

PROTOCOL_KEYS = {"model", "tool_call_id", "tool_use_id", "call_id", "item_id", "previous_response_id"}
PROTOCOL_ID_PARENTS = {"tool_calls", "tool_use"}
PROTOCOL_NAME_PARENTS = {"function"}
# Tool-call argument fields are the only sink where APG materializes secrets
# back to raw values on the downlink, so the agent harness receives the real
# credential when executing the tool. All other string fields stay redacted.
TOOL_ARG_FIELDS = {"arguments", "input"}
TOOL_ARG_PARENTS = {"function", "tool_use"}
STREAM_MATERIALIZATION_TAIL = 4096
STREAM_TEXT_BASE_TAIL = 256
STREAM_TEXT_MAX_PENDING = 4096
STREAM_TEXT_MAX_STRICT_BLOCK = 1_048_576
PROTECTED_VALUE = "APG-managed protected value"

_TOKEN_CHAR_RE = re.compile(r"[A-Za-z0-9._~+/=:@-]")
_ENV_ASSIGNMENT_RE = re.compile(
    r"(?:API_KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|PRIVATE_KEY|DATABASE_URL)\s*=",
    re.IGNORECASE,
)
_PEM_END_RE = re.compile(r"-----END (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----")


class StreamProtocolError(ValueError):
    pass


class ToolArgumentsJSONError(StreamProtocolError):
    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


class SSEDecoder:
    """Incrementally decode UTF-8 and split SSE events across byte chunks."""

    def __init__(self) -> None:
        self._decoder = codecs.getincrementaldecoder("utf-8")("strict")
        self._buffer = ""

    def feed(self, chunk: bytes) -> list[str]:
        try:
            self._buffer += self._decoder.decode(chunk, final=False)
        except UnicodeDecodeError as exc:
            raise StreamProtocolError("invalid_utf8") from exc
        return self._drain(complete_only=True)

    def finish(self) -> list[str]:
        try:
            self._buffer += self._decoder.decode(b"", final=True)
        except UnicodeDecodeError as exc:
            raise StreamProtocolError("invalid_utf8") from exc
        events = self._drain(complete_only=False)
        return events

    def _drain(self, *, complete_only: bool) -> list[str]:
        events: list[str] = []
        while True:
            match = re.search(r"\r?\n\r?\n", self._buffer)
            if match is None:
                break
            events.append(self._buffer[: match.start()])
            self._buffer = self._buffer[match.end() :]
        if not complete_only and self._buffer.strip():
            events.append(self._buffer)
            self._buffer = ""
        return events


def sse_data(event: str) -> str | None:
    data_lines: list[str] = []
    for line in event.splitlines():
        if not line.startswith("data:"):
            continue
        value = line[5:]
        if value.startswith(" "):
            value = value[1:]
        data_lines.append(value)
    return "\n".join(data_lines) if data_lines else None


async def iter_sse_data(chunks: AsyncIterator[bytes]) -> AsyncIterator[str]:
    decoder = SSEDecoder()
    async for chunk in chunks:
        for event in decoder.feed(chunk):
            data = sse_data(event)
            if data is not None:
                yield data
    for event in decoder.finish():
        data = sse_data(event)
        if data is not None:
            yield data


@dataclass
class StreamAuditSummary:
    folded: int = 0
    materialized: int = 0
    failures: Counter[str] = field(default_factory=Counter)
    parse_errors: int = 0
    stream_parse_errors: int = 0
    tool_argument_json_errors: Counter[str] = field(default_factory=Counter)
    termination: str = "completed"
    audit_operations: list[dict[str, Any]] = field(default_factory=list)
    audit_operations_omitted: int = 0
    _audit_operation_indexes: dict[tuple[tuple[str, str], ...], int] = field(default_factory=dict, repr=False)

    def record(self, events: list[dict[str, Any]]) -> None:
        for event in events:
            if event.get("action") == "fold":
                self.folded += 1
            elif event.get("action") == "materialize":
                self.materialized += 1
            elif event.get("action") == "preserve":
                self.failures[str(event.get("result_code") or "APG_MATERIALIZATION_FAILED")] += 1
            operation = event.get("_audit_operation")
            if isinstance(operation, dict):
                self._record_audit_operation(operation)

    def _record_audit_operation(self, operation: dict[str, Any]) -> None:
        occurrence_count = max(1, int(operation.get("occurrence_count", 1) or 1))
        key = tuple(sorted((str(k), str(v)) for k, v in operation.items() if k != "occurrence_count"))
        existing_index = self._audit_operation_indexes.get(key)
        if existing_index is not None:
            existing = self.audit_operations[existing_index]
            existing["occurrence_count"] = int(existing.get("occurrence_count", 1)) + occurrence_count
            return
        if len(self.audit_operations) >= 1000:
            self.audit_operations_omitted += occurrence_count
            return
        stored = dict(operation)
        stored["occurrence_count"] = occurrence_count
        self._audit_operation_indexes[key] = len(self.audit_operations)
        self.audit_operations.append(stored)

    def record_protocol_error(self, error: StreamProtocolError) -> None:
        self.parse_errors += 1
        if isinstance(error, ToolArgumentsJSONError):
            self.tool_argument_json_errors[error.reason_code] += 1
        else:
            self.stream_parse_errors += 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "folded": self.folded,
            "materialized": self.materialized,
            "materialization_failures": dict(self.failures),
            "parse_errors": self.parse_errors,
            "stream_parse_errors": self.stream_parse_errors,
            "tool_argument_json_errors": dict(self.tool_argument_json_errors),
            "termination": self.termination,
            "_audit_operations": self.audit_operations,
            "audit_operations_omitted": self.audit_operations_omitted,
        }


@dataclass(frozen=True)
class SSEEvent:
    event: str | None
    data: str

    def encode(self, *, event: str | None = None, data: str | None = None) -> bytes:
        event_name = self.event if event is None else event
        payload = self.data if data is None else data
        lines: list[str] = []
        if event_name:
            lines.append(f"event: {event_name}")
        lines.extend(f"data: {line}" for line in payload.split("\n"))
        return ("\n".join(lines) + "\n\n").encode("utf-8")


def parse_sse_event(raw: str) -> SSEEvent | None:
    event_name: str | None = None
    data_lines: list[str] = []
    for line in raw.splitlines():
        if line.startswith("event:"):
            event_name = line[6:].lstrip() or None
        elif line.startswith("data:"):
            data_lines.append(line[5:].lstrip(" "))
    if not data_lines:
        return None
    return SSEEvent(event_name, "\n".join(data_lines))


async def iter_sse_events(chunks: AsyncIterator[bytes]) -> AsyncIterator[SSEEvent]:
    decoder = SSEDecoder()
    async for chunk in chunks:
        for raw in decoder.feed(chunk):
            event = parse_sse_event(raw)
            if event is not None:
                yield event
    for raw in decoder.finish():
        event = parse_sse_event(raw)
        if event is not None:
            yield event


@dataclass
class _OpenAIToolBuffer:
    choice_index: int
    call_index: int
    call_id: str = ""
    call_type: str = "function"
    name: str = ""
    arguments: str = ""
    flushed: bool = False


@dataclass
class _ResponsesToolBuffer:
    key: tuple[int, str]
    arguments: str = ""
    flushed: bool = False
    template: dict[str, Any] = field(default_factory=dict)


class BalancedStreamScanner:
    """Bounded-delay scanner for one logical assistant text stream."""

    def __init__(self, redactor: "RedactionEngine", session_id: str) -> None:
        self.redactor = redactor
        self.session_id = session_id
        self.core_guard_enabled = redactor.detector_manager.core_guard_enabled
        self.known_secrets = (
            [
                value
                for value in redactor.active_secret_values(session_id)
                if value != APG_PLACEHOLDER_FORMAT_EXAMPLE
            ]
            if self.core_guard_enabled
            else []
        )
        self.path_aliases = redactor.active_path_aliases(session_id)
        longest = max((len(value) for value in self.known_secrets), default=0)
        self.strict = redactor.stream_requires_strict_buffering() or longest > STREAM_TEXT_MAX_PENDING
        self.tail = min(STREAM_TEXT_MAX_PENDING, max(STREAM_TEXT_BASE_TAIL, longest - 1))
        self.pending = ""
        self.discard_mode: str | None = None
        self.suppressed = False

    def feed(self, text: str) -> tuple[str, list[dict[str, Any]]]:
        if not text or self.suppressed:
            return "", []
        if self.discard_mode is not None:
            return self._consume_discard(text)

        self.pending += text
        if self.strict:
            if len(self.pending) > STREAM_TEXT_MAX_STRICT_BLOCK:
                self.pending = ""
                self.suppressed = True
                return PROTECTED_VALUE, [self._fold_event("stream_strict_limit")]
            return "", []

        cut = max(0, len(self.pending) - self.tail)
        detections = self.redactor.detector_manager.scan(self.pending)
        for detection in detections:
            if detection.span_end > cut:
                cut = min(cut, detection.span_start)
        for start, end in self._known_secret_spans(self.pending):
            if end > cut:
                cut = min(cut, start)
        for start, end in self._sequence_spans(self.pending, self.path_aliases):
            if end > cut:
                cut = min(cut, start)

        candidate_start = self._incomplete_candidate_start(self.pending)
        if candidate_start is not None:
            cut = min(cut, candidate_start)

        if cut <= 0:
            if len(self.pending) > STREAM_TEXT_MAX_PENDING:
                return self._overflow_candidate(detections)
            return "", []

        emit = self.pending[:cut]
        self.pending = self.pending[cut:]
        return self._sanitize(emit)

    def flush(self) -> tuple[str, list[dict[str, Any]]]:
        if self.suppressed:
            return "", []
        if self.discard_mode is not None:
            self.discard_mode = None
            self.pending = ""
            return "", []
        text = self.pending
        self.pending = ""
        if not text:
            return "", []
        candidate_start = self._incomplete_candidate_start(text, include_pem=True)
        if candidate_start is None:
            return self._sanitize(text)
        prefix, prefix_events = self._sanitize(text[:candidate_start])
        return prefix + PROTECTED_VALUE, [*prefix_events, self._fold_event("incomplete_stream_candidate")]

    def _sanitize(self, text: str) -> tuple[str, list[dict[str, Any]]]:
        if not text:
            return "", []
        folded = text
        events: list[dict[str, Any]] = []
        for value in self.known_secrets:
            count = folded.count(value)
            if not count:
                continue
            folded = folded.replace(value, PROTECTED_VALUE)
            events.extend(self._fold_event("known_session_secret") for _ in range(count))
        safe, scan_events = self.redactor.scan_local_text(folded, self.session_id)
        return safe, [*events, *scan_events]

    def _known_secret_spans(self, text: str) -> list[tuple[int, int]]:
        return self._sequence_spans(text, self.known_secrets)

    @staticmethod
    def _sequence_spans(text: str, sequences: list[str]) -> list[tuple[int, int]]:
        spans: list[tuple[int, int]] = []
        for value in sequences:
            start = 0
            while True:
                index = text.find(value, start)
                if index < 0:
                    break
                spans.append((index, index + len(value)))
                start = index + max(1, len(value))
        return spans

    def _incomplete_candidate_start(self, text: str, *, include_pem: bool = False) -> int | None:
        starts: list[int] = []
        if self.core_guard_enabled:
            apg_start = _partial_apg_start(text)
            if apg_start is not None:
                starts.append(apg_start)
        secret_start = _partial_sequence_start(text, self.known_secrets)
        if secret_start is not None:
            starts.append(secret_start)
        alias_start = _partial_sequence_start(text, self.path_aliases)
        if alias_start is not None:
            starts.append(alias_start)
        if self.core_guard_enabled:
            pem_start = _unclosed_pem_start(text)
            if pem_start is not None and (include_pem or len(text) - pem_start >= STREAM_TEXT_BASE_TAIL):
                starts.append(pem_start)
        return min(starts) if starts else None

    def _overflow_candidate(self, detections: list[Any]) -> tuple[str, list[dict[str, Any]]]:
        starts = [detection.span_start for detection in detections if detection.span_end == len(self.pending)]
        incomplete = self._incomplete_candidate_start(self.pending, include_pem=True)
        if incomplete is not None:
            starts.append(incomplete)
        start = min(starts) if starts else 0
        prefix, events = self._sanitize(self.pending[:start])
        candidate = self.pending[start:]
        self.discard_mode = _candidate_discard_mode(candidate)
        self.pending = ""
        return prefix + PROTECTED_VALUE, [*events, self._fold_event("stream_pending_limit")]

    def _consume_discard(self, text: str) -> tuple[str, list[dict[str, Any]]]:
        assert self.discard_mode is not None
        if self.discard_mode == "apg":
            end = text.find(">")
            remainder = text[end + 1 :] if end >= 0 else None
        elif self.discard_mode == "pem":
            match = _PEM_END_RE.search(text)
            remainder = text[match.end() :] if match else None
        elif self.discard_mode == "line":
            end = text.find("\n")
            remainder = text[end:] if end >= 0 else None
        else:
            end = next((i for i, char in enumerate(text) if _TOKEN_CHAR_RE.fullmatch(char) is None), -1)
            remainder = text[end:] if end >= 0 else None
        if remainder is None:
            return "", []
        self.discard_mode = None
        return self.feed(remainder)

    @staticmethod
    def _fold_event(subtype: str) -> dict[str, Any]:
        return {
            "type": "secret",
            "subtype": subtype,
            "detector": "stream_guard",
            "risk": "high",
            "action": "fold",
            "safe_preview": "<hidden>",
        }


def _partial_apg_start(text: str) -> int | None:
    marker = "<APG"
    index = text.rfind(marker)
    if index >= 0 and ">" not in text[index:]:
        return index
    for length in range(min(len(text), len(marker) - 1), 0, -1):
        if text.endswith(marker[:length]):
            return len(text) - length
    return None


def _partial_sequence_start(text: str, sequences: list[str]) -> int | None:
    starts: list[int] = []
    for sequence in sequences:
        max_prefix = min(len(text), len(sequence) - 1)
        for length in range(max_prefix, 3, -1):
            if text.endswith(sequence[:length]):
                starts.append(len(text) - length)
                break
    return min(starts) if starts else None


def _unclosed_pem_start(text: str) -> int | None:
    start = text.rfind("-----BEGIN")
    if start < 0 or "PRIVATE KEY-----" not in text[start:]:
        return None
    return start if _PEM_END_RE.search(text, start) is None else None


def _candidate_discard_mode(text: str) -> str:
    if _unclosed_pem_start(text) is not None:
        return "pem"
    if _partial_apg_start(text) is not None:
        return "apg"
    if _ENV_ASSIGNMENT_RE.search(text.rsplit("\n", 1)[-1]):
        return "line"
    return "token"


class RedactionEngine:
    def __init__(
        self,
        detector_manager: DetectorManager,
        mapping_store: MappingStore,
        signer: PlaceholderSigner,
        policy: PolicyEngine,
        workspace_id: str = "default",
    ) -> None:
        self.detector_manager = detector_manager
        self.mapping_store = mapping_store
        self.signer = signer
        self.policy = policy
        self.workspace_id = workspace_id
        self.path_aliases = PathAliasManager()
        self._materializer = MaterializationEngine(mapping_store, signer, policy, workspace_id)

    def sanitize_json(self, data: Any, session_id: str, scope: str = "request", *, alias_paths: bool = True, skip_tool_args: bool = False) -> tuple[Any, list[dict[str, Any]]]:
        events: list[dict[str, Any]] = []
        self.detector_manager.reset_diagnostics()

        def walk(value: Any, path: tuple[str, ...]) -> Any:
            if skip_tool_args and _is_tool_arg_field(path):
                return value
            if isinstance(value, str):
                if self._is_protocol_value(path):
                    return value
                sanitized, ev = self.sanitize_text(value, session_id, scope, alias_paths=alias_paths)
                events.extend(ev)
                return sanitized
            if isinstance(value, list):
                return [walk(v, path + (str(i),)) for i, v in enumerate(value)]
            if isinstance(value, dict):
                out = {}
                for k, v in value.items():
                    if k == "id" and isinstance(v, str) and value.get("type") in {"message", "tool_use"}:
                        out[k] = v
                    elif skip_tool_args and _is_tool_arg_container(value, str(k), path) and isinstance(v, (str, dict, list)):
                        out[k] = v
                    else:
                        out[k] = walk(v, path + (str(k),))
                return out
            return value

        return walk(copy.deepcopy(data), ()), events

    def sanitize_text(
        self,
        text: str,
        session_id: str,
        scope: str = "request",
        *,
        alias_paths: bool = True,
        fold_apg_markers: bool = True,
    ) -> tuple[str, list[dict[str, Any]]]:
        detections = self.detector_manager.scan(text)
        if not detections:
            return text, []
        out: list[str] = []
        cursor = 0
        events: list[dict[str, Any]] = []
        for det in detections:
            out.append(text[cursor:det.span_start])
            raw = text[det.span_start:det.span_end]
            decision = self.policy.decision_for_detection(det)
            if det.type == "pii" and decision.action == "allow":
                # pii_mode == "allow" (development only): pass PII through unchanged.
                out.append(raw)
                cursor = det.span_end
                events.append(
                    {
                        "type": det.type,
                        "subtype": det.subtype,
                        "detector": det.detector_name,
                        "risk": det.risk,
                        "action": "allow",
                        "safe_preview": det.safe_preview,
                    }
                )
                continue
            if det.type == "path" and not alias_paths:
                out.append(raw)
                cursor = det.span_end
                continue
            if fold_apg_markers and (det.type == "APG_MARKER" or det.subtype in {"signed_placeholder", "redaction_marker"}) and scope == "response":
                replacement = "APG-managed protected value"
                events.append(
                    {
                        "type": det.type,
                        "subtype": det.subtype,
                        "detector": det.detector_name,
                        "risk": det.risk,
                        "action": "fold",
                        "safe_preview": det.safe_preview,
                    }
                )
                out.append(replacement)
                cursor = det.span_end
                continue
            if fold_apg_markers and det.type == "secret" and scope == "response":
                replacement = "APG-managed protected value"
                events.append(
                    {
                        "type": det.type,
                        "subtype": det.subtype,
                        "detector": det.detector_name,
                        "risk": det.risk,
                        "action": "fold",
                        "safe_preview": det.safe_preview,
                    }
                )
                out.append(replacement)
                cursor = det.span_end
                continue
            if det.type == "path" and decision.action == "alias":
                alias = self._hierarchical_path_alias(raw, session_id)
                rec = self.mapping_store.upsert_mapping(
                    session_id=session_id,
                    workspace_id=self.workspace_id,
                    scope="workspace",
                    kind="path",
                    subtype=det.subtype,
                    value=raw,
                    store_value=True,
                    materialization_class="path",
                )
                replacement = alias
                representation_type = "path_alias"
                issued_at = 0
            else:
                # In pii_mode == "redact" PII is routed onto the secret track:
                # signed <APG:v1:secret:...> placeholder, mapping kind == "secret",
                # so it can never be materialized back to user-visible text.
                pii_on_secret_track = det.type == "pii" and decision.action == "redact"
                mapping_kind = "secret" if pii_on_secret_track else det.kind
                materialization_class = "secret" if pii_on_secret_track else {
                    "pii": "pii",
                    "path": "path",
                    "secret": "secret",
                }.get(det.type, "none")
                rec = self.mapping_store.upsert_mapping(
                    session_id=session_id,
                    workspace_id=self.workspace_id,
                    scope=scope if det.type != "pii" else "session",
                    kind=mapping_kind,
                    subtype=det.subtype,
                    value=raw,
                    store_value=True,
                    materialization_class=materialization_class,
                )
                placeholder_kind = "pii" if det.type == "pii" and decision.action == "pseudonymize" else mapping_kind
                issued_at = int(time.time())
                replacement = self.signer.issue(placeholder_kind, rec.handle_id, session_id, issued_at)
                representation_type = "signed_placeholder"
            event = {
                "type": det.type,
                "subtype": det.subtype,
                "detector": det.detector_name,
                "risk": det.risk,
                "action": decision.action,
                "safe_preview": det.safe_preview,
            }
            if scope != "response":
                event["_audit_operation"] = {
                    "direction": "replacement",
                    "handle_id": rec.handle_id,
                    "kind": rec.kind,
                    "subtype": rec.subtype,
                    "risk": det.risk,
                    "detector": det.detector_name,
                    "action": decision.action,
                    "sink": "remote_llm",
                    "result_code": "OK",
                    "representation_type": representation_type,
                    "placeholder_session_id": session_id if representation_type == "signed_placeholder" else "",
                    "issued_at": issued_at,
                    "suffix": "",
                    "alias": replacement if representation_type == "path_alias" else "",
                    "tool_name": "",
                }
            events.append(event)
            out.append(replacement)
            cursor = det.span_end
        out.append(text[cursor:])
        return "".join(out), events

    def materialize_local_json_with_events(
        self,
        data: Any,
        session_id: str,
        *,
        tool_name: str = "",
    ) -> tuple[Any, list[dict[str, Any]]]:
        events: list[dict[str, Any]] = []

        def walk(value: Any) -> Any:
            if isinstance(value, str):
                materialized, materialization_events = self.materialize_local_text_with_events(
                    value,
                    session_id,
                    tool_name=tool_name,
                )
                events.extend(materialization_events)
                return materialized
            if isinstance(value, list):
                return [walk(v) for v in value]
            if isinstance(value, dict):
                return {k: walk(v) for k, v in value.items()}
            return value

        return walk(copy.deepcopy(data)), events

    def materialize_local_json(self, data: Any, session_id: str) -> Any:
        materialized, _ = self.materialize_local_json_with_events(data, session_id)
        return materialized

    def materialize_local_text(self, text: str, session_id: str) -> str:
        materialized, _ = self.materialize_local_text_with_events(text, session_id)
        return materialized

    def materialize_local_text_with_events(
        self,
        text: str,
        session_id: str,
        *,
        tool_name: str = "",
    ) -> tuple[str, list[dict[str, Any]]]:
        materialized = text
        events: list[dict[str, Any]] = []
        for alias, value, rec in self._active_path_mapping(session_id):
            if alias in materialized:
                materialized = materialized.replace(alias, value)
                events.append(
                    self._materialization_event(
                        rec,
                        sink="local_tool",
                        action="materialize",
                        result_code="OK",
                        representation_type="path_alias",
                        alias=alias,
                        tool_name=tool_name,
                    )
                )
        for ph in self.signer.parse(materialized):
            result = self._materializer.materialize_placeholder(ph, session_id=session_id, sink_type="local_tool")
            if result.allowed and result.value is not None:
                materialized = materialized.replace(ph.raw + ph.suffix, result.value)
                action = "materialize"
                result_code = "OK"
            else:
                action = "preserve"
                result_code = result.error_code or "APG_MATERIALIZATION_FAILED"
            rec = self.mapping_store.get(ph.handle_id) if self.signer.is_valid(ph) else None
            if rec is None:
                events.append(
                    {
                        "type": "materialization",
                        "kind": ph.kind,
                        "sink": "local_tool",
                        "action": action,
                        "result_code": result_code,
                    }
                )
            else:
                events.append(
                    self._materialization_event(
                        rec,
                        sink="local_tool",
                        action=action,
                        result_code=result_code,
                        representation_type="signed_placeholder",
                        placeholder_session_id=ph.session_id,
                        issued_at=ph.issued_at,
                        suffix=ph.suffix,
                        tool_name=tool_name,
                    )
                )
        return materialized, events

    def active_secret_values(self, session_id: str) -> list[str]:
        values = self.mapping_store.active_values(
            session_id,
            self.workspace_id,
            materialization_class="secret",
        )
        return sorted(set(values), key=len, reverse=True)

    def _active_path_mapping(self, session_id: str) -> list[tuple[str, str, MappingRecord]]:
        pairs = [
            (self._hierarchical_path_alias(str(record.value), session_id), str(record.value), record)
            for record in self.mapping_store.active_records(
                session_id,
                self.workspace_id,
                materialization_class="path",
            )
            if record.value
        ]
        return sorted(set(pairs), key=lambda item: len(item[0]), reverse=True)

    def _hierarchical_path_alias(self, raw: str, session_id: str) -> str:
        active_paths = self.mapping_store.active_path_values(session_id, self.workspace_id)
        for parent in sorted(active_paths, key=len, reverse=True):
            suffix = self.path_aliases.relative_suffix(parent, raw)
            if suffix:
                return self.path_aliases.alias_for(parent) + suffix
        return self.path_aliases.alias_for(raw)

    def active_path_aliases(self, session_id: str) -> list[str]:
        return [alias for alias, _, _ in self._active_path_mapping(session_id)]

    def _materialization_event(
        self,
        record: MappingRecord,
        *,
        sink: str,
        action: str,
        result_code: str,
        representation_type: str,
        placeholder_session_id: str = "",
        issued_at: int = 0,
        suffix: str = "",
        alias: str = "",
        tool_name: str = "",
    ) -> dict[str, Any]:
        return {
            "type": "materialization",
            "kind": record.kind,
            "subtype": record.subtype,
            "sink": sink,
            "action": action,
            "result_code": result_code,
            "_audit_operation": {
                "direction": "materialization" if action == "materialize" else "materialization_failed",
                "handle_id": record.handle_id,
                "kind": record.kind,
                "subtype": record.subtype,
                "risk": "",
                "detector": "",
                "action": action,
                "sink": sink,
                "result_code": result_code,
                "representation_type": representation_type,
                "placeholder_session_id": placeholder_session_id,
                "issued_at": issued_at,
                "suffix": suffix,
                "alias": alias,
                "tool_name": tool_name,
            },
        }

    def stream_requires_strict_buffering(self) -> bool:
        modules = self.detector_manager.hierarchical.flow.modules
        return any(module.enabled and not module.stream_safe for module in modules)

    def materialize_local_tool_args(self, data: Any, session_id: str) -> Any:
        materialized, _ = self.materialize_local_tool_args_with_events(data, session_id)
        return materialized

    def materialize_local_tool_arguments_json_with_events(
        self,
        arguments: str,
        session_id: str,
        *,
        tool_name: str = "",
    ) -> tuple[str, list[dict[str, Any]]]:
        """Validate, materialize, and re-encode one standard tool argument object."""
        if not isinstance(arguments, str):
            raise ToolArgumentsJSONError("invalid_tool_arguments_type")

        source = arguments.strip() or "{}"

        def reject_nonstandard_constant(_: str) -> None:
            raise ValueError("nonstandard JSON constant")

        try:
            parsed = json.loads(source, parse_constant=reject_nonstandard_constant)
        except (ValueError, TypeError) as exc:
            raise ToolArgumentsJSONError("invalid_tool_arguments_json") from exc
        if not isinstance(parsed, dict):
            raise ToolArgumentsJSONError("invalid_tool_arguments_type")

        materialized, events = self.materialize_local_json_with_events(parsed, session_id, tool_name=tool_name)
        return json.dumps(materialized, ensure_ascii=False, allow_nan=False), events

    def materialize_local_tool_args_with_events(self, data: Any, session_id: str) -> tuple[Any, list[dict[str, Any]]]:
        """Materialize placeholders back to raw values, but only inside
        structured tool-call argument fields.

        This is the only path through which an agent harness transparently
        receives the real secret value needed to execute a tool. Every other
        string field (assistant-visible text, reasoning, tool descriptions)
        stays redacted and is handled separately by the response scanner.
        Fail-closed: an invalid/hallucinated placeholder is left as-is rather
        than partially replaced.
        """
        events: list[dict[str, Any]] = []

        def walk(value: Any, path: tuple[str, ...]) -> Any:
            if isinstance(value, list):
                return [walk(v, path + (str(i),)) for i, v in enumerate(value)]
            if isinstance(value, dict):
                out: dict[str, Any] = {}
                for k, v in value.items():
                    child_path = path + (str(k),)
                    if _is_tool_arg_container(value, str(k), path):
                        tool_name = str(value.get("name") or "")
                        if k == "arguments":
                            if not isinstance(v, str):
                                raise ToolArgumentsJSONError("invalid_tool_arguments_type")
                            out[k], argument_events = self.materialize_local_tool_arguments_json_with_events(
                                v,
                                session_id,
                                tool_name=tool_name,
                            )
                            events.extend(argument_events)
                        else:
                            if not isinstance(v, dict):
                                raise ToolArgumentsJSONError("invalid_tool_arguments_type")
                            out[k], argument_events = self.materialize_local_json_with_events(
                                v,
                                session_id,
                                tool_name=tool_name,
                            )
                            events.extend(argument_events)
                    else:
                        out[k] = walk(v, child_path)
                return out
            return value

        return walk(copy.deepcopy(data), ()), events

    def scan_local_json(self, data: Any, session_id: str, *, skip_tool_args: bool = True) -> tuple[Any, list[dict[str, Any]]]:
        events: list[dict[str, Any]] = []
        self.detector_manager.reset_diagnostics()

        def walk(value: Any, path: tuple[str, ...]) -> Any:
            if isinstance(value, str):
                if self._is_protocol_value(path):
                    return value
                safe, string_events = self.scan_local_text(value, session_id)
                events.extend(string_events)
                return safe
            if isinstance(value, list):
                return [walk(item, path + (str(index),)) for index, item in enumerate(value)]
            if isinstance(value, dict):
                out: dict[str, Any] = {}
                for key, item in value.items():
                    child_path = path + (str(key),)
                    if key == "id" and isinstance(item, str) and _is_response_protocol_id(value, path):
                        out[key] = item
                    elif skip_tool_args and _is_tool_arg_container(value, str(key), path):
                        out[key] = item
                    else:
                        out[key] = walk(item, child_path)
                return out
            return value

        return walk(copy.deepcopy(data), ()), events

    async def materialize_local_stream(self, chunks: AsyncIterator[bytes], session_id: str) -> AsyncIterator[bytes]:
        buffer = ""
        async for chunk in chunks:
            buffer += chunk.decode("utf-8", errors="ignore")
            if len(buffer) <= STREAM_MATERIALIZATION_TAIL:
                continue
            emit, buffer = buffer[:-STREAM_MATERIALIZATION_TAIL], buffer[-STREAM_MATERIALIZATION_TAIL:]
            yield self.materialize_local_text(emit, session_id).encode("utf-8")
        if buffer:
            yield self.materialize_local_text(buffer, session_id).encode("utf-8")

    def scan_local_text(self, text: str, session_id: str, *, fold_apg_markers: bool = True) -> tuple[str, list[dict[str, Any]]]:
        """Stream-safe downlink scan.

        Materializes path aliases and PII placeholders back to raw values
        (PII is safe enough to surface to a local viewer), but deliberately
        leaves secret placeholders intact — in the streaming path APG cannot
        reliably route a materialized secret into a structured tool-call
        argument field, so failing closed (keeping the placeholder) is
        safer than handing raw secrets out to an arbitrary stream consumer.

        After PII/path restoration, the text is re-scanned for any raw secret
        the model might echo, and echoing secrets are re-redacted away.
        """
        protected = text
        restorations: dict[str, str] = {}
        events: list[dict[str, Any]] = []

        def protect(raw: str) -> str:
            token = f"APGLOCALRESTORE{len(restorations):08d}"
            restorations[token] = raw
            return token

        for alias, value, rec in self._active_path_mapping(session_id):
            if alias in protected:
                protected = protected.replace(alias, protect(value))
                events.append(
                    self._materialization_event(
                        rec,
                        sink="local_user",
                        action="materialize",
                        result_code="OK",
                        representation_type="path_alias",
                        alias=alias,
                    )
                )
        for ph in self.signer.parse(protected):
            if ph.kind == "secret":
                continue
            result = self._materializer.materialize_placeholder(ph, session_id=session_id, sink_type="local_user")
            if result.allowed and result.value is not None:
                protected = protected.replace(ph.raw + ph.suffix, protect(result.value))
                action = "materialize"
                result_code = "OK"
            else:
                action = "preserve"
                result_code = result.error_code or "APG_MATERIALIZATION_FAILED"
            rec = self.mapping_store.get(ph.handle_id) if result.allowed and self.signer.is_valid(ph) else None
            if rec is None:
                events.append({"type": "materialization", "kind": ph.kind, "sink": "local_user", "action": action, "result_code": result_code})
            else:
                events.append(
                    self._materialization_event(
                        rec,
                        sink="local_user",
                        action=action,
                        result_code=result_code,
                        representation_type="signed_placeholder",
                        issued_at=ph.issued_at,
                        suffix=ph.suffix,
                    )
                )

        safe, scan_events = self.sanitize_text(
            protected,
            session_id,
            scope="response",
            alias_paths=False,
            fold_apg_markers=fold_apg_markers and self.detector_manager.core_guard_enabled,
        )
        for token, value in restorations.items():
            safe = safe.replace(token, value)
        post_events: list[dict[str, Any]] = []
        for ph in self.signer.parse(safe):
            if ph.kind == "secret":
                continue
            result = self._materializer.materialize_placeholder(ph, session_id=session_id, sink_type="local_user")
            if result.allowed and result.value is not None:
                safe = safe.replace(ph.raw + ph.suffix, result.value)
                rec = self.mapping_store.get(ph.handle_id)
                if rec is not None:
                    post_events.append(
                        self._materialization_event(
                            rec,
                            sink="local_user",
                            action="materialize",
                            result_code="OK",
                            representation_type="signed_placeholder",
                            issued_at=ph.issued_at,
                            suffix=ph.suffix,
                        )
                    )
        return safe, [*events, *scan_events, *post_events]

    def _is_protocol_value(self, path: tuple[str, ...]) -> bool:
        if not path:
            return False
        key = path[-1]
        if key in PROTOCOL_KEYS:
            return True
        if key == "name" and any(parent in PROTOCOL_NAME_PARENTS for parent in path[:-1]):
            return True
        return key == "id" and any(parent in PROTOCOL_ID_PARENTS for parent in path[:-1])

    async def scan_local_stream(
        self,
        chunks: AsyncIterator[bytes],
        session_id: str,
        *,
        on_complete: Callable[[dict[str, Any]], None] | None = None,
    ) -> AsyncIterator[bytes]:
        """Statefully scan an OpenAI Chat Completions SSE response."""
        summary = StreamAuditSummary()
        text_scanners: dict[int, BalancedStreamScanner] = {}
        tool_buffers: dict[tuple[int, int], _OpenAIToolBuffer] = {}
        last_base: dict[int, dict[str, Any]] = {}
        finished_choices: set[int] = set()
        normal_end = False

        def payload_bytes(payload: dict[str, Any]) -> bytes:
            return f"data: {json.dumps(payload, ensure_ascii=False)}\n\n".encode("utf-8")

        def choice_payload(base: dict[str, Any], choice_index: int, delta: dict[str, Any], finish_reason: Any = None) -> dict[str, Any]:
            return {
                **base,
                "choices": [
                    {
                        "index": choice_index,
                        "delta": delta,
                        "finish_reason": finish_reason,
                    }
                ],
            }

        def flush_choice(choice_index: int, base: dict[str, Any]) -> list[bytes]:
            if choice_index in finished_choices:
                return []
            output: list[bytes] = []
            scanner = text_scanners.get(choice_index)
            if scanner is not None:
                safe, events = scanner.flush()
                summary.record(events)
                if safe:
                    output.append(payload_bytes(choice_payload(base, choice_index, {"content": safe})))
            prepared_tools: list[tuple[_OpenAIToolBuffer, str]] = []
            materialization_events: list[dict[str, Any]] = []
            for key, tool in sorted(tool_buffers.items()):
                if key[0] != choice_index or tool.flushed:
                    continue
                args, events = self.materialize_local_tool_arguments_json_with_events(
                    tool.arguments,
                    session_id,
                    tool_name=tool.name,
                )
                prepared_tools.append((tool, args))
                materialization_events.extend(events)
            summary.record(materialization_events)
            for tool, args in prepared_tools:
                tool.flushed = True
                output.append(
                    payload_bytes(
                        choice_payload(
                            base,
                            choice_index,
                            {
                                "tool_calls": [
                                    {
                                        "index": tool.call_index,
                                        "function": {"arguments": args},
                                    }
                                ]
                            },
                        )
                    )
                )
            finished_choices.add(choice_index)
            return output

        try:
            async for data in iter_sse_data(chunks):
                if not data:
                    continue
                if data == "[DONE]":
                    for choice_index in sorted(set(text_scanners) | {key[0] for key in tool_buffers}):
                        for item in flush_choice(choice_index, last_base.get(choice_index, {})):
                            yield item
                    normal_end = True
                    yield b"data: [DONE]\n\n"
                    return
                try:
                    payload = json.loads(data)
                except (ValueError, TypeError) as exc:
                    raise StreamProtocolError("invalid_sse_json") from exc
                if not isinstance(payload, dict):
                    raise StreamProtocolError("invalid_sse_payload")

                choices = payload.get("choices")
                if not isinstance(choices, list):
                    safe_payload, events = self.sanitize_json(
                        payload,
                        session_id,
                        scope="response",
                        alias_paths=False,
                    )
                    summary.record(events)
                    yield payload_bytes(safe_payload)
                    continue

                base = {key: value for key, value in payload.items() if key != "choices"}
                for position, choice in enumerate(choices):
                    if not isinstance(choice, dict):
                        raise StreamProtocolError("invalid_choice")
                    choice_index = int(choice.get("index", position))
                    last_base[choice_index] = base
                    delta = choice.get("delta") or {}
                    if not isinstance(delta, dict):
                        raise StreamProtocolError("invalid_delta")
                    safe_delta = {key: value for key, value in delta.items() if key not in {"content", "tool_calls"}}

                    if isinstance(delta.get("content"), str):
                        scanner = text_scanners.get(choice_index)
                        if scanner is None:
                            scanner = BalancedStreamScanner(self, session_id)
                            text_scanners[choice_index] = scanner
                        safe_text, events = scanner.feed(delta["content"])
                        summary.record(events)
                        if safe_text:
                            safe_delta["content"] = safe_text

                    safe_calls: list[dict[str, Any]] = []
                    calls = delta.get("tool_calls")
                    if calls is not None and not isinstance(calls, list):
                        raise StreamProtocolError("invalid_tool_calls")
                    for call_position, call in enumerate(calls or []):
                        if not isinstance(call, dict):
                            raise StreamProtocolError("invalid_tool_call")
                        call_index = int(call.get("index", call_position))
                        key = (choice_index, call_index)
                        tool = tool_buffers.setdefault(key, _OpenAIToolBuffer(choice_index, call_index))
                        metadata: dict[str, Any] = {"index": call_index}
                        if isinstance(call.get("id"), str):
                            tool.call_id += call["id"]
                            metadata["id"] = call["id"]
                        if isinstance(call.get("type"), str):
                            tool.call_type = call["type"]
                            metadata["type"] = call["type"]
                        function = call.get("function") or {}
                        if not isinstance(function, dict):
                            raise StreamProtocolError("invalid_tool_function")
                        safe_function: dict[str, Any] = {}
                        if isinstance(function.get("name"), str):
                            tool.name += function["name"]
                            safe_function["name"] = function["name"]
                        if isinstance(function.get("arguments"), str):
                            tool.arguments += function["arguments"]
                        if safe_function:
                            metadata["function"] = safe_function
                        if len(metadata) > 1:
                            safe_calls.append(metadata)
                    if safe_calls:
                        safe_delta["tool_calls"] = safe_calls

                    finish_reason = choice.get("finish_reason")
                    passthrough = {
                        key: value
                        for key, value in choice.items()
                        if key not in {"index", "delta", "finish_reason"}
                    }
                    if safe_delta or (passthrough and finish_reason is None):
                        partial_choice = choice_payload(base, choice_index, safe_delta)
                        partial_choice["choices"][0].update(passthrough)
                        yield payload_bytes(partial_choice)
                    if finish_reason is not None:
                        for item in flush_choice(choice_index, base):
                            yield item
                        finish_payload = choice_payload(base, choice_index, {}, finish_reason)
                        finish_payload["choices"][0].update(passthrough)
                        yield payload_bytes(finish_payload)

            for choice_index in sorted(set(text_scanners) | {key[0] for key in tool_buffers}):
                for item in flush_choice(choice_index, last_base.get(choice_index, {})):
                    yield item
            normal_end = True
        except StreamProtocolError as exc:
            summary.record_protocol_error(exc)
            summary.termination = "protocol_error"
            tool_error = isinstance(exc, ToolArgumentsJSONError)
            error = {
                "error": {
                    "code": "APG_TOOL_ARGUMENTS_INVALID" if tool_error else "APG_STREAM_PARSE_ERROR",
                    "message": (
                        "The upstream tool-call arguments were not valid JSON."
                        if tool_error
                        else "The upstream stream could not be safely parsed."
                    ),
                    "retryable": True,
                }
            }
            yield payload_bytes(error)
            yield b"data: [DONE]\n\n"
        finally:
            if not normal_end and summary.termination == "completed":
                summary.termination = "client_disconnected"
            if on_complete is not None:
                on_complete(summary.to_dict())

    async def scan_responses_stream(
        self,
        chunks: AsyncIterator[bytes],
        session_id: str,
        *,
        on_complete: Callable[[dict[str, Any]], None] | None = None,
    ) -> AsyncIterator[bytes]:
        """Statefully scan an OpenAI Responses API SSE stream."""
        summary = StreamAuditSummary()
        text_scanners: dict[tuple[str, int, int, str], BalancedStreamScanner] = {}
        text_templates: dict[tuple[str, int, int, str], tuple[SSEEvent, dict[str, Any]]] = {}
        tool_buffers: dict[tuple[int, str], _ResponsesToolBuffer] = {}
        normal_end = False

        text_delta_fields = {
            "response.output_text.delta": "delta",
            "response.reasoning_summary_text.delta": "delta",
            "response.refusal.delta": "delta",
        }
        text_done_fields = {
            "response.output_text.done": "text",
            "response.reasoning_summary_text.done": "text",
            "response.refusal.done": "refusal",
        }
        def event_bytes(event: SSEEvent, payload: dict[str, Any], *, event_name: str | None = None) -> bytes:
            name = event_name or event.event or str(payload.get("type") or "message")
            return event.encode(event=name, data=json.dumps(payload, ensure_ascii=False))

        def text_key(event_type: str, payload: dict[str, Any]) -> tuple[str, int, int, str]:
            family = event_type.removesuffix(".delta").removesuffix(".done")
            return (
                family,
                int(payload.get("output_index") or 0),
                int(payload.get("content_index") or 0),
                str(payload.get("item_id") or ""),
            )

        def tool_key(payload: dict[str, Any]) -> tuple[int, str]:
            return (int(payload.get("output_index") or 0), str(payload.get("item_id") or payload.get("call_id") or ""))

        def flush_text(key: tuple[str, int, int, str]) -> list[bytes]:
            scanner = text_scanners.pop(key, None)
            template = text_templates.pop(key, None)
            if scanner is None or template is None:
                return []
            safe, events = scanner.flush()
            summary.record(events)
            if not safe:
                return []
            event, payload = template
            emitted = dict(payload)
            emitted["delta"] = safe
            return [event_bytes(event, emitted)]

        def flush_tool(key: tuple[int, str]) -> list[bytes]:
            tool = tool_buffers.get(key)
            if tool is None or tool.flushed:
                return []
            tool.flushed = True
            arguments, events = self.materialize_local_text_with_events(tool.arguments, session_id)
            summary.record(events)
            tool.arguments = arguments
            if not arguments:
                return []
            template = dict(tool.template)
            template["type"] = "response.function_call_arguments.delta"
            template["delta"] = arguments
            event = SSEEvent("response.function_call_arguments.delta", "")
            return [event_bytes(event, template)]

        def scan_complete_payload(payload: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
            materialized, materialization_events = self.materialize_local_tool_args_with_events(payload, session_id)
            safe, scan_events = self.scan_local_json(materialized, session_id, skip_tool_args=True)
            return safe, [*materialization_events, *scan_events]

        try:
            async for event in iter_sse_events(chunks):
                if event.data == "[DONE]":
                    for key in list(text_scanners):
                        for item in flush_text(key):
                            yield item
                    for key in list(tool_buffers):
                        for item in flush_tool(key):
                            yield item
                    normal_end = True
                    yield event.encode()
                    return
                try:
                    payload = json.loads(event.data)
                except (ValueError, TypeError) as exc:
                    raise StreamProtocolError("invalid_responses_sse_json") from exc
                if not isinstance(payload, dict):
                    raise StreamProtocolError("invalid_responses_sse_payload")
                event_type = str(payload.get("type") or event.event or "")

                if event_type in text_delta_fields:
                    field_name = text_delta_fields[event_type]
                    fragment = payload.get(field_name)
                    if not isinstance(fragment, str):
                        raise StreamProtocolError("invalid_responses_text_delta")
                    key = text_key(event_type, payload)
                    scanner = text_scanners.setdefault(key, BalancedStreamScanner(self, session_id))
                    template = {key_name: value for key_name, value in payload.items() if key_name != field_name}
                    template["type"] = event_type
                    text_templates[key] = (event, template)
                    safe, events = scanner.feed(fragment)
                    summary.record(events)
                    if safe:
                        emitted = dict(template)
                        emitted[field_name] = safe
                        yield event_bytes(event, emitted)
                    continue

                if event_type in text_done_fields:
                    key = text_key(event_type, payload)
                    for item in flush_text(key):
                        yield item
                    field_name = text_done_fields[event_type]
                    done_text = payload.get(field_name)
                    safe_payload = dict(payload)
                    if isinstance(done_text, str):
                        safe_text, events = self.scan_local_text(done_text, session_id)
                        summary.record(events)
                        safe_payload[field_name] = safe_text
                    yield event_bytes(event, safe_payload)
                    continue

                if event_type == "response.function_call_arguments.delta":
                    fragment = payload.get("delta")
                    if not isinstance(fragment, str):
                        raise StreamProtocolError("invalid_responses_tool_delta")
                    key = tool_key(payload)
                    tool = tool_buffers.setdefault(key, _ResponsesToolBuffer(key))
                    tool.arguments += fragment
                    tool.template = {key_name: value for key_name, value in payload.items() if key_name != "delta"}
                    continue

                if event_type == "response.function_call_arguments.done":
                    key = tool_key(payload)
                    tool = tool_buffers.setdefault(key, _ResponsesToolBuffer(key))
                    full_arguments = payload.get("arguments")
                    if isinstance(full_arguments, str):
                        tool.arguments = full_arguments
                    tool.template = {key_name: value for key_name, value in payload.items() if key_name != "arguments"}
                    for item in flush_tool(key):
                        yield item
                    safe_arguments, events = self.materialize_local_text_with_events(tool.arguments, session_id)
                    summary.record(events)
                    safe_payload = dict(payload)
                    safe_payload["arguments"] = safe_arguments
                    yield event_bytes(event, safe_payload)
                    continue

                if event_type in {"response.output_item.done", "response.completed"}:
                    if event_type == "response.completed":
                        for key in list(text_scanners):
                            for item in flush_text(key):
                                yield item
                        for key in list(tool_buffers):
                            for item in flush_tool(key):
                                yield item
                    safe_payload, events = scan_complete_payload(payload)
                    summary.record(events)
                    yield event_bytes(event, safe_payload)
                    if event_type == "response.completed":
                        normal_end = True
                    continue

                if event_type.endswith(".delta") and isinstance(payload.get("delta"), str):
                    raise StreamProtocolError("unknown_responses_text_delta")

                safe_payload, events = self.scan_local_json(payload, session_id, skip_tool_args=True)
                summary.record(events)
                yield event_bytes(event, safe_payload)

            for key in list(text_scanners):
                for item in flush_text(key):
                    yield item
            for key in list(tool_buffers):
                for item in flush_tool(key):
                    yield item
            normal_end = True
        except StreamProtocolError as exc:
            summary.record_protocol_error(exc)
            summary.termination = "protocol_error"
            error = {
                "type": "error",
                "code": "APG_STREAM_PARSE_ERROR",
                "message": "The upstream Responses stream could not be safely parsed.",
                "retryable": True,
            }
            yield SSEEvent("error", "").encode(event="error", data=json.dumps(error))
        finally:
            if not normal_end and summary.termination == "completed":
                summary.termination = "client_disconnected"
            if on_complete is not None:
                on_complete(summary.to_dict())


def _is_tool_arg_field(path: tuple[str, ...]) -> bool:
    """True when ``path`` points at a tool-call arguments/input field that the
    response scanner has already materialized and must NOT re-redact."""
    if not path:
        return False
    key = path[-1]
    if key not in TOOL_ARG_FIELDS:
        return False
    return any(parent in TOOL_ARG_PARENTS for parent in path[:-1])


def _is_tool_arg_container(container: dict[str, Any], key: str, path: tuple[str, ...]) -> bool:
    if key not in TOOL_ARG_FIELDS:
        return False
    if container.get("type") == "function_call" and key == "arguments":
        return True
    if container.get("type") == "tool_use" and key == "input":
        return True
    return any(parent in TOOL_ARG_PARENTS for parent in path)


def _is_response_protocol_id(container: dict[str, Any], path: tuple[str, ...]) -> bool:
    if container.get("object") == "response":
        return True
    if container.get("type") in {
        "message",
        "tool_use",
        "function_call",
        "output_text",
        "reasoning",
        "reasoning_summary",
        "refusal",
    }:
        return True
    return any(parent in {"response", "output", "content"} for parent in path)
