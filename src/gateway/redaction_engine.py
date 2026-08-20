from __future__ import annotations

import codecs
import copy
import json
import re
import secrets
from collections import Counter
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Any, Callable

from gateway.detector_manager import DetectorManager
from gateway.mapping_store import MappingRecord, MappingStore
from gateway.materialization_engine import MaterializationEngine
from gateway.models import Detection
from gateway.path_alias_manager import PathAliasManager
from gateway.placeholder_parser import PLACEHOLDER_RE, ParsedPlaceholder, PlaceholderSigner
from gateway.policy_engine import PolicyEngine

PROTOCOL_KEYS = {
    "approval_request_id",
    "call_id",
    "container_id",
    "file_id",
    "item_id",
    "model",
    "previous_response_id",
    "response_id",
    "signature",
    "tool_call_id",
    "tool_use_id",
    # Discriminator fields are structural enum values in every supported
    # protocol (e.g. `input_text`, `input_image`, `function`, `message`,
    # JSON-schema `object`/`string`). A detector or known-value merge must
    # never replace part of one: mangling it corrupts the wire format and
    # upstream rejects the request.
    "type",
}
PROTOCOL_ID_PARENTS = {"file_ids", "tool_calls", "tool_use", "vector_store_ids"}
PROTOCOL_NAME_PARENTS = {"function"}
CONTENT_FIELD_NAMES = {"content", "input", "instructions", "prompt", "system", "text"}
OPAQUE_MULTIMODAL_FIELDS = {"file_data", "file_url", "image_url", "partial_image_b64"}
OPAQUE_MULTIMODAL_TYPES = {
    "audio",
    "computer_screenshot",
    "image",
    "image_generation_call",
    "input_audio",
    "input_file",
    "input_image",
    "output_audio",
}
# Structured tool-call arguments and user-visible local response text are the
# two downlink sinks where exact, valid APG placeholders may be materialized.
# Raw values are never materialized into upstream/model-visible traffic.
TOOL_ARG_FIELDS = {"arguments", "input"}
TOOL_ARG_PARENTS = {"custom_tool_call", "function", "tool_use"}
STREAM_TEXT_BASE_TAIL = 256
STREAM_TEXT_MAX_PENDING = 4096
STREAM_TEXT_MAX_STRICT_BLOCK = 1_048_576
PROTECTED_VALUE = "PrivacyFlow-managed protected value"

_TOKEN_CHAR_RE = re.compile(r"[A-Za-z0-9._~+/=:@-]")
_ENV_ASSIGNMENT_RE = re.compile(
    r"(?:API_KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|PRIVATE_KEY|DATABASE_URL)\s*=",
    re.IGNORECASE,
)
_PEM_END_RE = re.compile(r"-----END (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----")
_AUDIT_IDENTIFIER_RE = re.compile(r"[A-Za-z0-9._:@/-]{1,128}")

PathMapping = tuple[tuple[str, str, MappingRecord], ...]

# Known-value re-protection only makes sense for values distinctive enough to
# be missing from ordinary text. A short value (e.g. a 1-character `x` from a
# `API_KEY=x` fixture) appears inside half the words of any real request;
# re-protecting it replaces it everywhere, mangling code, identifiers, and
# even protocol strings. First-pass detection at the assignment site still
# protects such values; only the whole-request merge is skipped.
#
# Generic short values stay out of the whole-request merge; only full,
# sufficiently long protected values are re-protected across a request.
MIN_KNOWN_VALUE_LEN = 12


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
    namespace: str = "APG"
    folded: int = 0
    materialized: int = 0
    failures: Counter[str] = field(default_factory=Counter)
    parse_errors: int = 0
    stream_parse_errors: int = 0
    tool_argument_json_errors: Counter[str] = field(default_factory=Counter)
    stream_parse_error_codes: list[str] = field(default_factory=list)
    termination: str = "completed"
    upstream_error_event: str | None = None
    upstream_error_type: str | None = None
    upstream_error_code: str | None = None
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
                self.failures[str(event.get("result_code") or f"{self.namespace}_MATERIALIZATION_FAILED")] += 1
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
        code = error.reason_code if isinstance(error, ToolArgumentsJSONError) else str(error)
        if code not in self.stream_parse_error_codes:
            self.stream_parse_error_codes.append(code)
        if isinstance(error, ToolArgumentsJSONError):
            self.tool_argument_json_errors[error.reason_code] += 1
        else:
            self.stream_parse_errors += 1

    def record_upstream_error(self, event_type: str, payload: dict[str, Any]) -> None:
        response = payload.get("response")
        response_error = response.get("error") if isinstance(response, dict) else None
        top_level_error = payload.get("error")
        error = response_error if isinstance(response_error, dict) else top_level_error
        error = error if isinstance(error, dict) else {}
        self.termination = "failed"
        self.upstream_error_event = self._safe_identifier(event_type, "error")
        self.upstream_error_type = self._safe_identifier(
            error.get("type") or payload.get("error_type") or event_type,
            "unspecified",
        )
        self.upstream_error_code = self._safe_identifier(
            error.get("code") or payload.get("code"),
            "unspecified",
        )

    @staticmethod
    def _safe_identifier(value: Any, default: str) -> str:
        normalized = str(value or "").strip()
        return normalized if _AUDIT_IDENTIFIER_RE.fullmatch(normalized) else default

    def to_dict(self) -> dict[str, Any]:
        return {
            "folded": self.folded,
            "materialized": self.materialized,
            "materialization_failures": dict(self.failures),
            "parse_errors": self.parse_errors,
            "stream_parse_errors": self.stream_parse_errors,
            "stream_parse_error_codes": list(self.stream_parse_error_codes),
            "tool_argument_json_errors": dict(self.tool_argument_json_errors),
            "termination": self.termination,
            "upstream_error_event": self.upstream_error_event,
            "upstream_error_type": self.upstream_error_type,
            "upstream_error_code": self.upstream_error_code,
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

    def __init__(
        self,
        redactor: "RedactionEngine",
        session_id: str,
        *,
        path_mapping: PathMapping | None = None,
    ) -> None:
        self.redactor = redactor
        self.session_id = session_id
        self.path_mapping = path_mapping if path_mapping is not None else redactor._active_path_mapping(session_id)
        self.path_aliases = [alias for alias, _, _ in self.path_mapping]
        self.strict = redactor.stream_requires_strict_buffering()
        self.tail = STREAM_TEXT_BASE_TAIL
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
                return self.redactor.protected_value, [self._fold_event("stream_strict_limit")]
            return "", []

        cut = max(0, len(self.pending) - self.tail)
        detections = self.redactor.detector_manager.scan(self.pending)
        for detection in detections:
            if detection.span_end > cut:
                cut = min(cut, detection.span_start)
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
        return prefix + self.redactor.protected_value, [*prefix_events, self._fold_event("incomplete_stream_candidate")]

    def _sanitize(self, text: str) -> tuple[str, list[dict[str, Any]]]:
        if not text:
            return "", []
        return self.redactor.scan_local_text(text, self.session_id, path_mapping=self.path_mapping)

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
        pf_start = _partial_pf_start(text)
        if pf_start is not None:
            starts.append(pf_start)
        alias_start = _partial_sequence_start(text, self.path_aliases)
        if alias_start is not None:
            starts.append(alias_start)
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
        return prefix + self.redactor.protected_value, [*events, self._fold_event("stream_pending_limit")]

    def _consume_discard(self, text: str) -> tuple[str, list[dict[str, Any]]]:
        if self.discard_mode is None:
            raise RuntimeError("_consume_discard called without discard_mode set")
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


def _partial_pf_start(text: str) -> int | None:
    starts: list[int] = []
    for marker in ("<PF", "<APG"):
        index = text.rfind(marker)
        if index >= 0 and ">" not in text[index:]:
            starts.append(index)
        for length in range(min(len(text), len(marker) - 1), 0, -1):
            if text.endswith(marker[:length]):
                starts.append(len(text) - length)
                break
    if starts:
        return min(starts)
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
    if _partial_pf_start(text) is not None:
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
        self.namespace = getattr(signer, "namespace", getattr(mapping_store, "namespace", "APG"))
        self.protected_value = "PrivacyFlow-managed protected value" if self.namespace == "PF" else "APG-managed protected value"
        self.policy = policy
        self.workspace_id = workspace_id
        self.path_aliases = PathAliasManager()
        self._materializer = MaterializationEngine(mapping_store, signer, policy, workspace_id)
        # Cache of active known-value records per (session, workspace),
        # invalidated by the store's write generation. Without this, large
        # requests (e.g. Codex's ~400 KB bodies with hundreds of active
        # mappings) re-query the store for every string field, adding seconds.
        self._known_records_cache: dict[tuple[str, str], tuple[int, list[MappingRecord]]] = {}
        # Cache of the hierarchical path mapping per (session, workspace),
        # invalidated the same way. Building it is O(active_paths^2); on a
        # response stream with hundreds of accumulated paths that is the single
        # largest fixed cost, and it is recomputed on every call when mappings
        # have not changed.
        self._path_mapping_cache: dict[tuple[str, str], tuple[int, PathMapping]] = {}
        # Which mapping kinds the active detector configuration can produce,
        # cached per DetectorManager instance (the server swaps it on config
        # activate). The known-value merge re-protects only these kinds so a
        # credentials-only config no longer keeps re-aliasing paths that were
        # mapped by an earlier path-inclusive configuration.
        self._supported_kinds_cache: tuple[DetectorManager, frozenset[str]] | None = None

    def _code(self, suffix: str) -> str:
        return f"{self.namespace}_{suffix}"

    def _normalize_code(self, code: str | None) -> str | None:
        if not isinstance(code, str):
            return code
        for other in ("PF", "APG"):
            if other != self.namespace and code.startswith(f"{other}_"):
                return f"{self.namespace}_{code[len(other) + 1:]}"
        return code

    def _marker_type(self) -> str:
        return "PF_MARKER" if self.namespace == "PF" else "APG_MARKER"

    def sanitize_json(self, data: Any, session_id: str, scope: str = "request", *, alias_paths: bool = True, skip_tool_args: bool = False) -> tuple[Any, list[dict[str, Any]]]:
        events: list[dict[str, Any]] = []
        self.detector_manager.reset_diagnostics()

        def walk(value: Any, path: tuple[str, ...]) -> Any:
            if skip_tool_args and _is_tool_arg_field(path):
                return value
            if isinstance(value, str):
                if self._is_protocol_value(path):
                    return value
                sanitized, ev = self.sanitize_text(
                    value,
                    session_id,
                    scope,
                    alias_paths=alias_paths,
                    source_kind=_source_kind_for_json_path(path, scope),
                )
                events.extend(ev)
                return sanitized
            if isinstance(value, list):
                return [walk(v, path + (str(i),)) for i, v in enumerate(value)]
            if isinstance(value, dict):
                if _is_opaque_multimodal_container(value):
                    return copy.deepcopy(value)
                out = {}
                for k, v in value.items():
                    if k in OPAQUE_MULTIMODAL_FIELDS:
                        out[k] = v
                    elif k == "id" and isinstance(v, str) and _is_response_protocol_id(value, path):
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
        source_kind: str = "text",
    ) -> tuple[str, list[dict[str, Any]]]:
        marker_events: list[dict[str, Any]] = []
        protected_marker_spans: list[tuple[int, int]] = []
        if scope != "response":
            text, marker_events, protected_marker_spans = self._canonicalize_request_placeholders(text, session_id)
        detections = self.detector_manager.scan(text, kind=source_kind)
        if protected_marker_spans:
            detections = [
                detection
                for detection in detections
                if not any(
                    detection.span_start < end and start < detection.span_end
                    for start, end in protected_marker_spans
                )
            ]
        if scope != "response":
            detections = self._merge_known_value_detections(text, detections, session_id)
        if not detections:
            return text, marker_events
        out: list[str] = []
        cursor = 0
        events: list[dict[str, Any]] = list(marker_events)
        active_paths_for_aliasing: list[str] | None = None
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
            if fold_apg_markers and (det.type in {"PF_MARKER", "APG_MARKER"} or det.subtype in {"signed_placeholder", "redaction_marker"}):
                replacement = self.protected_value
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
                replacement = self.protected_value
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
                if active_paths_for_aliasing is None:
                    active_paths_for_aliasing = self.mapping_store.active_path_values(
                        session_id,
                        self.workspace_id,
                    )
                alias = self._hierarchical_path_alias(raw, active_paths_for_aliasing)
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
                if raw not in active_paths_for_aliasing:
                    active_paths_for_aliasing.append(raw)
                replacement = alias
                representation_type = "path_alias"
                issued_at = 0
            else:
                # In pii_mode == "redact" PII is routed onto the secret track:
                # signed <APG:v1:secret:...> placeholder, mapping kind == "secret",
                # so it follows secret-grade storage and sink validation.
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
                replacement = self._issue_placeholder(placeholder_kind, rec)
                parsed = self.signer.parse(replacement)
                issued_at = parsed[0].issued_at if parsed else rec.created_at
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

    def _known_value_records(self, session_id: str) -> list[MappingRecord]:
        """Active records for the session, cached until the store changes.

        `_merge_known_value_detections` runs once per string field, and large
        agent requests contain thousands of fields. Re-querying the mapping
        store for every field is O(fields x rows); a single query cached across
        the request (and across requests until a mapping is inserted,
        tombstoned, or expired) keeps it O(rows + fields).
        """
        key = (session_id, self.workspace_id)
        generation = self.mapping_store.write_generation
        cached = self._known_records_cache.get(key)
        if cached is not None and cached[0] == generation:
            return cached[1]
        records = self.mapping_store.active_records(session_id, self.workspace_id)
        if len(self._known_records_cache) >= 32:
            # Bound memory by dropping the whole cache; a cold start is one
            # extra query per session, far cheaper than the unbounded growth.
            self._known_records_cache = {}
        self._known_records_cache[key] = (generation, records)
        return records

    def _supported_kinds(self) -> frozenset[str]:
        """Kinds the active detector configuration can produce.

        Derived from the detector flow modules: `path_detector` supports paths,
        `entropy_context` supports secrets, `local_model` supports PII, and
        `regex_rules` supports the kinds of its rule types. The known-value
        merge uses this so it only re-protects values the current configuration
        would actually detect, instead of every accumulated mapping from older
        configurations.
        """
        cached = self._supported_kinds_cache
        if cached is not None and cached[0] is self.detector_manager:
            return cached[1]
        kinds: set[str] = set()
        modules = getattr(self.detector_manager.hierarchical.flow, "modules", ())
        for module in modules:
            if not getattr(module, "enabled", True):
                continue
            mtype = getattr(module, "type", "")
            if mtype == "path_detector":
                kinds.add("path")
            elif mtype == "entropy_context":
                kinds.add("secret")
            elif mtype in {"local_model", "hf_token_classification", "gliner"}:
                if self.policy.pii_mode == "redact":
                    # Redacted PII is deliberately stored on the secret track.
                    kinds.add("secret")
                elif self.policy.pii_mode == "pseudonymize":
                    kinds.add("pii")
            elif mtype in {"regex_rules", "rule_validator"}:
                detector = getattr(module, "detector", None)
                for rule in getattr(detector, "rules", ()):
                    if not getattr(rule, "enabled", True):
                        continue
                    rule_type = getattr(rule, "type", "")
                    if rule_type in {"MACHINE_SECRET", "PF_MARKER", "APG_MARKER", "UNKNOWN_SECRET_CANDIDATE"}:
                        kinds.add("secret")
                    elif rule_type == "PII":
                        if self.policy.pii_mode == "redact":
                            kinds.add("secret")
                        elif self.policy.pii_mode == "pseudonymize":
                            kinds.add("pii")
                    elif rule_type in {"LOCAL_CONTEXT", "CREDENTIAL_FILE"}:
                        kinds.add("path")
        result = frozenset(kinds)
        self._supported_kinds_cache = (self.detector_manager, result)
        return result

    def _issue_placeholder(self, kind: str, record: MappingRecord) -> str:
        """Derive the canonical placeholder from durable mapping fields."""
        return self.signer.issue(kind, record.handle_id, record.session_id, record.created_at)

    def _canonicalize_request_placeholders(
        self,
        text: str,
        session_id: str,
    ) -> tuple[str, list[dict[str, Any]], list[tuple[int, int]]]:
        """Preserve valid handles and fold invalid ones before generic detection.

        A signed placeholder is a protocol object, not another secret value.
        Passing it through generic detection used to wrap valid handles in a
        second mapping. Canonical handles use the mapping creation timestamp,
        which keeps their representation stable across process restarts.
        """
        matches = list(PLACEHOLDER_RE.finditer(text))
        if not matches:
            return text, [], []
        out: list[str] = []
        events: list[dict[str, Any]] = []
        protected_spans: list[tuple[int, int]] = []
        cursor = 0
        output_length = 0
        for match in matches:
            prefix = text[cursor:match.start()]
            out.append(prefix)
            output_length += len(prefix)
            placeholder = ParsedPlaceholder(
                raw=match.group(0),
                kind=match.group("kind"),
                handle_id=match.group("handle"),
                session_id=match.group("session"),
                issued_at=int(match.group("issued")),
                mac=match.group("mac"),
            )
            record: MappingRecord | None = None
            result_code = self._code("PLACEHOLDER_INVALID_MAC")
            valid = self.signer.is_valid(placeholder)
            if valid:
                valid, record, result_code = self.mapping_store.validate_active(
                    placeholder.handle_id,
                    session_id,
                    self.workspace_id,
                )
                if valid and placeholder.session_id != session_id:
                    valid = False
                    result_code = self._code("PLACEHOLDER_SCOPE_MISMATCH")
                if valid and record is not None and placeholder.kind != record.kind:
                    valid = False
                    result_code = self._code("PLACEHOLDER_POLICY_MISMATCH")
            if valid and record is not None:
                replacement = self._issue_placeholder(placeholder.kind, record)
                start = output_length
                out.append(replacement)
                output_length += len(replacement)
                protected_spans.append((start, output_length))
                action = "preserve" if replacement == placeholder.raw else "canonicalize"
                result_code = "OK"
            else:
                replacement = self.protected_value
                out.append(replacement)
                output_length += len(replacement)
                action = "fold"
            events.append(
                {
                    "type": self._marker_type(),
                    "subtype": "signed_placeholder",
                    "detector": "placeholder_parser",
                    "risk": "high",
                    "action": action,
                    "result_code": result_code,
                    "safe_preview": f"<{self.namespace}:...>",
                }
            )
            cursor = match.end()
        out.append(text[cursor:])
        return "".join(out), events, protected_spans

    def _merge_known_value_detections(
        self,
        text: str,
        detections: list[Detection],
        session_id: str,
    ) -> list[Detection]:
        """Re-protect active values even when their surrounding syntax changed.

        A value can legitimately be materialized into a local tool result and
        then be included by an agent in a later model request. The second
        occurrence may no longer have the assignment/header syntax that first
        identified it, so detector-only rescanning is insufficient. Active
        mappings provide session-scoped taint tracking for those exact values.
        """
        known: list[tuple[Detection, bool]] = [(detection, False) for detection in detections]
        seen: set[tuple[int, int, str]] = set()
        supported_kinds = self._supported_kinds()
        for record in self._known_value_records(session_id):
            if record.kind not in supported_kinds:
                # The current configuration does not detect this kind (e.g. a
                # credentials-only config no longer aliases paths mapped by an
                # earlier path-inclusive configuration); do not re-protect it.
                continue
            value = record.value or ""
            if not value or len(value) < MIN_KNOWN_VALUE_LEN or len(value) > len(text):
                # A needle longer than the field cannot appear in it; skipping
                # avoids a wasted find() for every such record. Most fields are
                # short while secrets and paths are long, so this prunes the
                # bulk of the per-field value scan.
                continue
            start = text.find(value)
            while start >= 0:
                end = start + len(value)
                key = (start, end, record.handle_id)
                if key not in seen:
                    seen.add(key)
                    det_type = record.kind if record.kind in {"secret", "pii", "path"} else "secret"
                    known.append(
                        (
                            Detection(
                                span_start=start,
                                span_end=end,
                                type=det_type,
                                subtype=record.subtype,
                                risk="high" if det_type == "secret" else "medium",
                                detector_name="known_value",
                                suggested_action="alias" if det_type == "path" else "redact",
                                safe_preview="",
                            ),
                            True,
                        )
                    )
                start = text.find(value, start + 1)

        # Prefer the widest match at a position. On an exact tie, reusing a
        # known mapping is more stable than generating a detector-specific one.
        selected: list[Detection] = []
        cursor = 0
        for detection, _is_known in sorted(
            known,
            key=lambda item: (
                item[0].span_start,
                -(item[0].span_end - item[0].span_start),
                not item[1],
            ),
        ):
            if detection.span_start < cursor:
                continue
            selected.append(detection)
            cursor = detection.span_end
        return selected

    def materialize_local_json_with_events(
        self,
        data: Any,
        session_id: str,
        *,
        tool_name: str = "",
        path_mapping: PathMapping | None = None,
    ) -> tuple[Any, list[dict[str, Any]]]:
        events: list[dict[str, Any]] = []
        mapping = path_mapping if path_mapping is not None else self._active_path_mapping(session_id)

        def walk(value: Any) -> Any:
            if isinstance(value, str):
                materialized, materialization_events = self.materialize_local_text_with_events(
                    value,
                    session_id,
                    tool_name=tool_name,
                    path_mapping=mapping,
                )
                events.extend(materialization_events)
                return materialized
            if isinstance(value, list):
                return [walk(v) for v in value]
            if isinstance(value, dict):
                return {k: walk(v) for k, v in value.items()}
            return value

        return walk(copy.deepcopy(data)), events

    def materialize_local_text(self, text: str, session_id: str) -> str:
        materialized, _ = self.materialize_local_text_with_events(text, session_id)
        return materialized

    def materialize_local_text_with_events(
        self,
        text: str,
        session_id: str,
        *,
        tool_name: str = "",
        path_mapping: PathMapping | None = None,
    ) -> tuple[str, list[dict[str, Any]]]:
        materialized = text
        events: list[dict[str, Any]] = []
        mapping = path_mapping if path_mapping is not None else self._active_path_mapping(session_id)
        for alias, value, rec in mapping:
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
                materialized = materialized.replace(self._placeholder_replace_key(ph), result.value)
                action = "materialize"
                result_code = "OK"
            else:
                action = "preserve"
                result_code = self._normalize_code(result.error_code) or self._code("MATERIALIZATION_FAILED")
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

    def _active_path_mapping(self, session_id: str) -> PathMapping:
        key = (session_id, self.workspace_id)
        generation = self.mapping_store.write_generation
        cached = self._path_mapping_cache.get(key)
        if cached is not None and cached[0] == generation:
            return cached[1]
        records = self.mapping_store.active_records(
            session_id,
            self.workspace_id,
            materialization_class="path",
        )
        active_paths = [str(record.value) for record in records if record.value]
        sorted_paths = sorted(set(active_paths), key=len, reverse=True)
        pairs = [
            (self._hierarchical_path_alias(str(record.value), sorted_paths), str(record.value), record)
            for record in records
            if record.value
        ]
        result: PathMapping = tuple(sorted(set(pairs), key=lambda item: len(item[0]), reverse=True))
        if len(self._path_mapping_cache) >= 32:
            self._path_mapping_cache = {}
        self._path_mapping_cache[key] = (generation, result)
        return result

    def _hierarchical_path_alias(self, raw: str, active_paths: list[str]) -> str:
        best_parent = ""
        best_suffix: str | None = None
        for parent in active_paths:
            suffix = self.path_aliases.relative_suffix(parent, raw)
            if suffix and len(parent) > len(best_parent):
                best_parent = parent
                best_suffix = suffix
        if best_suffix is not None:
            return self.path_aliases.alias_for(best_parent) + best_suffix
        return self.path_aliases.alias_for(raw)

    @staticmethod
    def _placeholder_replace_key(ph: Any) -> str:
        """Return the text to replace when restoring a placeholder.

        ``parse()`` treats a following ``/path``-shaped run as a suffix. For
        ``path`` mappings the suffix is part of the restored value
        (``join_suffix``), so it is consumed together with the raw handle.
        For secret/PII mappings the suffix is unrelated following text and
        must be preserved, not swallowed with the replacement.
        """
        return ph.raw + ph.suffix if ph.kind == "path" else ph.raw

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

    def materialize_local_tool_arguments_json_with_events(
        self,
        arguments: str,
        session_id: str,
        *,
        tool_name: str = "",
        path_mapping: PathMapping | None = None,
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

        materialized, events = self.materialize_local_json_with_events(
            parsed,
            session_id,
            tool_name=tool_name,
            path_mapping=path_mapping,
        )
        return json.dumps(materialized, ensure_ascii=False, allow_nan=False), events

    def materialize_local_tool_args_with_events(
        self,
        data: Any,
        session_id: str,
        *,
        path_mapping: PathMapping | None = None,
    ) -> tuple[Any, list[dict[str, Any]]]:
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
        mapping = path_mapping if path_mapping is not None else self._active_path_mapping(session_id)

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
                                path_mapping=mapping,
                            )
                            events.extend(argument_events)
                        elif value.get("type") == "custom_tool_call" and k == "input":
                            if not isinstance(v, str):
                                raise ToolArgumentsJSONError("invalid_tool_arguments_type")
                            out[k], argument_events = self.materialize_local_text_with_events(
                                v,
                                session_id,
                                tool_name=tool_name,
                                path_mapping=mapping,
                            )
                            events.extend(argument_events)
                        else:
                            if not isinstance(v, dict):
                                raise ToolArgumentsJSONError("invalid_tool_arguments_type")
                            out[k], argument_events = self.materialize_local_json_with_events(
                                v,
                                session_id,
                                tool_name=tool_name,
                                path_mapping=mapping,
                            )
                            events.extend(argument_events)
                    else:
                        out[k] = walk(v, child_path)
                return out
            return value

        return walk(copy.deepcopy(data), ()), events

    def scan_local_json(
        self,
        data: Any,
        session_id: str,
        *,
        skip_tool_args: bool = True,
        path_mapping: PathMapping | None = None,
    ) -> tuple[Any, list[dict[str, Any]]]:
        events: list[dict[str, Any]] = []
        self.detector_manager.reset_diagnostics()
        mapping = path_mapping if path_mapping is not None else self._active_path_mapping(session_id)

        def walk(value: Any, path: tuple[str, ...]) -> Any:
            if isinstance(value, str):
                if self._is_protocol_value(path):
                    return value
                safe, string_events = self.scan_local_text(value, session_id, path_mapping=mapping)
                events.extend(string_events)
                return safe
            if isinstance(value, list):
                return [walk(item, path + (str(index),)) for index, item in enumerate(value)]
            if isinstance(value, dict):
                if _is_opaque_multimodal_container(value):
                    return copy.deepcopy(value)
                out: dict[str, Any] = {}
                for key, item in value.items():
                    child_path = path + (str(key),)
                    if key in OPAQUE_MULTIMODAL_FIELDS:
                        out[key] = item
                    elif key == "id" and isinstance(item, str) and _is_response_protocol_id(value, path):
                        out[key] = item
                    elif skip_tool_args and _is_tool_arg_container(value, str(key), path):
                        out[key] = item
                    else:
                        out[key] = walk(item, child_path)
                return out
            return value

        return walk(copy.deepcopy(data), ()), events

    def scan_local_text(
        self,
        text: str,
        session_id: str,
        *,
        fold_apg_markers: bool = True,
        path_mapping: PathMapping | None = None,
    ) -> tuple[str, list[dict[str, Any]]]:
        """Stream-safe downlink scan.

        Materializes exact valid same-session placeholders and path aliases
        back to raw values for the local user. Restored values are temporarily
        protected while the rest of the text is scanned, so an authorized
        restoration is not immediately redacted again. Any raw secret echoed
        directly by the model still gets folded.
        """
        protected = text
        restorations: dict[str, str] = {}
        events: list[dict[str, Any]] = []
        # This marker needs uniqueness, not secrecy. A hexadecimal nonce can
        # itself look like a high-entropy credential and be folded during the
        # response scan before restoration. Decimal digits keep the complete
        # token environment-reference-shaped without creating a secret-like
        # substring.
        restore_nonce = f"{secrets.randbelow(1_000_000_000_000):012d}"

        def protect(raw: str) -> str:
            # Use an environment-reference-shaped sentinel so credential
            # assignment detection treats it as an intentionally unresolved
            # local value rather than folding it as another secret. Restore
            # only the occurrence created here below.
            token = f"$PF_LOCAL_RESTORE_{restore_nonce}_{len(restorations):08d}"
            restorations[token] = raw
            return token

        mapping = path_mapping if path_mapping is not None else self._active_path_mapping(session_id)
        for alias, value, rec in mapping:
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
            result = self._materializer.materialize_placeholder(ph, session_id=session_id, sink_type="local_user")
            if result.allowed and result.value is not None:
                protected = protected.replace(self._placeholder_replace_key(ph), protect(result.value))
                action = "materialize"
                result_code = "OK"
            else:
                action = "preserve"
                result_code = self._normalize_code(result.error_code) or self._code("MATERIALIZATION_FAILED")
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
                        placeholder_session_id=ph.session_id,
                        issued_at=ph.issued_at,
                        suffix=ph.suffix,
                    )
                )

        safe, scan_events = self.sanitize_text(
            protected,
            session_id,
            scope="response",
            alias_paths=False,
            fold_apg_markers=fold_apg_markers,
        )
        for token, value in restorations.items():
            safe = safe.replace(token, value, 1)
        post_events: list[dict[str, Any]] = []
        for ph in self.signer.parse(safe):
            result = self._materializer.materialize_placeholder(ph, session_id=session_id, sink_type="local_user")
            if result.allowed and result.value is not None:
                safe = safe.replace(self._placeholder_replace_key(ph), result.value)
                rec = self.mapping_store.get(ph.handle_id)
                if rec is not None:
                    post_events.append(
                        self._materialization_event(
                            rec,
                            sink="local_user",
                            action="materialize",
                            result_code="OK",
                            representation_type="signed_placeholder",
                            placeholder_session_id=ph.session_id,
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
        if key in OPAQUE_MULTIMODAL_FIELDS:
            return True
        if key == "name" and any(parent in PROTOCOL_NAME_PARENTS for parent in path[:-1]):
            return True
        if any(parent in PROTOCOL_ID_PARENTS for parent in path[:-1]):
            return key == "id" or key.isdigit()
        return False

    async def scan_local_stream(
        self,
        chunks: AsyncIterator[bytes],
        session_id: str,
        *,
        on_complete: Callable[[dict[str, Any]], None] | None = None,
    ) -> AsyncIterator[bytes]:
        """Statefully scan an OpenAI Chat Completions SSE response."""
        summary = StreamAuditSummary(namespace=self.namespace)
        path_mapping = self._active_path_mapping(session_id)
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
                    path_mapping=path_mapping,
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
                            scanner = BalancedStreamScanner(self, session_id, path_mapping=path_mapping)
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
                    "code": self._code("TOOL_ARGUMENTS_INVALID") if tool_error else self._code("STREAM_PARSE_ERROR"),
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

    async def scan_anthropic_stream(
        self,
        chunks: AsyncIterator[bytes],
        session_id: str,
        *,
        on_complete: Callable[[dict[str, Any]], None] | None = None,
    ) -> AsyncIterator[bytes]:
        """Scan a native Anthropic Messages SSE stream without protocol conversion."""
        summary = StreamAuditSummary(namespace=self.namespace)
        path_mapping = self._active_path_mapping(session_id)
        text_scanners: dict[int, BalancedStreamScanner] = {}
        tool_buffers: dict[int, dict[str, str | bool]] = {}
        normal_end = False

        def event_bytes(payload: dict[str, Any]) -> bytes:
            event_type = str(payload.get("type") or "message")
            return (
                f"event: {event_type}\n"
                f"data: {json.dumps(payload, ensure_ascii=False)}\n\n"
            ).encode("utf-8")

        def flush_text(index: int) -> list[bytes]:
            scanner = text_scanners.pop(index, None)
            if scanner is None:
                return []
            safe, events = scanner.flush()
            summary.record(events)
            if not safe:
                return []
            return [
                event_bytes(
                    {
                        "type": "content_block_delta",
                        "index": index,
                        "delta": {"type": "text_delta", "text": safe},
                    }
                )
            ]

        def flush_tool(index: int) -> list[bytes]:
            tool = tool_buffers.get(index)
            if tool is None or bool(tool.get("flushed")):
                return []
            tool["flushed"] = True
            if not bool(tool.get("saw_delta")):
                return []
            arguments, events = self.materialize_local_tool_arguments_json_with_events(
                str(tool.get("arguments") or ""),
                session_id,
                tool_name=str(tool.get("name") or ""),
                path_mapping=path_mapping,
            )
            summary.record(events)
            return [
                event_bytes(
                    {
                        "type": "content_block_delta",
                        "index": index,
                        "delta": {
                            "type": "input_json_delta",
                            "partial_json": arguments,
                        },
                    }
                )
            ]

        try:
            async for data in iter_sse_data(chunks):
                if not data:
                    continue
                if data == "[DONE]":
                    raise StreamProtocolError("unexpected_anthropic_done")
                try:
                    payload = json.loads(data)
                except (ValueError, TypeError) as exc:
                    raise StreamProtocolError("invalid_sse_json") from exc
                if not isinstance(payload, dict):
                    raise StreamProtocolError("invalid_sse_payload")

                event_type = payload.get("type")
                if event_type == "content_block_start":
                    try:
                        index = int(payload.get("index", 0))
                    except (TypeError, ValueError) as exc:
                        raise StreamProtocolError("invalid_content_block_index") from exc
                    block = payload.get("content_block")
                    if not isinstance(block, dict):
                        raise StreamProtocolError("invalid_content_block")
                    block_type = block.get("type")
                    if block_type == "text":
                        scanner = BalancedStreamScanner(self, session_id, path_mapping=path_mapping)
                        text_scanners[index] = scanner
                        initial = block.get("text", "")
                        if not isinstance(initial, str):
                            raise StreamProtocolError("invalid_text_block")
                        safe, events = scanner.feed(initial)
                        summary.record(events)
                        emitted = copy.deepcopy(payload)
                        emitted["content_block"]["text"] = safe
                        yield event_bytes(emitted)
                        continue
                    if block_type == "tool_use":
                        name = block.get("name", "")
                        if not isinstance(name, str):
                            raise StreamProtocolError("invalid_tool_name")
                        initial_input = block.get("input", {})
                        if not isinstance(initial_input, dict):
                            raise ToolArgumentsJSONError("invalid_tool_arguments_type")
                        materialized, events = self.materialize_local_json_with_events(
                            initial_input,
                            session_id,
                            tool_name=name,
                            path_mapping=path_mapping,
                        )
                        summary.record(events)
                        emitted = copy.deepcopy(payload)
                        emitted["content_block"]["input"] = materialized
                        tool_buffers[index] = {
                            "name": name,
                            "arguments": "",
                            "flushed": False,
                            "saw_delta": False,
                        }
                        yield event_bytes(emitted)
                        continue

                if event_type == "content_block_delta":
                    try:
                        index = int(payload.get("index", 0))
                    except (TypeError, ValueError) as exc:
                        raise StreamProtocolError("invalid_content_block_index") from exc
                    delta = payload.get("delta")
                    if not isinstance(delta, dict):
                        raise StreamProtocolError("invalid_content_block_delta")
                    delta_type = delta.get("type")
                    if delta_type == "text_delta":
                        text = delta.get("text")
                        if not isinstance(text, str):
                            raise StreamProtocolError("invalid_text_delta")
                        scanner = text_scanners.setdefault(
                            index,
                            BalancedStreamScanner(self, session_id, path_mapping=path_mapping),
                        )
                        safe, events = scanner.feed(text)
                        summary.record(events)
                        if safe:
                            emitted = copy.deepcopy(payload)
                            emitted["delta"]["text"] = safe
                            yield event_bytes(emitted)
                        continue
                    if delta_type == "input_json_delta":
                        partial = delta.get("partial_json")
                        if not isinstance(partial, str):
                            raise ToolArgumentsJSONError("invalid_tool_arguments_type")
                        tool = tool_buffers.setdefault(
                            index,
                            {
                                "name": "",
                                "arguments": "",
                                "flushed": False,
                                "saw_delta": False,
                            },
                        )
                        tool["arguments"] = str(tool.get("arguments") or "") + partial
                        tool["saw_delta"] = True
                        continue

                if event_type == "content_block_stop":
                    try:
                        index = int(payload.get("index", 0))
                    except (TypeError, ValueError) as exc:
                        raise StreamProtocolError("invalid_content_block_index") from exc
                    for item in flush_text(index):
                        yield item
                    for item in flush_tool(index):
                        yield item
                    yield event_bytes(payload)
                    continue

                if event_type == "message_stop":
                    for index in sorted(text_scanners):
                        for item in flush_text(index):
                            yield item
                    for index in sorted(tool_buffers):
                        for item in flush_tool(index):
                            yield item
                    normal_end = True

                safe_payload, events = self.scan_local_json(
                    payload,
                    session_id,
                    path_mapping=path_mapping,
                )
                summary.record(events)
                yield event_bytes(safe_payload)
            if not normal_end:
                raise StreamProtocolError("incomplete_anthropic_stream")
        except StreamProtocolError as exc:
            summary.record_protocol_error(exc)
            summary.termination = "protocol_error"
            tool_error = isinstance(exc, ToolArgumentsJSONError)
            yield event_bytes(
                {
                    "type": "error",
                    "error": {
                        "type": "api_error",
                        "message": (
                            "The upstream tool-call arguments were not valid JSON."
                            if tool_error
                            else "The upstream stream could not be safely parsed."
                        ),
                    },
                }
            )
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
        summary = StreamAuditSummary(namespace=self.namespace)
        path_mapping = self._active_path_mapping(session_id)
        text_scanners: dict[tuple[str, int, int, str], BalancedStreamScanner] = {}
        text_templates: dict[tuple[str, int, int, str], tuple[SSEEvent, dict[str, Any]]] = {}
        tool_buffers: dict[tuple[int, str], _ResponsesToolBuffer] = {}
        custom_tool_buffers: dict[tuple[int, str], _ResponsesToolBuffer] = {}
        normal_end = False

        text_delta_fields = {
            "response.code_interpreter_call_code.delta": "delta",
            "response.mcp_call_arguments.delta": "delta",
            "response.output_text.delta": "delta",
            "response.reasoning_text.delta": "delta",
            "response.reasoning_summary_text.delta": "delta",
            "response.refusal.delta": "delta",
        }
        text_done_fields = {
            "response.code_interpreter_call_code.done": "code",
            "response.mcp_call_arguments.done": "arguments",
            "response.output_text.done": "text",
            "response.reasoning_text.done": "text",
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
            arguments, events = self.materialize_local_text_with_events(
                tool.arguments,
                session_id,
                path_mapping=path_mapping,
            )
            summary.record(events)
            tool.arguments = arguments
            if not arguments:
                return []
            template = dict(tool.template)
            template["type"] = "response.function_call_arguments.delta"
            template["delta"] = arguments
            event = SSEEvent("response.function_call_arguments.delta", "")
            return [event_bytes(event, template)]

        def flush_custom_tool(key: tuple[int, str]) -> list[bytes]:
            tool = custom_tool_buffers.get(key)
            if tool is None or tool.flushed:
                return []
            tool.flushed = True
            tool_input, events = self.materialize_local_text_with_events(
                tool.arguments,
                session_id,
                path_mapping=path_mapping,
            )
            summary.record(events)
            tool.arguments = tool_input
            if not tool_input:
                return []
            template = dict(tool.template)
            template["type"] = "response.custom_tool_call_input.delta"
            template["delta"] = tool_input
            event = SSEEvent("response.custom_tool_call_input.delta", "")
            return [event_bytes(event, template)]

        def scan_complete_payload(payload: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
            materialized, materialization_events = self.materialize_local_tool_args_with_events(
                payload,
                session_id,
                path_mapping=path_mapping,
            )
            safe, scan_events = self.scan_local_json(
                materialized,
                session_id,
                skip_tool_args=True,
                path_mapping=path_mapping,
            )
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
                    for key in list(custom_tool_buffers):
                        for item in flush_custom_tool(key):
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

                if event_type.startswith(("response.audio.", "response.image_generation_call.")):
                    yield event_bytes(event, payload)
                    continue

                if event_type in text_delta_fields:
                    field_name = text_delta_fields[event_type]
                    fragment = payload.get(field_name)
                    if not isinstance(fragment, str):
                        raise StreamProtocolError("invalid_responses_text_delta")
                    key = text_key(event_type, payload)
                    scanner = text_scanners.setdefault(
                        key,
                        BalancedStreamScanner(self, session_id, path_mapping=path_mapping),
                    )
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
                        safe_text, events = self.scan_local_text(
                            done_text,
                            session_id,
                            path_mapping=path_mapping,
                        )
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
                    safe_arguments, events = self.materialize_local_text_with_events(
                        tool.arguments,
                        session_id,
                        path_mapping=path_mapping,
                    )
                    summary.record(events)
                    safe_payload = dict(payload)
                    safe_payload["arguments"] = safe_arguments
                    yield event_bytes(event, safe_payload)
                    continue

                if event_type == "response.custom_tool_call_input.delta":
                    fragment = payload.get("delta")
                    if not isinstance(fragment, str):
                        raise StreamProtocolError("invalid_responses_custom_tool_delta")
                    key = tool_key(payload)
                    tool = custom_tool_buffers.setdefault(key, _ResponsesToolBuffer(key))
                    tool.arguments += fragment
                    tool.template = {key_name: value for key_name, value in payload.items() if key_name != "delta"}
                    continue

                if event_type == "response.custom_tool_call_input.done":
                    key = tool_key(payload)
                    tool = custom_tool_buffers.setdefault(key, _ResponsesToolBuffer(key))
                    full_input = payload.get("input")
                    if isinstance(full_input, str):
                        tool.arguments = full_input
                    tool.template = {key_name: value for key_name, value in payload.items() if key_name != "input"}
                    for item in flush_custom_tool(key):
                        yield item
                    safe_input, events = self.materialize_local_text_with_events(
                        tool.arguments,
                        session_id,
                        path_mapping=path_mapping,
                    )
                    summary.record(events)
                    safe_payload = dict(payload)
                    safe_payload["input"] = safe_input
                    yield event_bytes(event, safe_payload)
                    continue

                if event_type in {"response.output_item.done", "response.completed", "response.incomplete"}:
                    if event_type in {"response.completed", "response.incomplete"}:
                        for key in list(text_scanners):
                            for item in flush_text(key):
                                yield item
                        for key in list(tool_buffers):
                            for item in flush_tool(key):
                                yield item
                        for key in list(custom_tool_buffers):
                            for item in flush_custom_tool(key):
                                yield item
                    safe_payload, events = scan_complete_payload(payload)
                    summary.record(events)
                    yield event_bytes(event, safe_payload)
                    if event_type in {"response.completed", "response.incomplete"}:
                        normal_end = True
                        if event_type == "response.incomplete":
                            summary.termination = "incomplete"
                    continue

                if event_type in {"response.failed", "error"}:
                    safe_payload, events = scan_complete_payload(payload)
                    summary.record(events)
                    summary.record_upstream_error(event_type, payload)
                    normal_end = True
                    yield event_bytes(event, safe_payload)
                    return

                if event_type.endswith(".delta") and isinstance(payload.get("delta"), str):
                    raise StreamProtocolError("unknown_responses_text_delta")

                safe_payload, events = self.scan_local_json(
                    payload,
                    session_id,
                    skip_tool_args=True,
                    path_mapping=path_mapping,
                )
                summary.record(events)
                yield event_bytes(event, safe_payload)

            for key in list(text_scanners):
                for item in flush_text(key):
                    yield item
            for key in list(tool_buffers):
                for item in flush_tool(key):
                    yield item
            for key in list(custom_tool_buffers):
                for item in flush_custom_tool(key):
                    yield item
            if not normal_end:
                summary.termination = "upstream_disconnected"
                normal_end = True
        except StreamProtocolError as exc:
            summary.record_protocol_error(exc)
            summary.termination = "protocol_error"
            error = {
                "type": "error",
                "code": self._code("STREAM_PARSE_ERROR"),
                "message": "The upstream Responses stream could not be safely parsed.",
                "retryable": True,
            }
            yield SSEEvent("error", "").encode(event="error", data=json.dumps(error))
        finally:
            if not normal_end and summary.termination == "completed":
                summary.termination = "client_disconnected"
            if on_complete is not None:
                on_complete(summary.to_dict())


def _source_kind_for_json_path(path: tuple[str, ...], scope: str) -> str:
    if "tools" in path:
        return "tool_schema"
    if path and path[-1] in CONTENT_FIELD_NAMES:
        return "model_response" if scope == "response" else "prompt"
    return "protocol_metadata"


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
    if container.get("type") == "custom_tool_call" and key == "input":
        return True
    return any(parent in TOOL_ARG_PARENTS for parent in path)


def _is_opaque_multimodal_container(container: dict[str, Any]) -> bool:
    value = container.get("type")
    return isinstance(value, str) and value in OPAQUE_MULTIMODAL_TYPES


def _is_response_protocol_id(container: dict[str, Any], path: tuple[str, ...]) -> bool:
    if container.get("object") == "response":
        return True
    value = container.get("type")
    if isinstance(value, str) and value in {
        "message",
        "tool_use",
        "function_call",
        "function_call_output",
        "custom_tool_call",
        "custom_tool_call_output",
        "computer_call",
        "computer_call_output",
        "local_shell_call",
        "local_shell_call_output",
        "shell_call",
        "shell_call_output",
        "mcp_call",
        "mcp_approval_request",
        "mcp_approval_response",
        "code_interpreter_call",
        "image_generation_call",
        "file_search_call",
        "web_search_call",
        "compaction",
        "output_text",
        "reasoning",
        "reasoning_summary",
        "refusal",
    }:
        return True
    return any(parent in {"response", "output", "content"} for parent in path)
