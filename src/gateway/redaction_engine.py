from __future__ import annotations

import copy
from collections.abc import AsyncIterator
from typing import Any

from gateway.detector_manager import DetectorManager
from gateway.mapping_store import MappingStore
from gateway.materialization_engine import MaterializationEngine
from gateway.path_alias_manager import PathAliasManager
from gateway.placeholder_parser import PlaceholderSigner
from gateway.policy_engine import PolicyEngine

PROTOCOL_KEYS = {"model", "tool_call_id", "tool_use_id"}
PROTOCOL_ID_PARENTS = {"tool_calls", "tool_use"}
PROTOCOL_NAME_PARENTS = {"function"}
# Tool-call argument fields are the only sink where APG materializes secrets
# back to raw values on the downlink, so the agent harness receives the real
# credential when executing the tool. All other string fields stay redacted.
TOOL_ARG_FIELDS = {"arguments", "input"}
TOOL_ARG_PARENTS = {"function", "tool_use"}
STREAM_MATERIALIZATION_TAIL = 4096


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
        self._path_alias_to_value: dict[str, str] = {}
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
                    else:
                        out[k] = walk(v, path + (str(k),))
                return out
            return value

        return walk(copy.deepcopy(data), ()), events

    def sanitize_text(self, text: str, session_id: str, scope: str = "request", *, alias_paths: bool = True) -> tuple[str, list[dict[str, Any]]]:
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
            if det.type == "path" and decision.action == "alias":
                alias = self.path_aliases.alias_for(raw)
                self._path_alias_to_value[alias] = raw
                self.mapping_store.upsert_mapping(
                    session_id=session_id,
                    workspace_id=self.workspace_id,
                    scope="workspace",
                    kind="path",
                    subtype=det.subtype,
                    value=raw,
                    store_value=True,
                    materialization_class="path",
                    ttl_seconds=14 * 86_400,
                    max_ttl_seconds=90 * 86_400,
                )
                replacement = alias
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
                    ttl_seconds=7 * 86_400 if det.type == "pii" else 1800,
                    max_ttl_seconds=30 * 86_400 if det.type == "pii" else 7200,
                )
                if det.type == "pii" and decision.action == "pseudonymize":
                    replacement = f"<APG_PII:{rec.handle_id}>"
                else:
                    replacement = self.signer.issue(mapping_kind, rec.handle_id, session_id)
            events.append(
                {
                    "type": det.type,
                    "subtype": det.subtype,
                    "detector": det.detector_name,
                    "risk": det.risk,
                    "action": decision.action,
                    "safe_preview": det.safe_preview,
                }
            )
            out.append(replacement)
            cursor = det.span_end
        out.append(text[cursor:])
        return "".join(out), events

    def materialize_local_json(self, data: Any, session_id: str) -> Any:
        def walk(value: Any) -> Any:
            if isinstance(value, str):
                return self.materialize_local_text(value, session_id)
            if isinstance(value, list):
                return [walk(v) for v in value]
            if isinstance(value, dict):
                return {k: walk(v) for k, v in value.items()}
            return value

        return walk(copy.deepcopy(data))

    def materialize_local_text(self, text: str, session_id: str) -> str:
        materialized = text
        for alias, value in sorted(self._path_alias_to_value.items(), key=lambda item: len(item[0]), reverse=True):
            materialized = materialized.replace(alias, value)
        for ph in self.signer.parse(materialized):
            result = self._materializer.materialize_placeholder(ph, session_id=session_id, sink_type="local_tool")
            if result.allowed and result.value is not None:
                materialized = materialized.replace(ph.raw + ph.suffix, result.value)
        return materialized

    def materialize_local_tool_args(self, data: Any, session_id: str) -> Any:
        """Materialize placeholders back to raw values, but only inside
        structured tool-call argument fields.

        This is the only path through which an agent harness transparently
        receives the real secret value needed to execute a tool. Every other
        string field (assistant-visible text, reasoning, tool descriptions)
        stays redacted and is handled separately by the response scanner.
        Fail-closed: an invalid/hallucinated placeholder is left as-is rather
        than partially replaced.
        """
        import json as _json

        def materialize_string(s: str) -> str:
            # arguments is a JSON-encoded string in the OpenAI shape; try to
            # materialize inside the decoded structure so keys/positions are
            # preserved, then re-encode. If it isn't valid JSON, treat the
            # whole string as a free-form argument and materialize directly.
            try:
                parsed = _json.loads(s)
            except (ValueError, TypeError):
                return self.materialize_local_text(s, session_id)
            materialized = _materialize_json_node(parsed, session_id)
            return _json.dumps(materialized, ensure_ascii=False)

        def _materialize_json_node(node: Any, sid: str) -> Any:
            if isinstance(node, str):
                return self.materialize_local_text(node, sid)
            if isinstance(node, list):
                return [_materialize_json_node(v, sid) for v in node]
            if isinstance(node, dict):
                return {k: _materialize_json_node(v, sid) for k, v in node.items()}
            return node

        def walk(value: Any, path: tuple[str, ...]) -> Any:
            if isinstance(value, list):
                return [walk(v, path + (str(i),)) for i, v in enumerate(value)]
            if isinstance(value, dict):
                out: dict[str, Any] = {}
                for k, v in value.items():
                    child_path = path + (str(k),)
                    if k in TOOL_ARG_FIELDS and any(parent in TOOL_ARG_PARENTS for parent in child_path[:-1]) and isinstance(v, (str, dict, list)):
                        if isinstance(v, str):
                            out[k] = materialize_string(v)
                        else:
                            out[k] = _materialize_json_node(v, session_id)
                    else:
                        out[k] = walk(v, child_path)
                return out
            return value

        return walk(copy.deepcopy(data), ())

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

    def scan_local_text(self, text: str, session_id: str) -> tuple[str, list[dict[str, Any]]]:
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
        materialized = text
        for alias, value in sorted(self._path_alias_to_value.items(), key=lambda item: len(item[0]), reverse=True):
            materialized = materialized.replace(alias, value)
        for ph in self.signer.parse(materialized):
            if ph.kind == "secret":
                continue
            result = self._materializer.materialize_placeholder(ph, session_id=session_id, sink_type="local_tool")
            if result.allowed and result.value is not None:
                materialized = materialized.replace(ph.raw + ph.suffix, result.value)
        return self.sanitize_text(materialized, session_id, scope="response", alias_paths=False)

    def _is_protocol_value(self, path: tuple[str, ...]) -> bool:
        if not path:
            return False
        key = path[-1]
        if key in PROTOCOL_KEYS:
            return True
        if key == "name" and any(parent in PROTOCOL_NAME_PARENTS for parent in path[:-1]):
            return True
        return key == "id" and any(parent in PROTOCOL_ID_PARENTS for parent in path[:-1])

    async def scan_local_stream(self, chunks: AsyncIterator[bytes], session_id: str) -> AsyncIterator[bytes]:
        """Downlink stream scanner.

        Parses the OpenAI SSE stream into discrete ``data: ...`` events,
        materializes path/PII placeholders inside ``choices[].delta.content``
        and ``(tool_calls[].function).arguments`` deltas, and re-scans each
        instance for raw secret echoes. A secret split across SSE deltas is
        not retried across deltas (per-token content is the streamable
        contract); secrets fully contained in a single delta are redacted.
        Non-JSON/SSE bytes are passed through unchanged.
        """
        import json as _json

        raw = ""
        async for chunk in chunks:
            raw += chunk.decode("utf-8", errors="ignore")
            while "\n\n" in raw:
                event, raw = raw.split("\n\n", 1)
                yield _scan_sse_event(self, event, session_id, _json).encode("utf-8")
            # Re-emit the trailing incomplete line as-is so the client sees
            # natural SSE whitespace framing between events.
            if raw and not raw.startswith("data:") and not raw.startswith("event:") and not raw.startswith("id:"):
                yield raw.encode("utf-8")
                raw = ""
        if raw:
            yield _scan_sse_event(self, raw, session_id, _json).encode("utf-8")


def _scan_sse_event(redactor: "RedactionEngine", event: str, session_id: str, _json: Any) -> str:
    """Apply downlink scanning to a single SSE event, preserving framing."""
    lines = event.splitlines()
    out_lines: list[str] = []
    for line in lines:
        stripped = line.strip()
        if not stripped.startswith("data:"):
            out_lines.append(line)
            continue
        data = stripped.removeprefix("data:").strip()
        if not data or data == "[DONE]":
            out_lines.append(line)
            continue
        try:
            payload = _json.loads(data)
        except (ValueError, TypeError):
            out_lines.append(line)
            continue
        _scan_payload(redactor, payload, session_id)
        out_lines.append("data: " + _json.dumps(payload, ensure_ascii=False))
    return "\n".join(out_lines) + "\n\n"


def _scan_payload(redactor: "RedactionEngine", payload: Any, session_id: str) -> None:
    """Mutate ``payload`` in place, redacting raw secret echoes inside
    ``choices[].delta.content`` and ``delta.tool_calls[].function.arguments``
    deltas. PII/path placeholders inside the same fields are materialized."""
    if not isinstance(payload, dict):
        return
    choices = payload.get("choices")
    if not isinstance(choices, list):
        return
    for choice in choices:
        if not isinstance(choice, dict):
            continue
        delta = choice.get("delta")
        if not isinstance(delta, dict):
            continue
        if isinstance(delta.get("content"), str):
            scanned, _ = redactor.scan_local_text(delta["content"], session_id)
            delta["content"] = scanned
        calls = delta.get("tool_calls")
        if isinstance(calls, list):
            for call in calls:
                if not isinstance(call, dict):
                    continue
                fn = call.get("function")
                if isinstance(fn, dict) and isinstance(fn.get("arguments"), str):
                    scanned, _ = redactor.scan_local_text(fn["arguments"], session_id)
                    fn["arguments"] = scanned


def _is_tool_arg_field(path: tuple[str, ...]) -> bool:
    """True when ``path`` points at a tool-call arguments/input field that the
    response scanner has already materialized and must NOT re-redact."""
    if not path:
        return False
    key = path[-1]
    if key not in TOOL_ARG_FIELDS:
        return False
    return any(parent in TOOL_ARG_PARENTS for parent in path[:-1])
