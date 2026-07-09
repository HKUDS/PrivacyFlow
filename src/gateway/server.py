from __future__ import annotations

import json
import uuid
from collections.abc import AsyncIterator
from typing import Any

import httpx
from fastapi import FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse

from gateway.audit_logger import AuditLogger
from gateway.config import GatewayConfig, load_config
from gateway.detector_manager import DetectorManager
from gateway.mapping_store import MappingStore
from gateway.placeholder_parser import PlaceholderSigner
from gateway.policy_engine import PolicyEngine
from gateway.redaction_engine import RedactionEngine
from gateway.response_scanner import ResponseScanner
from gateway.state.session_manager import SessionManager
from gateway.upstream_client import UpstreamClient

ANTHROPIC_DEFAULT_UPSTREAM_MODEL = "deepseek-v4-flash"


def _upstream_error_response(exc: Exception, audit: AuditLogger, request_id: str, session_id: str, workspace_id: str, endpoint: str) -> JSONResponse:
    """Normalize an httpx upstream exception into a safe 502/504 response.

    Prevents the default FastAPI/Starlette 500 with a traceback from leaking
    request shape or upstream address details to the caller.
    """
    if isinstance(exc, httpx.TimeoutException):
        code = "APG_UPSTREAM_TIMEOUT"
        status = 504
    else:
        code = "APG_UPSTREAM_UNREACHABLE"
        status = 502
    audit.log(
        {
            "request_id": request_id,
            "session_id": session_id,
            "workspace_id": workspace_id,
            "endpoint": endpoint,
            "phase": "upstream_error",
            "error_type": exc.__class__.__name__,
            "code": code,
            "status": status,
        }
    )
    return JSONResponse(
        {"error": {"code": code, "retryable": True, "message": "Upstream provider could not be reached."}},
        status_code=status,
    )


def create_app(config: GatewayConfig | None = None, upstream_client: UpstreamClient | None = None) -> FastAPI:
    cfg = config or load_config()
    store = MappingStore(cfg.database_path)
    signer = PlaceholderSigner(cfg.signing_secret, cfg.workspace_id)
    policy = PolicyEngine(pii_mode=cfg.pii_mode)
    redactor = RedactionEngine(DetectorManager(detectors_config=cfg.detectors_config), store, signer, policy, cfg.workspace_id)
    response_scanner = ResponseScanner(redactor)
    sessions = SessionManager(cfg.database_path)
    upstream = upstream_client or UpstreamClient(cfg.upstream)
    audit = AuditLogger(cfg.audit_log_path)

    app = FastAPI(title="Agent Privacy Gateway", version="0.1.0")

    def authenticate(auth: str | None, requested_session_id: str | None, x_api_key: str | None = None) -> str:
        if x_api_key:
            key = x_api_key.strip()
        elif auth and auth.startswith("Bearer "):
            key = auth.removeprefix("Bearer ").strip()
        else:
            raise HTTPException(status_code=401, detail="Missing local API key")
        if cfg.local_api_keys and key not in cfg.local_api_keys:
            raise HTTPException(status_code=401, detail="Invalid local API key")
        return sessions.session_for_key(key, requested_session_id)

    async def proxy_json(endpoint: str, request: Request, authorization: str | None, x_apg_session_id: str | None, x_api_key: str | None = None) -> Response:
        request_id = f"req_{uuid.uuid4().hex[:12]}"
        session_id = authenticate(authorization, x_apg_session_id, x_api_key)
        try:
            body: Any = await request.json()
        except Exception as exc:
            raise HTTPException(status_code=400, detail="Invalid JSON") from exc
        sanitized, request_events = redactor.sanitize_json(body, session_id)
        audit.log(
            {
                "request_id": request_id,
                "session_id": session_id,
                "workspace_id": cfg.workspace_id,
                "endpoint": endpoint,
                "phase": "request",
                "detections": request_events,
                "detector_diagnostics": redactor.detector_manager.diagnostics(),
                "before_chars": len(str(body)),
                "after_chars": len(str(sanitized)),
            }
        )
        if isinstance(sanitized, dict) and sanitized.get("stream") is True:
            try:
                status, headers, stream_body = await upstream.stream_request("POST", endpoint, sanitized)
            except httpx.HTTPError as exc:
                return _upstream_error_response(exc, audit, request_id, session_id, cfg.workspace_id, endpoint)
            audit.log(
                {
                    "request_id": request_id,
                    "session_id": session_id,
                    "workspace_id": cfg.workspace_id,
                    "endpoint": endpoint,
                    "phase": "response",
                    "status": status,
                    "stream": True,
                    "detections": [],
                    "note": "stream path scans per-chunk via scan_local_stream; detections not aggregated here",
                }
            )
            local_stream = redactor.scan_local_stream(stream_body, session_id)
            return StreamingResponse(local_stream, status_code=status, media_type=headers.get("content-type", "text/event-stream"))
        try:
            status, headers, upstream_body = await upstream.request_json("POST", endpoint, sanitized)
        except httpx.HTTPError as exc:
            return _upstream_error_response(exc, audit, request_id, session_id, cfg.workspace_id, endpoint)
        scanned_body, response_events = response_scanner.scan_response_json(upstream_body, session_id)
        audit.log(
            {
                "request_id": request_id,
                "session_id": session_id,
                "workspace_id": cfg.workspace_id,
                "endpoint": endpoint,
                "phase": "response",
                "status": status,
                "detections": response_events,
            }
        )
        return JSONResponse(scanned_body, status_code=status, headers=headers)

    def anthropic_text_from_content(content: Any) -> str:
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            parts: list[str] = []
            for block in content:
                if isinstance(block, dict):
                    if block.get("type") == "text":
                        parts.append(str(block.get("text", "")))
                    elif block.get("type") == "tool_result":
                        result_content = block.get("content", "")
                        if isinstance(result_content, str):
                            parts.append(result_content)
                        else:
                            parts.append(json.dumps(result_content, ensure_ascii=False))
            return "\n".join(part for part in parts if part)
        return str(content)

    def anthropic_to_openai(body: dict[str, Any]) -> dict[str, Any]:
        messages: list[dict[str, Any]] = []
        system = body.get("system")
        if isinstance(system, str) and system:
            messages.append({"role": "system", "content": system})
        elif isinstance(system, list):
            system_text = anthropic_text_from_content(system)
            if system_text:
                messages.append({"role": "system", "content": system_text})

        for message in body.get("messages", []):
            role = message.get("role")
            content = message.get("content", "")
            if role == "user" and isinstance(content, list) and any(isinstance(block, dict) and block.get("type") == "tool_result" for block in content):
                text_parts: list[str] = []
                for block in content:
                    if not isinstance(block, dict):
                        continue
                    if block.get("type") == "tool_result":
                        messages.append(
                            {
                                "role": "tool",
                                "tool_call_id": block.get("tool_use_id", ""),
                                "content": anthropic_text_from_content(block.get("content", "")),
                            }
                        )
                    elif block.get("type") == "text":
                        text_parts.append(str(block.get("text", "")))
                if text_parts:
                    messages.append({"role": "user", "content": "\n".join(text_parts)})
                continue

            if role == "assistant" and isinstance(content, list):
                text_parts = []
                tool_calls = []
                for block in content:
                    if not isinstance(block, dict):
                        continue
                    if block.get("type") == "text":
                        text_parts.append(str(block.get("text", "")))
                    elif block.get("type") == "tool_use":
                        tool_calls.append(
                            {
                                "id": block.get("id", f"call_{uuid.uuid4().hex[:12]}"),
                                "type": "function",
                                "function": {
                                    "name": block.get("name", ""),
                                    "arguments": json.dumps(block.get("input", {}), ensure_ascii=False),
                                },
                            }
                        )
                msg: dict[str, Any] = {"role": "assistant", "content": "\n".join(text_parts) if text_parts else None}
                if tool_calls:
                    msg["tool_calls"] = tool_calls
                messages.append(msg)
                continue

            messages.append({"role": role, "content": anthropic_text_from_content(content)})

        requested_model = str(body.get("model") or ANTHROPIC_DEFAULT_UPSTREAM_MODEL)
        upstream_model = requested_model if requested_model.startswith("deepseek-") else ANTHROPIC_DEFAULT_UPSTREAM_MODEL
        converted: dict[str, Any] = {
            "model": upstream_model,
            "_apg_requested_model": requested_model,
            "messages": messages,
            "stream": bool(body.get("stream")),
        }
        if "max_tokens" in body:
            converted["max_tokens"] = body["max_tokens"]
        if "temperature" in body:
            converted["temperature"] = body["temperature"]
        if body.get("tools"):
            converted["tools"] = [
                {
                    "type": "function",
                    "function": {
                        "name": tool.get("name"),
                        "description": tool.get("description", ""),
                        "parameters": tool.get("input_schema", {"type": "object", "properties": {}}),
                    },
                }
                for tool in body["tools"]
                if isinstance(tool, dict)
            ]
        if body.get("tool_choice"):
            choice = body["tool_choice"]
            if isinstance(choice, dict) and choice.get("type") == "tool":
                converted["tool_choice"] = {"type": "function", "function": {"name": choice.get("name")}}
            elif isinstance(choice, dict) and choice.get("type") == "any":
                converted["tool_choice"] = "required"
            elif isinstance(choice, dict) and choice.get("type") == "auto":
                converted["tool_choice"] = "auto"
        return converted

    def openai_message_to_anthropic(body: dict[str, Any], model: str) -> dict[str, Any]:
        choice = (body.get("choices") or [{}])[0]
        message = choice.get("message") or {}
        content: list[dict[str, Any]] = []
        text = message.get("content")
        if text:
            content.append({"type": "text", "text": text})
        for call in message.get("tool_calls") or []:
            function = call.get("function") or {}
            try:
                args = json.loads(function.get("arguments") or "{}")
            except json.JSONDecodeError:
                args = {}
            content.append({"type": "tool_use", "id": call.get("id"), "name": function.get("name"), "input": args})
        finish = choice.get("finish_reason")
        stop_reason = "tool_use" if finish == "tool_calls" else "max_tokens" if finish == "length" else "end_turn"
        usage = body.get("usage") or {}
        return {
            "id": body.get("id", f"msg_{uuid.uuid4().hex[:24]}"),
            "type": "message",
            "role": "assistant",
            "model": model,
            "content": content,
            "stop_reason": stop_reason,
            "stop_sequence": None,
            "usage": {
                "input_tokens": usage.get("prompt_tokens", 0),
                "output_tokens": usage.get("completion_tokens", 0),
            },
        }

    def sse_event(event: str, data: dict[str, Any]) -> bytes:
        return f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n".encode("utf-8")

    async def openai_stream_to_anthropic(chunks: AsyncIterator[bytes], session_id: str, model: str) -> AsyncIterator[bytes]:
        message_id = f"msg_{uuid.uuid4().hex[:24]}"
        yield sse_event(
            "message_start",
            {
                "type": "message_start",
                "message": {
                    "id": message_id,
                    "type": "message",
                    "role": "assistant",
                    "model": model,
                    "content": [],
                    "stop_reason": None,
                    "stop_sequence": None,
                    "usage": {"input_tokens": 0, "output_tokens": 0},
                },
            },
        )
        text_started = False
        text_index: int | None = None
        tool_indexes: dict[int, int] = {}
        tool_arg_buffers: dict[int, str] = {}
        next_index = 0
        stop_reason = "end_turn"
        buffer = ""
        async for chunk in chunks:
            buffer += chunk.decode("utf-8", errors="ignore")
            while "\n\n" in buffer:
                event, buffer = buffer.split("\n\n", 1)
                for line in event.splitlines():
                    if not line.startswith("data:"):
                        continue
                    data = line.removeprefix("data:").strip()
                    if not data or data == "[DONE]":
                        continue
                    try:
                        payload = json.loads(data)
                    except json.JSONDecodeError:
                        continue
                    choice = (payload.get("choices") or [{}])[0]
                    delta = choice.get("delta") or {}
                    finish = choice.get("finish_reason")
                    if finish == "tool_calls":
                        stop_reason = "tool_use"
                    elif finish == "length":
                        stop_reason = "max_tokens"
                    text = delta.get("content")
                    if text:
                        if not text_started:
                            text_index = next_index
                            yield sse_event("content_block_start", {"type": "content_block_start", "index": next_index, "content_block": {"type": "text", "text": ""}})
                            text_started = True
                            next_index += 1
                        safe_text, _txt_events = redactor.scan_local_text(text, session_id)
                        yield sse_event("content_block_delta", {"type": "content_block_delta", "index": text_index, "delta": {"type": "text_delta", "text": safe_text}})
                    for call in delta.get("tool_calls") or []:
                        call_pos = int(call.get("index", 0))
                        function = call.get("function") or {}
                        if call_pos not in tool_indexes:
                            tool_indexes[call_pos] = next_index
                            tool_arg_buffers[call_pos] = ""
                            yield sse_event(
                                "content_block_start",
                                {
                                    "type": "content_block_start",
                                    "index": next_index,
                                    "content_block": {
                                        "type": "tool_use",
                                        "id": call.get("id") or f"call_{uuid.uuid4().hex[:12]}",
                                        "name": function.get("name", ""),
                                        "input": {},
                                    },
                                },
                            )
                            next_index += 1
                        index = tool_indexes[call_pos]
                        args_delta = function.get("arguments") or ""
                        if args_delta:
                            tool_arg_buffers[call_pos] += args_delta
        if text_started:
            yield sse_event("content_block_stop", {"type": "content_block_stop", "index": text_index})
        for _, index in sorted(tool_indexes.items(), key=lambda item: item[1]):
            call_pos = next(pos for pos, tool_index in tool_indexes.items() if tool_index == index)
            args, _arg_events = redactor.scan_local_text(tool_arg_buffers.get(call_pos, ""), session_id)
            if args:
                yield sse_event("content_block_delta", {"type": "content_block_delta", "index": index, "delta": {"type": "input_json_delta", "partial_json": args}})
            yield sse_event("content_block_stop", {"type": "content_block_stop", "index": index})
        yield sse_event("message_delta", {"type": "message_delta", "delta": {"stop_reason": stop_reason, "stop_sequence": None}, "usage": {"output_tokens": 0}})
        yield sse_event("message_stop", {"type": "message_stop"})

    async def anthropic_messages(request: Request, authorization: str | None, x_apg_session_id: str | None, x_api_key: str | None = None) -> Response:
        request_id = f"req_{uuid.uuid4().hex[:12]}"
        session_id = authenticate(authorization, x_apg_session_id, x_api_key)
        try:
            body: Any = await request.json()
        except Exception as exc:
            raise HTTPException(status_code=400, detail="Invalid JSON") from exc
        if not isinstance(body, dict):
            raise HTTPException(status_code=400, detail="Invalid Anthropic messages payload")
        sanitized, request_events = redactor.sanitize_json(body, session_id)
        upstream_payload = anthropic_to_openai(sanitized)
        response_model = str(upstream_payload.pop("_apg_requested_model", upstream_payload.get("model", "")))
        endpoint = "/v1/messages"
        audit.log(
            {
                "request_id": request_id,
                "session_id": session_id,
                "workspace_id": cfg.workspace_id,
                "endpoint": endpoint,
                "phase": "request",
                "detections": request_events,
                "detector_diagnostics": redactor.detector_manager.diagnostics(),
                "before_chars": len(str(body)),
                "after_chars": len(str(sanitized)),
            }
        )
        if upstream_payload.get("stream"):
            try:
                status, headers, stream_body = await upstream.stream_request("POST", "/v1/chat/completions", upstream_payload)
            except httpx.HTTPError as exc:
                return _upstream_error_response(exc, audit, request_id, session_id, cfg.workspace_id, endpoint)
            audit.log(
                {
                    "request_id": request_id,
                    "session_id": session_id,
                    "workspace_id": cfg.workspace_id,
                    "endpoint": endpoint,
                    "phase": "response",
                    "status": status,
                    "stream": True,
                    "detections": [],
                }
            )
            return StreamingResponse(openai_stream_to_anthropic(stream_body, session_id, response_model), status_code=status, media_type=headers.get("content-type", "text/event-stream"))
        try:
            status, headers, upstream_body = await upstream.request_json("POST", "/v1/chat/completions", upstream_payload)
        except httpx.HTTPError as exc:
            return _upstream_error_response(exc, audit, request_id, session_id, cfg.workspace_id, endpoint)
        scanned_body, response_events = response_scanner.scan_response_json(upstream_body, session_id)
        anthropic_body = openai_message_to_anthropic(scanned_body, response_model)
        audit.log(
            {
                "request_id": request_id,
                "session_id": session_id,
                "workspace_id": cfg.workspace_id,
                "endpoint": endpoint,
                "phase": "response",
                "status": status,
                "detections": response_events,
            }
        )
        return JSONResponse(anthropic_body, status_code=status, headers=headers)

    @app.get("/v1/models")
    async def models(authorization: str | None = Header(default=None), x_apg_session_id: str | None = Header(default=None), x_api_key: str | None = Header(default=None)) -> Response:
        request_id = f"req_{uuid.uuid4().hex[:12]}"
        session_id = authenticate(authorization, x_apg_session_id, x_api_key)
        try:
            status, headers, body = await upstream.request_json("GET", "/v1/models")
        except httpx.HTTPError as exc:
            return _upstream_error_response(exc, audit, request_id, session_id, cfg.workspace_id, "/v1/models")
        audit.log({"request_id": request_id, "session_id": session_id, "endpoint": "/v1/models", "phase": "models", "status": status})
        return JSONResponse(body, status_code=status, headers=headers)

    @app.post("/v1/chat/completions")
    async def chat_completions(request: Request, authorization: str | None = Header(default=None), x_apg_session_id: str | None = Header(default=None), x_api_key: str | None = Header(default=None)) -> Response:
        return await proxy_json("/v1/chat/completions", request, authorization, x_apg_session_id, x_api_key)

    @app.post("/v1/apg/detect")
    async def apg_detect(request: Request, authorization: str | None = Header(default=None), x_apg_session_id: str | None = Header(default=None), x_api_key: str | None = Header(default=None)) -> Response:
        session_id = authenticate(authorization, x_apg_session_id, x_api_key)
        try:
            body: Any = await request.json()
        except Exception as exc:
            raise HTTPException(status_code=400, detail="Invalid JSON") from exc
        if not isinstance(body, dict) or not isinstance(body.get("text"), str):
            raise HTTPException(status_code=400, detail="Expected JSON body with string field 'text'")
        text = body["text"]
        kind = str(body.get("kind", "text"))
        redactor.detector_manager.reset_diagnostics()
        findings = redactor.detector_manager.scan_findings(text, kind=kind)
        response: dict[str, Any] = {
            "session_id": session_id,
            "preset": redactor.detector_manager.hierarchical.flow.preset,
            "findings": [finding.to_dict() for finding in findings],
            "diagnostics": redactor.detector_manager.diagnostics(),
        }
        if body.get("return_sanitized", True):
            response["sanitized_text"] = _preview_sanitized_text(text, findings)
        audit.log(
            {
                "request_id": f"req_{uuid.uuid4().hex[:12]}",
                "session_id": session_id,
                "workspace_id": cfg.workspace_id,
                "endpoint": "/v1/apg/detect",
                "phase": "detect",
                "detections": [finding.to_dict() for finding in findings],
                "detector_diagnostics": redactor.detector_manager.diagnostics(),
            }
        )
        return JSONResponse(response)

    @app.post("/v1/messages")
    async def messages(request: Request, authorization: str | None = Header(default=None), x_apg_session_id: str | None = Header(default=None), x_api_key: str | None = Header(default=None)) -> Response:
        return await anthropic_messages(request, authorization, x_apg_session_id, x_api_key)

    @app.post("/v1/responses")
    async def responses(request: Request, authorization: str | None = Header(default=None), x_apg_session_id: str | None = Header(default=None), x_api_key: str | None = Header(default=None)) -> Response:
        return await proxy_json("/v1/responses", request, authorization, x_apg_session_id, x_api_key)

    return app


def _preview_sanitized_text(text: str, findings: list[Any]) -> str:
    out: list[str] = []
    cursor = 0
    for finding in sorted(findings, key=lambda f: f.original_start):
        if finding.original_start < cursor:
            continue
        out.append(text[cursor : finding.original_start])
        out.append(f"<APG_DETECTED:{finding.subtype}>")
        cursor = finding.original_end
    out.append(text[cursor:])
    return "".join(out)


def main() -> None:
    import uvicorn

    cfg = load_config()
    uvicorn.run("gateway.server:create_app", host=cfg.bind_host, port=cfg.bind_port, factory=True)


if __name__ == "__main__":
    main()
