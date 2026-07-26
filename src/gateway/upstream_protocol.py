from __future__ import annotations

import json
import time
import uuid
from collections.abc import AsyncIterator
from typing import Any

from gateway.redaction_engine import iter_sse_data


OPENAI_CHAT_COMPLETIONS = "openai_chat_completions"
OPENAI_RESPONSES = "openai_responses"
ANTHROPIC_MESSAGES = "anthropic_messages"
SUPPORTED_UPSTREAM_PROTOCOLS = frozenset(
    {
        OPENAI_CHAT_COMPLETIONS,
        OPENAI_RESPONSES,
        ANTHROPIC_MESSAGES,
    }
)
LEGACY_UPSTREAM_PROTOCOLS = {
    "openai": OPENAI_CHAT_COMPLETIONS,
    "anthropic": ANTHROPIC_MESSAGES,
}


def canonical_upstream_protocol(value: str) -> str:
    normalized = value.strip().lower()
    return LEGACY_UPSTREAM_PROTOCOLS.get(normalized, normalized)


def openai_chat_to_anthropic(payload: dict[str, Any]) -> dict[str, Any]:
    system_parts: list[str] = []
    messages: list[dict[str, Any]] = []

    def append_message(role: str, content: list[dict[str, Any]]) -> None:
        if not content:
            return
        if messages and messages[-1]["role"] == role:
            previous = messages[-1]["content"]
            if isinstance(previous, list):
                previous.extend(content)
                return
        messages.append({"role": role, "content": content})

    for message in payload.get("messages") or []:
        if not isinstance(message, dict):
            continue
        role = str(message.get("role") or "")
        if role in {"system", "developer"}:
            text = _openai_content_text(message.get("content"))
            if text:
                system_parts.append(text)
            continue
        if role == "tool":
            append_message(
                "user",
                [
                    {
                        "type": "tool_result",
                        "tool_use_id": str(message.get("tool_call_id") or ""),
                        "content": _openai_content_text(message.get("content")),
                    }
                ],
            )
            continue
        if role == "assistant":
            blocks = _openai_content_blocks(message.get("content"))
            for call in message.get("tool_calls") or []:
                if not isinstance(call, dict):
                    continue
                function = call.get("function") or {}
                if not isinstance(function, dict):
                    continue
                arguments = function.get("arguments")
                try:
                    tool_input = json.loads(arguments or "{}") if isinstance(arguments, str) else arguments
                except (TypeError, ValueError):
                    tool_input = {}
                if not isinstance(tool_input, dict):
                    tool_input = {}
                blocks.append(
                    {
                        "type": "tool_use",
                        "id": str(call.get("id") or f"toolu_{uuid.uuid4().hex[:20]}"),
                        "name": str(function.get("name") or ""),
                        "input": tool_input,
                    }
                )
            append_message("assistant", blocks)
            continue
        append_message("user" if role not in {"user", "assistant"} else role, _openai_content_blocks(message.get("content")))

    converted: dict[str, Any] = {
        "model": str(payload.get("model") or ""),
        "max_tokens": int(payload.get("max_tokens") or 4096),
        "messages": messages,
        "stream": bool(payload.get("stream")),
    }
    if system_parts:
        converted["system"] = "\n\n".join(system_parts)
    for source, target in (
        ("temperature", "temperature"),
        ("top_p", "top_p"),
    ):
        if source in payload:
            converted[target] = payload[source]
    if "stop" in payload:
        stop = payload["stop"]
        converted["stop_sequences"] = [stop] if isinstance(stop, str) else stop

    tools: list[dict[str, Any]] = []
    for tool in payload.get("tools") or []:
        if not isinstance(tool, dict):
            continue
        function = tool.get("function") if tool.get("type") == "function" else tool
        if not isinstance(function, dict) or not function.get("name"):
            continue
        tools.append(
            {
                "name": function["name"],
                "description": function.get("description", ""),
                "input_schema": function.get("parameters") or function.get("input_schema") or {"type": "object", "properties": {}},
            }
        )
    choice = payload.get("tool_choice")
    if tools and choice != "none":
        converted["tools"] = tools

    if choice == "required":
        converted["tool_choice"] = {"type": "any"}
    elif choice == "auto":
        converted["tool_choice"] = {"type": "auto"}
    elif isinstance(choice, dict):
        function = choice.get("function") or {}
        if choice.get("type") == "function" and isinstance(function, dict) and function.get("name"):
            converted["tool_choice"] = {"type": "tool", "name": function["name"]}
    return converted


def anthropic_message_to_openai(body: dict[str, Any]) -> dict[str, Any]:
    if body.get("type") == "error":
        error = body.get("error") or {}
        return {
            "error": {
                "message": str(error.get("message") or "Anthropic upstream error"),
                "type": str(error.get("type") or "api_error"),
            }
        }

    text_parts: list[str] = []
    tool_calls: list[dict[str, Any]] = []
    for block in body.get("content") or []:
        if not isinstance(block, dict):
            continue
        if block.get("type") == "text":
            text_parts.append(str(block.get("text") or ""))
        elif block.get("type") == "tool_use":
            tool_calls.append(
                {
                    "id": str(block.get("id") or f"call_{uuid.uuid4().hex[:12]}"),
                    "type": "function",
                    "function": {
                        "name": str(block.get("name") or ""),
                        "arguments": json.dumps(block.get("input") or {}, ensure_ascii=False, allow_nan=False),
                    },
                }
            )

    message: dict[str, Any] = {"role": "assistant", "content": "".join(text_parts) or None}
    if tool_calls:
        message["tool_calls"] = tool_calls
    stop_reason = body.get("stop_reason")
    finish_reason = {
        "tool_use": "tool_calls",
        "max_tokens": "length",
        "end_turn": "stop",
        "stop_sequence": "stop",
        "refusal": "stop",
    }.get(stop_reason, "stop")
    usage = body.get("usage") or {}
    prompt_tokens = int(usage.get("input_tokens") or 0)
    completion_tokens = int(usage.get("output_tokens") or 0)
    return {
        "id": str(body.get("id") or f"chatcmpl_{uuid.uuid4().hex[:20]}"),
        "object": "chat.completion",
        "created": int(time.time()),
        "model": str(body.get("model") or ""),
        "choices": [{"index": 0, "message": message, "finish_reason": finish_reason}],
        "usage": {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": prompt_tokens + completion_tokens,
        },
    }


async def anthropic_stream_to_openai(chunks: AsyncIterator[bytes]) -> AsyncIterator[bytes]:
    message_id = f"chatcmpl_{uuid.uuid4().hex[:20]}"
    model = ""
    created = int(time.time())
    tool_indexes: dict[int, int] = {}
    next_tool_index = 0
    finish_sent = False
    input_tokens = 0
    output_tokens = 0

    def event(delta: dict[str, Any], finish_reason: str | None = None, *, usage: dict[str, Any] | None = None) -> bytes:
        payload: dict[str, Any] = {
            "id": message_id,
            "object": "chat.completion.chunk",
            "created": created,
            "model": model,
            "choices": [{"index": 0, "delta": delta, "finish_reason": finish_reason}],
        }
        if usage is not None:
            payload["usage"] = usage
        return f"data: {json.dumps(payload, ensure_ascii=False)}\n\n".encode("utf-8")

    try:
        async for data in iter_sse_data(chunks):
            payload = json.loads(data)
            if not isinstance(payload, dict):
                raise ValueError("invalid Anthropic SSE payload")
            event_type = payload.get("type")
            if event_type == "ping":
                continue
            if event_type == "error":
                error = payload.get("error") or {}
                safe_error = {
                    "error": {
                        "message": "Anthropic upstream stream error",
                        "type": str(error.get("type") or "api_error"),
                    }
                }
                yield f"data: {json.dumps(safe_error, ensure_ascii=False)}\n\n".encode("utf-8")
                yield b"data: [DONE]\n\n"
                return
            if event_type == "message_start":
                message = payload.get("message") or {}
                message_id = str(message.get("id") or message_id)
                model = str(message.get("model") or model)
                usage = message.get("usage") or {}
                input_tokens = int(usage.get("input_tokens") or 0)
                yield event({"role": "assistant"})
                continue
            if event_type == "content_block_start":
                block_index = int(payload.get("index") or 0)
                block = payload.get("content_block") or {}
                if block.get("type") == "text":
                    initial = str(block.get("text") or "")
                    if initial:
                        yield event({"content": initial})
                elif block.get("type") == "tool_use":
                    call_index = next_tool_index
                    next_tool_index += 1
                    tool_indexes[block_index] = call_index
                    initial_input = block.get("input") or {}
                    initial_arguments = "" if not initial_input else json.dumps(initial_input, ensure_ascii=False, allow_nan=False)
                    yield event(
                        {
                            "tool_calls": [
                                {
                                    "index": call_index,
                                    "id": str(block.get("id") or f"call_{uuid.uuid4().hex[:12]}"),
                                    "type": "function",
                                    "function": {
                                        "name": str(block.get("name") or ""),
                                        "arguments": initial_arguments,
                                    },
                                }
                            ]
                        }
                    )
                continue
            if event_type == "content_block_delta":
                block_index = int(payload.get("index") or 0)
                delta = payload.get("delta") or {}
                if delta.get("type") == "text_delta":
                    yield event({"content": str(delta.get("text") or "")})
                elif delta.get("type") == "input_json_delta":
                    call_index = tool_indexes.get(block_index)
                    if call_index is None:
                        raise ValueError("tool delta arrived before tool block")
                    yield event(
                        {
                            "tool_calls": [
                                {
                                    "index": call_index,
                                    "function": {"arguments": str(delta.get("partial_json") or "")},
                                }
                            ]
                        }
                    )
                continue
            if event_type == "message_delta":
                delta = payload.get("delta") or {}
                usage = payload.get("usage") or {}
                output_tokens = int(usage.get("output_tokens") or output_tokens)
                finish_reason = {
                    "tool_use": "tool_calls",
                    "max_tokens": "length",
                    "end_turn": "stop",
                    "stop_sequence": "stop",
                    "refusal": "stop",
                }.get(delta.get("stop_reason"), "stop")
                yield event(
                    {},
                    finish_reason,
                    usage={
                        "prompt_tokens": input_tokens,
                        "completion_tokens": output_tokens,
                        "total_tokens": input_tokens + output_tokens,
                    },
                )
                finish_sent = True
                continue
            if event_type == "message_stop":
                if not finish_sent:
                    yield event({}, "stop")
                yield b"data: [DONE]\n\n"
                return
    except (TypeError, ValueError, json.JSONDecodeError):
        safe_error = {"error": {"message": "The Anthropic upstream stream could not be parsed safely.", "type": "api_error"}}
        yield f"data: {json.dumps(safe_error)}\n\n".encode("utf-8")
        yield b"data: [DONE]\n\n"
        return
    if not finish_sent:
        yield event({}, "stop")
    yield b"data: [DONE]\n\n"


def _openai_content_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    return "".join(block.get("text", "") for block in _openai_content_blocks(content) if block.get("type") == "text")


def _openai_content_blocks(content: Any) -> list[dict[str, Any]]:
    if isinstance(content, str):
        return [{"type": "text", "text": content}] if content else []
    if not isinstance(content, list):
        return []
    blocks: list[dict[str, Any]] = []
    for item in content:
        if not isinstance(item, dict):
            continue
        if item.get("type") in {"text", "input_text"}:
            blocks.append({"type": "text", "text": str(item.get("text") or "")})
        elif item.get("type") == "image_url":
            image = item.get("image_url")
            url = image.get("url") if isinstance(image, dict) else image
            if isinstance(url, str) and url:
                blocks.append({"type": "image", "source": {"type": "url", "url": url}})
    return blocks
