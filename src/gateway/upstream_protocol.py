from __future__ import annotations


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

UPSTREAM_PROTOCOL_ENDPOINTS = {
    OPENAI_CHAT_COMPLETIONS: "/v1/chat/completions",
    OPENAI_RESPONSES: "/v1/responses",
    ANTHROPIC_MESSAGES: "/v1/messages",
}
DEFAULT_UPSTREAM_PROTOCOLS = tuple(UPSTREAM_PROTOCOL_ENDPOINTS)


def canonical_upstream_protocol(value: str) -> str:
    normalized = value.strip().lower()
    return LEGACY_UPSTREAM_PROTOCOLS.get(normalized, normalized)


def upstream_protocol_for_path(path: str) -> str:
    normalized = path.rstrip("/")
    for protocol, endpoint in UPSTREAM_PROTOCOL_ENDPOINTS.items():
        if normalized.endswith(endpoint.removeprefix("/v1")) or normalized.endswith(endpoint):
            return protocol
    return ""
