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


def canonical_upstream_protocol(value: str) -> str:
    normalized = value.strip().lower()
    return LEGACY_UPSTREAM_PROTOCOLS.get(normalized, normalized)
