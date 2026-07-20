# Harness Integration Contract

APG is a transparent OpenAI/Anthropic-compatible privacy proxy. It does **not** act as a tool permission broker, file-write firewall, or secret capability layer. An agent harness owns those responsibilities. This document defines what APG guarantees and what the harness must provide.

## What APG guarantees

1. **Upstream redaction.** Any raw secret, PII, or sensitive local path that appears anywhere in the request JSON sent to a `/v1/*` endpoint is replaced with a signed placeholder or alias before forwarding to the upstream model. The cloud LLM never sees the raw value.
2. **Downlink response scanning.** Any secret the model echoes in non-tool response fields (visible text, reasoning, tool descriptions) is redacted again before reaching the harness.
3. **Transparent tool-call materialization.** When the upstream LLM responds with structured `tool_calls[].function.arguments` (OpenAI) or `content[].tool_use.input` (Anthropic) fields that contain APG placeholders, APG materializes the placeholder back to the raw value **only inside those argument fields**. The harness receives `tool_call.arguments` containing the real credential and can execute the tool with it.
4. **Fail-closed for forged placeholders.** Hallucinated or unsigned placeholders anywhere (including in `arguments`) are left intact rather than partially replaced; the harness will normally see a tool call that fails when the bogus value is used.
5. **Per-session HMAC.** Placeholders carry `kind`, `handle_id`, `session_id`, `issued_at`, and a short HMAC over a workspace/session/policy scope. Materialization fails if the MAC, session, workspace, expiry, tombstone state, or sink policy does not match.
6. **Hierarchical path aliases.** Once a workspace path is aliased, descendant paths reuse that parent alias plus a relative suffix. This keeps remote tool context navigable while preserving session/workspace isolation and local restoration.

## What the harness owns

Anything APG does not enforce is explicitly the harness' responsibility. Concretely:

- **Tool permission.** Whether a particular tool may be invoked at all, by which model, in which mode.
- **Domain routing.** Whether `tool_call.arguments` may bind to `https://api.openai.com` vs an attacker-controlled URL. APG does not inspect domains; it materializes the secret regardless of the destination.
- **Outbound execution approval.** Whether the harness executes a materialized tool call, asks the user, or refuses. APG has no approval flow.
- **Tool argument validation.** Whether the JSON arguments are well-formed for the tool's schema.
- **Local file writes.** APG does not gate file writes. If a redacted view of `.env` is shown to the LLM and the LLM proposes writing it back, the harness (or the host VCS / editor) must prevent destructive whole-file overwrite of the original secret.
- **Secret lifecycle and rotation.** APG's mapping store is a short-lived per-session cache. Long-term secret storage, key rotation, and revocation live in the harness' keystore.
- **Local trajectory retention.** A trusted agent may record a tool argument after APG materializes it locally. APG protects upstream/model-visible traffic and final visible text; the harness must apply its own retention and access policy to local trajectories.

## Residual prompt-injection risk

A cloud LLM under prompt injection can return a tool call that points the agent at an attacker-controlled URL with the materialized secret in the arguments. APG materializes by design (the harness needs the real value to run any authenticated tool), so it cannot prevent this. Mitigations must be applied at the harness boundary:

- Gate outbound HTTP from tools before execution.
- Allowlist destination domains per tool.
- Statically bound tool surfaces (rather than freeform `http` tools).
- Human-in-the-loop approval for high-risk tool calls.
- Sandboxed tool execution that blocks exfiltration patterns.

## Storage caveat

To make materialization possible, the APG SQLite mapping store holds the raw secret value for the active session. The database file is created with mode `0600`. Operators must:

- Place `APG_DATABASE_PATH` on encrypted storage (FileVault, LUKS, etc.).
- Restrict filesystem access to the user running APG.
- Delete or rotate `.apg/state.sqlite3` between unrelated sessions.

APG keeps raw values only for the duration allowed by mapping TTLs; expired mappings are tombstoned with `value=NULL`. The `state/gc.py` helper tombstones expired request-scope mappings; regular tombstone sweeps reduce the at-rest footprint of the raw secret cache.

## Endpoint index

- `POST /v1/chat/completions` — OpenAI-compatible proxy
- `POST /v1/responses` — non-streaming and statefully scanned streaming Responses proxy
- `POST /v1/messages` — Anthropic-compatible proxy (OpenAI ↔ Anthropic translation)
- `GET /v1/models` — passthrough models list
- `POST /v1/apg/detect` — dry-run detector inspection

The previous `/v1/apg/capability/{assess,execute,approve}` endpoints, the `apg` `use_secret` MCP tool, and the `apg-approve`/`apg-secret` CLIs have been removed. Tool capability and approval flows now belong to the harness.

## Stable placeholders

```text
<APG:v1:secret:secr_abc123:sess_abcd:1710000000:mac>
<APG:v1:pii:pii_abc123:sess_abcd:1710000000:mac>
<APG:v1:path:path_abc123:sess_abcd:1710000000:mac>
```

The harness should treat any `<APG:v1:...>` marker in non-argument strings as opaque redaction; do not display it to end users and do not echo it back into prompts. Inside materialized `tool_call.arguments`, the placeholder has already been replaced with the raw value and the harness proceeds normally.
