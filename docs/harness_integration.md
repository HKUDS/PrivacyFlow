# Harness Integration Contract

PrivacyFlow is a transparent OpenAI/Anthropic-compatible privacy proxy. It does **not** act as a tool permission broker, file-write firewall, or secret capability layer. An agent harness owns those responsibilities. This document defines what PrivacyFlow guarantees and what the harness must provide.

The WebUI can configure Codex, Claude Code, DeepSeek Harness, and nanobot to use PrivacyFlow endpoints. This convenience changes endpoint, model, and local credential configuration only; it does not expand the traffic or tool-execution boundary described below. DeepSeek Harness integration is endpoint mode, not a native plugin. The current official `@deepseek-ai/dsh` launcher uses `$DSH_HOME/settings.yaml` plus `$DSH_HOME/.credentials.yaml`; PrivacyFlow registers a lowercase `pf` provider with `api: openai-completions`, `apiKeyEnv: PF_DSH_API_KEY`, a PrivacyFlow `/v1` URL, and a complete discovered model list. The key is stored under the referenced credential name, never in `settings.yaml`.

If a target configuration already contains a reserved PrivacyFlow provider, preset, or environment key, the first Quick connect request stops with a conflict and lists the affected paths. PrivacyFlow does not overwrite the files silently. The WebUI then asks for explicit migration confirmation; after confirmation, PrivacyFlow records the complete original bytes and permissions in a private transaction snapshot before replacing the configuration. Cancel leaves the files and credentials unchanged. Once connected, **Restore previous configuration** uses that snapshot to return the target to its exact pre-connect state and revokes the connector key. This confirmation is also exposed to API clients as `confirm_existing_config: true` on the connect request.

## What PrivacyFlow guarantees

1. **Supported textual-field redaction.** Detected secrets, PII, and sensitive local paths in supported request JSON strings are replaced before forwarding. Protocol identifiers and opaque multimodal fields such as `image_url`, `file_data`, audio, image, and screenshot blocks pass through unchanged; unknown formats can also be missed.
2. **Transparent local response restoration.** If the model emits an exact valid PF placeholder in response text, PrivacyFlow restores the original value for the local user. A raw secret echoed directly by the model is still folded, and invalid, forged, expired, revoked, or cross-session placeholders fail closed.
3. **Response-field-classified tool-call materialization.** When the upstream LLM responds with recognized Chat, Responses, or Anthropic tool-argument fields containing PF placeholders, PrivacyFlow materializes them before returning the response. JSON-object formats are decoded and re-serialized; Responses custom-tool text remains protocol text. The `local_tool` classification comes from field shape and is not a permission decision.
4. **Fail-closed where structured JSON is required.** Invalid argument JSON is not materialized through raw string replacement on Chat, Anthropic, and non-streaming structured-object paths. Those paths return a protocol-native safe error or HTTP `502` with `PF_TOOL_ARGUMENTS_INVALID`. Responses streaming argument/input events are buffered and materialized as their native protocol text.
5. **Fail-closed for forged placeholders.** Hallucinated or unsigned placeholders inside otherwise valid arguments are left intact rather than partially replaced; the harness will normally see a tool call that fails when the bogus value is used.
6. **Session-bound HMAC.** Placeholders carry `kind`, `handle_id`, `session_id`, `issued_at`, and a short HMAC over workspace/session/policy-bound data. Materialization fails if the MAC, session, workspace, expiry, tombstone state, or response-field policy does not match.
7. **Hierarchical path aliases.** Once a workspace path is aliased, descendant paths reuse that parent alias plus a relative suffix. This keeps remote tool context navigable while preserving session/workspace isolation and local restoration.

## What the harness owns

Anything PrivacyFlow does not enforce is explicitly the harness' responsibility. Concretely:

- **Tool permission.** Whether a particular tool may be invoked at all, by which model, in which mode.
- **Tool locality.** PrivacyFlow does not prove that a recognized tool-call field will be executed locally; `local_tool` is only an internal field-class label.
- **Domain routing.** Whether `tool_call.arguments` may bind to `https://api.openai.com` vs an attacker-controlled URL. PrivacyFlow does not inspect domains; it materializes the secret regardless of the destination.
- **Outbound execution approval.** Whether the harness executes a materialized tool call, asks the user, or refuses. PrivacyFlow has no approval flow.
- **Tool schema and semantic validation.** PrivacyFlow validates JSON syntax on native paths that require a decoded argument object; the harness still decides whether fields satisfy the selected tool's schema and whether their meaning is safe.
- **Local file writes.** PrivacyFlow does not gate file writes. If a redacted view of `.env` is shown to the LLM and the LLM proposes writing it back, the harness (or the host VCS / editor) must prevent destructive whole-file overwrite of the original secret.
- **Secret lifecycle and rotation.** PrivacyFlow's mapping store is a local runtime cache. Long-term secret storage, key rotation, and revocation live in the harness' keystore.
- **Local response and trajectory retention.** A trusted client may record user-visible text or a tool argument after PrivacyFlow materializes it locally. PrivacyFlow protects upstream/model-visible traffic; the harness must apply its own retention and access policy to local responses and trajectories.

## Residual prompt-injection risk

A cloud LLM under prompt injection can return a tool call that points the agent at an attacker-controlled URL with the materialized secret in the arguments. PrivacyFlow materializes by design (the harness needs the real value to run any authenticated tool), so it cannot prevent this. Mitigations must be applied at the harness boundary:

- Gate outbound HTTP from tools before execution.
- Allowlist destination domains per tool.
- Statically bound tool surfaces (rather than freeform `http` tools).
- Human-in-the-loop approval for high-risk tool calls.
- Sandboxed tool execution that blocks exfiltration patterns.

## Storage caveat

To make materialization possible, the PrivacyFlow SQLite mapping store holds active raw values in plaintext. Provider credentials are likewise stored in the private launcher JSON. PrivacyFlow does not encrypt these files; it creates them with restrictive permissions where supported. Operators must:

- Place `PF_DATABASE_PATH` on encrypted storage (FileVault, LUKS, etc.).
- Restrict filesystem access to the user running PrivacyFlow.
- Delete or rotate `.privacyflow/state.sqlite3` between unrelated sessions.

PrivacyFlow retains raw mapping values locally by default so long-running agents do not lose materialization capability. Administrators can enable a workspace-wide idle duration in the WebUI; expired mappings are then tombstoned with `value=NULL`, while manual revocation remains available at any time. Regular tombstone sweeps only clear mappings with an active deadline.

## Endpoint index

- `POST /v1/chat/completions` — OpenAI-compatible proxy
- `POST /v1/responses` — non-streaming and statefully scanned streaming Responses proxy
- `POST /v1/messages` — native Anthropic Messages proxy
- `GET /v1/models` — upstream model lookup normalized into a client-compatible list
- `POST /v1/pf/detect` — dry-run detector inspection (the old `/v1/apg/detect` route remains a migration alias)

## Stable placeholders

```text
<PF:v1:secret:secr_abc123:sess_abcd:1710000000:mac>
<PF:v1:pii:pii_abc123:sess_abcd:1710000000:mac>
```

The harness should not need to handle `<PF:v1:...>` markers itself. In normal response text, PrivacyFlow has already restored valid same-session placeholders and folded invalid ones. Inside materialized `tool_call.arguments`, valid placeholders have likewise been replaced with raw values before the harness proceeds. Legacy `<APG:v1:...>` markers remain readable during the migration release.
