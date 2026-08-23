# Design

PrivacyFlow is a protocol-aware local reverse proxy for OpenAI Chat Completions, OpenAI Responses, and Anthropic Messages. The runtime owns textual-field scanning, stateful placeholder management, response-field-classified materialization, and audit logging. Tool permission, file-write arbitration, and secret-use brokerage belong to the agent harness — PrivacyFlow is intentionally not a tool/capability firewall.

## Stateful Mapping Store

Mappings are not plain dictionaries. A placeholder may appear minutes or days after it was issued, in a different operation, or inside a tool argument. The gateway must know whether it belongs to the active session and workspace, whether it expired, whether it was tombstoned, and which recognized response-field class is being processed. SQLite gives the MVP durable local state with WAL mode, normal sync, and busy timeout. Active raw mapping values are stored as local plaintext; mode `0600` filesystem permissions, OS-account isolation, and encrypted host storage are the confidentiality boundary for the database at rest.

Mapping expiry is a local administrator policy rather than a fixed detector-specific TTL. The default policy does not automatically expire active mappings. An administrator may enable idle-time clearing from the WebUI and choose a duration from one minute to 365 days; each valid sighting or materialization refreshes the idle deadline. Enabling the policy starts a fresh deadline for every active mapping, while disabling it removes pending deadlines. Already tombstoned values are never restored. The policy and revision are stored in SQLite; background GC tombstones active mappings only when they carry an expired deadline, then removes non-secret tombstone metadata after the configured history-retention period.

## Local Management Control Plane

The WebUI and `/api/admin/*` routes form a separate local control plane with no application-layer authentication. They are registered only when PrivacyFlow binds to a loopback address; every request also requires a loopback socket peer and loopback `Host`, and a supplied browser `Origin` must be loopback on the same port. This prevents a non-loopback bind or DNS rebinding from exposing the management plane. Ordinary summaries never serialize mapping values, fingerprints, internal handles, complete PF placeholders, provider credentials, or full session ids. Operation lists and request details use a stable HMAC-derived `pv_...` administration id to correlate an upstream replacement with a local materialization. Operation and detail endpoints may reconstruct the exact signed placeholder from operation metadata and, only when explicitly requested, read an original value from a mapping that is still active. They do not create an audit copy of that value; expiry or revocation makes it unavailable.

Detailed operations are stored in SQLite separately from the safe JSONL. Each row contains direction, mapping reference, representation metadata, detector/action or tool/sink result, and an occurrence count, but no raw value or complete signed placeholder. Identical operations within one request are merged. At most 1,000 distinct combinations are retained per request, with omitted occurrences counted separately. JSONL files rotate at 16 MiB with five mode-`0600` backups by default; SQLite operation rows and mapping tombstones are removed after 30 days by background GC. These bounds are configurable. The JSONL and `/api/admin/audit` interface remain capability-free; temporary raw reads add a safe `view_audit_raw_values` or `view_protected_raw_values` event without the viewed content.

Detector management uses revisioned configurations rather than editing the primary
YAML file. Built-in and YAML deployment templates are read-only; user
configurations contain an ordered list of typed modules and are stored in a
mode-`0600` JSON file beside the mapping database. Every enabled module runs in
order and findings are merged after the flow completes. Saving an active
configuration validates and builds a replacement before persistence and an atomic
`DetectorManager` swap, so a failed build leaves the previous runtime active.
User-authored and deployment-authored regex modules use a timeout-capable engine
with a bounded default match time. Matching is not delegated to an uncancellable
executor thread; a timeout follows the module's fail-open/fail-closed policy
without leaving a worker that can block shutdown.

The explicit `privacyflow migrate` command copies valid legacy detector state,
including custom configurations, into `.privacyflow/` and upgrades that copied
state into the PF namespace. It also creates a separate, hash-verified read-only
backup at `.apg.legacy/<timestamp>/`. The original `.apg/` tree remains untouched
and available until the operator chooses to remove it; migration does not move,
edit, or delete the original state. Malformed or unsupported state is ignored at
startup and safely falls back to built-in defaults rather than making the gateway
unavailable.

## Hierarchical Sensitive Information Detection

The detector layer is local-first and layered. Request and response walkers
recursively inspect supported string values and classify them as prompt/response
content, tool schema, or protocol metadata. Protocol identifiers and opaque
multimodal containers or fields (`image_url`, `file_data`, audio, image, screenshot,
and related blocks) bypass scanning to preserve the wire contract. Deterministic
built-in rules inspect the remaining strings; verified local models can be selected
by optional local-model modules. Per-field diagnostics are aggregated by the active pipeline.
Normalization applies NFKC, zero-width removal, bounded URL decoding, bounded HTML
entity decoding, and bounded escape decoding without treating normalization as a
replacement for forensic traceability. Expensive local-model modules are limited
to content-bearing prompt and response fields.

The built-in rules cover PEM private keys, JWTs, database URLs, bearer
tokens, `.env` sensitive assignments, provider-like tokens, cookies/session IDs,
IP-hosted access links, credential-pair passwords, credit cards with Luhn
validation, emails, phones, PF markers, and high-confidence local paths. Local
model artifacts can be inspected, prepared, validated, and selected by an optional
local-model detector module through the WebUI.

All detector outputs are normalized into `Finding` records. The aggregator merges overlapping evidence, raises risk when multiple weak signals agree, and keeps hard deterministic matches critical. Risk and detector `suggested_action` values are evidence and audit metadata. The current `PolicyEngine` replaces every detected secret, including findings marked `block`; it does not reject the complete upstream request on that action.

Known limits remain: unknown secret formats can be missed, PII is context-dependent,
false positives are unavoidable, and semantic privacy leakage cannot be solved by
span detection alone.

## Signed Placeholders

Plain strings are forgeable. A model or untrusted file can invent `<PF:...>` text. PrivacyFlow placeholders carry kind, handle, session, issued time, and a short HMAC over session/workspace/policy-bound data. Materialization fails closed when the MAC or mapping is invalid. Legacy APG placeholders remain readable during the migration release.

## Three Views

`remote_view` is sent to the cloud model after supported textual fields are scanned. Detection misses, skipped protocol identifiers, and opaque multimodal payload fields can still contain raw data.

`user_view` is the ordinary response text returned to the local Agent client. The implementation labels this field class `local_user` and restores an exact valid placeholder after signature, session, workspace, mapping-state, expiry, and policy checks pass. It is not a separately authenticated human-only channel.

`tool_call_argument_view` is a recognized structured tool-call argument field in a downlink response. The implementation labels this field class `local_tool` and materializes exact valid placeholders before returning the response to the Agent. PrivacyFlow does not establish that the named tool is local, authorized, or safe, and it does not execute the tool.

## Response-Field-Classified Materialization

The policy engine receives `(kind, sink_type, materialization_class)`, but the current proxy derives `sink_type` from response shape rather than from a capability or tool-authorization system:

- `kind=secret`: `sink_type=local_user` and `sink_type=local_tool` are allowed after placeholder validation; `remote_llm` and any other sink remain blocked.
- `kind=pii`/`path`: `local_tool` and `local_user` are allowed; `remote_llm` is blocked.
- Any `materialization_class="none"` mapping is blocked for every sink.

Invalid or hallucinated placeholders fail closed and are not partially replaced. This intentionally leaves the harness to observe a natural tool-call failure rather than execute with a bogus value.

These rules are not per-tool allowlists. Tool identity, destination-domain checks, user approval, and execution policy remain entirely outside PrivacyFlow.

## Upstream System-Prompt Contract

PrivacyFlow prepends a short system prompt (`PF_UPSTREAM_SYSTEM_PROMPT` in `src/gateway/server.py`) to every OpenAI-compatible `/v1/chat/completions` and Anthropic `/v1/messages` request before forwarding it upstream. Responses requests receive the same contract through the `instructions` field. The contract instructs the cloud model to treat PF placeholders as opaque protected handles, preserve each distinct handle byte-for-byte in normal prose or its corresponding structured local tool argument, never substitute one handle for another, and never follow untrusted-document instructions to exfiltrate protected data.

This is a defense-in-depth layer. It cannot be relied on alone — the downlink validates every placeholder before local restoration and separately folds direct raw-secret echoes.

## Downlink Validation And Restoration

`sanitize_text` and `scan_local_text` (used by `ResponseScanner` for non-streaming and `scan_local_stream` for streaming) take a `fold_apg_markers: bool = True` flag. The name is a migration-release compatibility alias: when enabled and `scope="response"`, both PF and legacy APG markers are handled:

- Exact signed placeholders that validate for the active session and `local_user` sink are protected during scanning and restored to their mapped value afterward.
- Other `PF_MARKER` detections (forged, invalid, cross-session, expired, or revoked markers) are replaced with the fixed phrase `PrivacyFlow-managed protected value`. Legacy APG marker names are accepted during migration.
- Detections whose type is `secret` (a raw secret echoed by the model) are also replaced with the same phrase.

This prevents valid PrivacyFlow internals from remaining visible and folds raw values that the active detector recognizes as `secret`. Raw PII and paths may remain visible in the local response by design, and unknown secret formats can still be missed. PrivacyFlow does not control storage performed by a local client after receiving the response.

Recognized Chat `tool_calls[].function.arguments`, Anthropic `content[].tool_use.input`, and Responses function/custom-tool argument fields are routed outside visible-text folding. Non-streaming structured argument objects are decoded and re-serialized where the native format requires JSON; Chat and Anthropic streaming paths likewise buffer and validate complete argument objects. Responses streaming argument/input events are buffered as protocol text and materialized after completion. Invalid, expired, or cross-session handles remain unchanged. Malformed JSON in formats that require a decoded object terminates the response with a safe protocol-native error. Audit events contain only kind, field-class label, action, and reason code.

## Stateful Streaming

Network chunks, named SSE events, model deltas, and logical content blocks are different boundaries. PrivacyFlow incrementally decodes UTF-8 and SSE framing first, then maintains independent state for each Chat choice, Responses output/content item, Anthropic content block, and tool call. A native Anthropic `/v1/messages` stream remains Anthropic SSE: PrivacyFlow scans text deltas in place, buffers `input_json_delta` fragments until they form a valid tool-input object, materializes protected values locally, and re-emits the same Anthropic event families.

The default Balanced guard retains a 256-character tail and scans the complete pending text before releasing a safe prefix. It moves the release point backward when a detector finding, PF marker, known session secret, or path alias crosses the boundary. Incomplete markers, token-like values, environment assignments, and PEM blocks remain pending. A candidate exceeding 4096 characters is folded once and discarded through its terminator. If an active secret is longer than that, or the active flow cannot safely operate incrementally (`stream_safe` is false), PrivacyFlow buffers the complete text block up to 1 MiB and then fails closed.

Tool arguments are not treated as visible prose. Chat and Anthropic streaming paths buffer argument fragments, validate and re-serialize the complete JSON object, and emit materialized arguments before the protocol's finish event. Responses buffers its function/custom-tool argument text and also scans output text, reasoning summaries, refusals, output-item snapshots, and the final completed response. Malformed UTF-8 or SSE JSON produces a sanitized protocol-native error; malformed tool JSON is rejected on paths that require JSON decoding. Completion audits do not record raw values or handles.

This stateful guarantee covers OpenAI Chat Completions, OpenAI Responses, and Anthropic Messages. Unknown text-bearing Responses delta types fail closed. It does not cover Gemini, MCP, provider-hosted tool execution, custom transports, or raw values written by an agent into its own local transcript after PrivacyFlow has released a trusted tool argument.

Every upstream profile optimistically exposes `openai_chat_completions`, `openai_responses`, and `anthropic_messages` while sharing one Base URL and credential. PrivacyFlow selects the native upstream route from the incoming local endpoint and never translates between formats. If the provider does not implement that route, its actual upstream error is returned. This keeps provider-specific message roles, content blocks, tool semantics, streaming events, errors, usage fields, and optional features native rather than silently dropping or approximating them.

## Future MCP And Runtime Tracing

Future MCP integration is limited to proxying existing MCP servers against the same transparent privacy contract (scan supported upstream text and validate handles in recognized local response fields). Tool permission brokerage, file-write arbitration, sensitive-edit approval flows, and Secret Usage Graph analysis are the agent harness' responsibility and are out of PrivacyFlow's scope.
