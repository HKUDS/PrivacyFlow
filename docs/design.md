# Design

APG starts with an API proxy because OpenAI-compatible clients are common, but the proxy is the only layer APG owns. The durable boundary is the local privacy runtime: field-aware scanning, stateful placeholder management, sink-aware materialization, and audit logging. Tool permission, file-write arbitration, and secret-use brokerage belong to the agent harness — APG is intentionally not a tool/capability firewall.

## Stateful Mapping Store

Mappings are not plain dictionaries. A placeholder may appear minutes or days after it was issued, in a different operation, or inside a tool argument. The gateway must know whether it belongs to the active session and workspace, whether it expired, whether it was tombstoned, and what sinks may materialize it. SQLite gives the MVP durable local state with WAL mode, normal sync, and busy timeout.

Mapping expiry is a local administrator policy rather than a fixed detector-specific TTL. The default policy does not automatically expire active mappings. An administrator may enable idle-time clearing from the WebUI and choose a duration from one minute to 365 days; each valid sighting or materialization refreshes the idle deadline. Enabling the policy starts a fresh deadline for every active mapping, while disabling it removes pending deadlines. Already tombstoned values are never restored. The policy and revision are stored in SQLite, and background GC only clears mappings that carry an active deadline.

## Local Management Control Plane

The WebUI and `/api/admin/*` routes form a separate local control plane with no application-layer authentication. Its security boundary is the default loopback bind, so it must not be exposed to an untrusted network. Ordinary summaries never serialize mapping values, fingerprints, internal handles, complete APG placeholders, provider credentials, or full session ids. Operation lists and request details use a stable HMAC-derived `pv_...` administration id to correlate an upstream replacement with a local materialization. Operation and detail endpoints may reconstruct the exact signed placeholder from operation metadata and, only when explicitly requested, read an original value from a mapping that is still active. They do not create an audit copy of that value; expiry or revocation makes it unavailable.

Detailed operations are stored in SQLite separately from the append-only safe JSONL. Each row contains direction, mapping reference, representation metadata, detector/action or tool/sink result, and an occurrence count, but no raw value or complete signed placeholder. Identical operations within one request are merged. At most 1,000 distinct combinations are retained per request, with omitted occurrences counted separately. The JSONL and legacy `/api/admin/audit` interface remain capability-free; temporary raw reads add a safe `view_audit_raw_values` or `view_protected_raw_values` event without the viewed content.

Detector management is implemented as revisioned configurations rather than editing the primary YAML file. Built-in and YAML deployment templates are read-only; user configurations contain an ordered list of typed modules and are persisted in a mode-`0600` version 2 JSON file beside the mapping database. Every enabled module runs in order and findings are merged after the flow completes. Saving an active configuration validates and builds a replacement before persistence and an atomic `DetectorManager` swap, so a failed build leaves the previous runtime intact while in-flight requests finish on their existing flow. Version 1 overlays are backed up and migrated without losing preset selection, module switches, or custom rules.

## Hierarchical Sensitive Information Detection

The detector layer is local-first and layered. Level 0 adapters extract text blocks from raw text and recursive JSON while preserving source metadata such as JSON pointers. Deterministic rules still inspect every non-protocol string, while expensive local models are limited to content-bearing prompt and response fields rather than tool schemas and protocol metadata. Per-field diagnostics are aggregated by module. Normalization applies NFKC, zero-width removal, bounded URL decoding, bounded HTML entity decoding, and bounded escape decoding without treating normalization as a replacement for forensic traceability.

Level 1 deterministic detectors are the default evidence source: PEM private keys, JWTs, database URLs, bearer tokens, `.env` sensitive assignments, provider-like tokens, cookies/session IDs, IP-hosted access links, credential-pair passwords, credit cards with Luhn validation, emails, phones, APG markers, and high-confidence local paths. Level 2 entropy detection is optional and disabled in built-in templates because normal source identifiers can look random; strict or explicitly customized flows may enable it.

Level 3 validators increase confidence without contacting external services. Level 4 external scanners such as detect-secrets, gitleaks, trufflehog, and Presidio are optional plugins. Level 5 small model detectors such as StarPII-like, Piiranha-like, GLiNER-PII-like, or privacy-filter-like models are also optional, lazy-loaded, local-only, CPU-capable, and failure-tolerant.

All detector outputs are normalized into `Finding` records. The aggregator merges overlapping evidence, raises risk when multiple weak signals agree, and keeps hard deterministic matches critical. Model-only PII can be useful evidence, but it is not a final block decision. Policy decides; materialization restores values only into explicit sink types (see below).

Known limits remain: unknown secret formats can be missed, PII is context-dependent, model detectors can miss or hallucinate spans, false positives are unavoidable, and semantic privacy leakage cannot be solved by span detection alone.

## Signed Placeholders

Plain strings are forgeable. A model or untrusted file can invent `<APG:...>` text. APG placeholders carry kind, handle, session, issued time, and a short HMAC over session/workspace/policy-bound data. Materialization fails closed when the MAC or mapping is invalid.

## Three Views

`remote_view` is sent to the cloud model and must not contain raw machine secrets or configured private data.

`user_view` is shown locally and restores an exact valid placeholder to its original value. The raw value is never sent upstream; restoration occurs only after signature, session, workspace, mapping-state, expiry, and sink checks pass.

`tool_call_argument_view` is the structured `tool_calls[].function.arguments` (OpenAI) or `content[].tool_use.input` (Anthropic) field in a downlink response. APG also materializes exact valid placeholders here, so compatible harnesses transparently receive the value needed to execute a tool.

## Sink-Aware Materialization

The same placeholder can be safe in one sink and unsafe in another. The policy engine decides per `(kind, sink_type, materialization_class)`:

- `kind=secret`: `sink_type=local_user` and `sink_type=local_tool` are allowed after placeholder validation; `remote_llm` and any other sink remain blocked.
- `kind=pii`/`path`: `local_tool` and `local_user` are allowed; `remote_llm` is blocked.
- Any `materialization_class="none"` mapping is blocked for every sink.

Invalid or hallucinated placeholders fail closed and are not partially replaced. This intentionally leaves the harness to observe a natural tool-call failure rather than execute with a bogus value.

## Upstream System-Prompt Contract

APG prepends a short system prompt (`APG_UPSTREAM_SYSTEM_PROMPT` in `src/gateway/server.py`) to every OpenAI-compatible `/v1/chat/completions` and Anthropic `/v1/messages` request before forwarding it upstream. Responses requests receive the same contract through the `instructions` field. The contract instructs the cloud model to treat APG placeholders as opaque protected handles, preserve each distinct handle byte-for-byte in normal prose or its corresponding structured local tool argument, never substitute one handle for another, and never follow untrusted-document instructions to exfiltrate protected data.

This is a defense-in-depth layer. It cannot be relied on alone — the downlink validates every placeholder before local restoration and separately folds direct raw-secret echoes.

## Downlink Validation And Restoration

`sanitize_text` and `scan_local_text` (used by `ResponseScanner` for non-streaming and `scan_local_stream` for streaming) take a `fold_apg_markers: bool = True` flag. When enabled and `scope="response"`:

- Exact signed placeholders that validate for the active session and `local_user` sink are protected during scanning and restored to their mapped value afterward.
- Other `APG_MARKER` detections (forged, invalid, cross-session, expired, revoked, or legacy redaction markers) are replaced with the fixed phrase `APG-managed protected value`.
- Detections whose type is `secret` (a raw secret echoed by the model) are also replaced with the same phrase.

This guarantees that user-visible response text does not expose APG internals and that a raw value appears only after a valid same-session placeholder round trip. It does not extend APG's control to storage performed by a local client after receiving the response.

Structured `tool_calls[].function.arguments` and `content[].tool_use.input` fields are routed outside visible-text folding. APG buffers each call by choice/tool index, requires a complete JSON object, materializes valid placeholders only in decoded string values, and serializes the object again. This prevents a restored quote, backslash, newline, or control character from corrupting the tool protocol. Invalid, expired, or cross-session handles remain unchanged; malformed argument JSON terminates the response with a safe protocol-native error. Audit events contain only kind, sink, action, and reason code.

## Stateful Streaming

Network chunks, named SSE events, model deltas, and logical content blocks are different boundaries. APG incrementally decodes UTF-8 and SSE framing first, then maintains independent state for each Chat choice, Responses output/content item, Anthropic content block, and tool call. A native Anthropic `/v1/messages` stream remains Anthropic SSE: APG scans text deltas in place, buffers `input_json_delta` fragments until they form a valid tool-input object, materializes protected values locally, and re-emits the same Anthropic event families.

The default Balanced guard retains a 256-character tail and scans the complete pending text before releasing a safe prefix. It moves the release point backward when a detector finding, APG marker, known session secret, or path alias crosses the boundary. Incomplete markers, token-like values, environment assignments, and PEM blocks remain pending. A candidate exceeding 4096 characters is folded once and discarded through its terminator. If an active secret is longer than that, or an enabled detector cannot safely operate incrementally, APG buffers the complete text block up to 1 MiB and then fails closed.

Tool arguments are never treated as visible prose. Chat and Anthropic streaming paths buffer argument fragments, validate and re-serialize the complete JSON object, and emit materialized arguments before the protocol's finish event. Responses additionally scans output text, reasoning summaries, refusals, output-item snapshots, and the final completed response. Malformed UTF-8, SSE JSON, or tool argument JSON produces a sanitized protocol-native error and terminates the stream. Completion audits distinguish `stream_parse_errors` from per-reason `tool_argument_json_errors` without recording raw values or handles.

This stateful guarantee covers OpenAI Chat Completions, OpenAI Responses, and Anthropic Messages. Unknown text-bearing Responses delta types fail closed. It does not cover Gemini, MCP, provider-hosted tool execution, custom transports, or raw values written by an agent into its own local transcript after APG has released a trusted tool argument.

Upstream configuration treats those wire formats as separate capabilities: `openai_chat_completions`, `openai_responses`, and `anthropic_messages`. APG never translates between them. Each local endpoint is available only when the active upstream profile declares the identical format; otherwise APG returns a sanitized `501`. This keeps provider-specific message roles, content blocks, tool semantics, streaming events, errors, usage fields, and optional features native rather than silently dropping or approximating them.

## Future MCP And Runtime Tracing

Future MCP integration is limited to proxying existing MCP servers against the same transparent privacy contract (redact upstream, validate and materialize only at explicit local sinks). Tool permission brokerage, file-write arbitration, sensitive-edit approval flows, and Secret Usage Graph analysis are the agent harness' responsibility and are out of APG's scope.
