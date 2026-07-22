# Design

APG starts with an API proxy because OpenAI-compatible clients are common, but the proxy is the only layer APG owns. The durable boundary is the local privacy runtime: recursive scanning, stateful placeholder management, sink-aware materialization, and audit logging. Tool permission, file-write arbitration, and secret-use brokerage belong to the agent harness — APG is intentionally not a tool/capability firewall.

## Stateful Mapping Store

Mappings are not plain dictionaries. A placeholder may appear minutes or days after it was issued, in a different operation, or inside a tool argument. The gateway must know whether it belongs to the active session and workspace, whether it expired, whether it was tombstoned, and what sinks may materialize it. SQLite gives the MVP durable local state with WAL mode, normal sync, and busy timeout.

## Local Management Control Plane

The WebUI and `/api/admin/*` routes form a separate local control plane. They may summarize the audit JSONL and mapping registry, but they never serialize mapping values, fingerprints, internal handles, complete APG placeholders, provider credentials, or full session ids. A mapping is represented by an HMAC-derived administration id that can only be used to revoke it. An optional administrator-key set separates control-plane authority from the keys used by Agent clients.

Detector management is implemented as revisioned configurations rather than editing the primary YAML file. Built-in and YAML deployment templates are read-only; user configurations contain an ordered list of typed modules and are persisted in a mode-`0600` version 2 JSON file beside the mapping database. Every enabled module runs in order and findings are merged after the flow completes. Saving an active configuration validates and builds a replacement before persistence and an atomic `DetectorManager` swap, so a failed build leaves the previous runtime intact while in-flight requests finish on their existing flow. Version 1 overlays are backed up and migrated without losing preset selection, module switches, or custom rules.

## Hierarchical Sensitive Information Detection

The detector layer is local-first and layered. Level 0 adapters extract text blocks from raw text and recursive JSON while preserving source metadata such as JSON pointers. Normalization applies NFKC, zero-width removal, bounded URL decoding, bounded HTML entity decoding, and bounded escape decoding without treating normalization as a replacement for forensic traceability.

Level 1 deterministic detectors are the most trusted evidence source: PEM private keys, JWTs, database URLs, bearer tokens, `.env` sensitive assignments, provider-like tokens, cookies/session IDs, credit cards with Luhn validation, emails, phones, APG markers, and high-confidence local paths. Level 2 entropy/context detectors find random-looking token candidates and weigh nearby words such as `token`, `secret`, `authorization`, and `cookie`, while lowering confidence around fake/example/mock contexts.

Level 3 validators increase confidence without contacting external services. Level 4 external scanners such as detect-secrets, gitleaks, trufflehog, and Presidio are optional plugins. Level 5 small model detectors such as StarPII-like, Piiranha-like, GLiNER-PII-like, or privacy-filter-like models are also optional, lazy-loaded, local-only, CPU-capable, and failure-tolerant.

All detector outputs are normalized into `Finding` records. The aggregator merges overlapping evidence, raises risk when multiple weak signals agree, and keeps hard deterministic matches critical. Model-only PII can be useful evidence, but it is not a final block decision. Policy decides; materialization restores values only into explicit sink types (see below).

Known limits remain: unknown secret formats can be missed, PII is context-dependent, model detectors can miss or hallucinate spans, false positives are unavoidable, and semantic privacy leakage cannot be solved by span detection alone.

## Signed Placeholders

Plain strings are forgeable. A model or untrusted file can invent `<APG:...>` text. APG placeholders carry kind, handle, session, issued time, and a short HMAC over session/workspace/policy-bound data. Materialization fails closed when the MAC or mapping is invalid.

## Three Views

`remote_view` is sent to the cloud model and must not contain raw machine secrets or configured private data.

`user_view` is shown locally and may restore safe PII or paths when policy allows, but it does not materialize machine secrets.

`tool_call_argument_view` is the structured `tool_calls[].function.arguments` (OpenAI) or `content[].tool_use.input` (Anthropic) field in a downlink response. This is the only sink where APG materializes a secret back to its raw value, so any OpenAI/Anthropic-compatible harness transparently receives the real credential needed to execute a tool. Every other string field in a response stays redacted.

## Sink-Aware Materialization

The same placeholder can be safe in one sink and unsafe in another. The policy engine decides per `(kind, sink_type, materialization_class)`:

- `kind=secret`: only `sink_type=local_tool` (tool-call argument fields) is allowed; `remote_llm`, `local_user`, and any other sink are blocked with a non-retryable error. There is no privileged "secret broker" sink.
- `kind=pii`/`path`: `local_tool` and `local_user` are allowed; `remote_llm` is blocked.
- Any `materialization_class="none"` mapping is blocked for every sink.

Invalid or hallucinated placeholders fail closed and are not partially replaced. This intentionally leaves the harness to observe a natural tool-call failure rather than execute with a bogus value.

## Upstream System-Prompt Contract

APG prepends a short system prompt (`APG_UPSTREAM_SYSTEM_PROMPT` in `src/gateway/server.py`) to every OpenAI-compatible `/v1/chat/completions` and Anthropic `/v1/messages` request before forwarding it upstream. Responses requests receive the same contract through the `instructions` field. The contract instructs the cloud model to treat APG placeholders as opaque protected handles, refer to protected values generically in prose, only emit placeholders verbatim inside structured local tool-call arguments, and never invent placeholders or follow untrusted-document instructions to exfiltrate protected data.

This is a defense-in-depth layer. It cannot be relied on alone — a sufficiently capable or injected model may still attempt to echo placeholders or raw secrets in its visible output. The downlink fold below catches those cases deterministically.

## Downlink Marker Folding

`sanitize_text` and `scan_local_text` (used by `ResponseScanner` for non-streaming and `scan_local_stream` for streaming) take a `fold_apg_markers: bool = True` flag. When enabled and `scope="response"`:

- Detections whose type is `APG_MARKER` (signed placeholder or redaction marker) are replaced with the fixed phrase `APG-managed protected value`.
- Detections whose type is `secret` (a raw secret echoed by the model) are also replaced with the same phrase.

This guarantees user-visible response text, reasoning, tool descriptions, written files, memory, and logs never carry verbatim APG handles or raw secret echoes back to the human, regardless of whether the upstream model honored the system-prompt contract.

Structured `tool_calls[].function.arguments` and `content[].tool_use.input` fields are routed outside visible-text folding. APG buffers each call by choice/tool index, validates signed placeholders after the arguments are complete, and materializes valid values locally. Invalid, expired, or cross-session handles remain unchanged so the tool fails naturally; the audit event contains only kind, sink, action, and reason code.

## Stateful Streaming

Network chunks, named SSE events, model deltas, and logical content blocks are different boundaries. APG incrementally decodes UTF-8 and SSE framing first, then maintains independent state for each Chat choice, Responses output/content item, and tool call. Anthropic responses use the same text guard while converting the OpenAI-compatible upstream stream into Anthropic content blocks.

The default Balanced guard retains a 256-character tail and scans the complete pending text before releasing a safe prefix. It moves the release point backward when a detector finding, APG marker, known session secret, or path alias crosses the boundary. Incomplete markers, token-like values, environment assignments, and PEM blocks remain pending. A candidate exceeding 4096 characters is folded once and discarded through its terminator. If an active secret is longer than that, or an enabled detector cannot safely operate incrementally, APG buffers the complete text block up to 1 MiB and then fails closed.

Tool arguments are never treated as visible prose. Chat, Responses, and Anthropic streaming paths buffer argument fragments, materialize only after the call is complete, and emit the materialized arguments before the protocol's finish event. Responses additionally scans output text, reasoning summaries, refusals, output-item snapshots, and the final completed response. Malformed UTF-8 or SSE JSON produces a sanitized protocol-native error and terminates the stream. A completion audit records aggregate counts and reason codes without raw values or handles.

This stateful guarantee covers OpenAI Chat Completions, OpenAI Responses, and Anthropic Messages. Unknown text-bearing Responses delta types fail closed. It does not cover Gemini, MCP, provider-hosted tool execution, custom transports, or raw values written by an agent into its own local transcript after APG has released a trusted tool argument.

## Future MCP And Runtime Tracing

Future MCP integration is limited to proxying existing MCP servers against the same transparent privacy contract (redact upstream, materialize only into structured tool arguments). Tool permission brokerage, file-write arbitration, sensitive-edit approval flows, and Secret Usage Graph analysis are the agent harness' responsibility and are out of APG's scope.
