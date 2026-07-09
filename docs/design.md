# Design

APG starts with an API proxy because OpenAI-compatible clients are common, but the proxy is the only layer APG owns. The durable boundary is the local privacy runtime: recursive scanning, stateful placeholder management, sink-aware materialization, and audit logging. Tool permission, file-write arbitration, and secret-use brokerage belong to the agent harness — APG is intentionally not a tool/capability firewall.

## Stateful Mapping Store

Mappings are not plain dictionaries. A placeholder may appear minutes or days after it was issued, in a different operation, or inside a tool argument. The gateway must know whether it belongs to the active session and workspace, whether it expired, whether it was tombstoned, and what sinks may materialize it. SQLite gives the MVP durable local state with WAL mode, normal sync, and busy timeout.

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

## Future MCP And Runtime Tracing

Future MCP integration is limited to proxying existing MCP servers against the same transparent privacy contract (redact upstream, materialize only into structured tool arguments). Tool permission brokerage, file-write arbitration, sensitive-edit approval flows, and Secret Usage Graph analysis are the agent harness' responsibility and are out of APG's scope.
