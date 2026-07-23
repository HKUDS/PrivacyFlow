# Roadmap

## v0.1

- OpenAI-compatible non-streaming API proxy
- Rule-based detectors
- Signed placeholders
- Redaction and pseudonymization
- SQLite mapping store with default-persistent values, configurable idle retention, and tombstones
- Response scanner
- Audit logs
- Basic policy engine
- Transparent tool-call argument materialization

## v0.2

- Rich materialization engine
- Path alias manager with workspace mounts
- Session lifecycle controls
- Tombstones surfaced in API-safe errors
- Low-bandwidth error normalization
- Strict startup mode and configurable PII disposition

## v0.3

- Hardened OpenAI and Anthropic compatibility
- Harness integration fixtures and canary leak contracts
- Safer upstream error normalization and audit diagnostics

## v0.4

- Stateful streaming for Chat Completions, Anthropic Messages, and OpenAI Responses
- Buffered function-call argument materialization across all supported streaming protocols
- Embeddings and file upload scanning

## v0.5

- Local management WebUI for safe audit review, protected-value revocation, and detector configuration
- Authenticated administration API with dedicated-key support
- Revisioned detector configurations with ordered typed modules, read-only templates, atomic hot reload, v1 migration, and local dry runs
- MCP proxy for existing MCP servers against the same transparent privacy contract

## v0.6

- Runtime secret tracing for Python and Node projects
- Harness-side reference policies for domain/tool approval

## v0.7

- `privacy run -- <agent command>` CLI wrapper
- Browser extension or editor integration
