# Agent Privacy Gateway

Agent Privacy Gateway is a local privacy/security runtime for cloud AI agents. It sits between OpenAI-compatible local clients and an upstream model provider, recursively scans request JSON, replaces sensitive content with aliases or signed placeholders, scans responses, writes audit-safe logs, and keeps state in SQLite.

It is not another agent, and it is not a plugin for a single agent. The MVP is an OpenAI-compatible API proxy that can later grow into MCP proxying, SDK middleware, and CLI wrapping. Tool permission brokerage and file-write firewalls are intentionally left to the agent harness — APG only redacts upstream material and restores secrets into structured `tool_call` argument fields on the downlink so any OpenAI/Anthropic-compatible harness can use authenticated tools transparently.

## Why Stateful

A stateless text filter can redact strings, but it cannot safely answer later questions like:

- Did this placeholder come from this gateway session?
- Is the mapping still active, expired, revoked, or tombstoned?
- May this value be materialized for a local tool, a user response, an audit log, or a remote provider?
- Is this placeholder forged text, or a signed value issued by this APG instance?

APG uses signed placeholders, scoped mappings, session identity, TTLs, tombstones, sink-aware materialization policy. The write-firewall / leases / capability broker modules have been removed; those responsibilities moved to the agent harness.

## Current MVP

- `POST /v1/chat/completions`
- `GET /v1/models`
- `POST /v1/responses` basic non-streaming proxy support
- Recursive scanning of any JSON string field
- Rule-based detectors for common API keys, JWTs, private keys, database URLs, bearer tokens, env secrets, emails, phones, credit cards, and high-confidence local paths
- Signed APG placeholders using HMAC
- SQLite mapping registry with WAL, `synchronous=NORMAL`, and busy timeout
- Response scanning
- Audit logs without raw machine secrets
- Transparent materialization of signed placeholders only inside structured local tool-call argument fields

## Project Layout

- [src/gateway/server.py](/Users/howard/Documents/code/Agent-Privacy-Gateway/src/gateway/server.py): FastAPI app and OpenAI-compatible local endpoints.
- [src/gateway/request_adapter.py](/Users/howard/Documents/code/Agent-Privacy-Gateway/src/gateway/request_adapter.py), [src/gateway/upstream_client.py](/Users/howard/Documents/code/Agent-Privacy-Gateway/src/gateway/upstream_client.py): provider request/response plumbing.
- [src/gateway/detectors/](/Users/howard/Documents/code/Agent-Privacy-Gateway/src/gateway/detectors): layered local sensitive-information detection.
- [src/gateway/redaction_engine.py](/Users/howard/Documents/code/Agent-Privacy-Gateway/src/gateway/redaction_engine.py), [src/gateway/response_scanner.py](/Users/howard/Documents/code/Agent-Privacy-Gateway/src/gateway/response_scanner.py): upstream redaction and downstream response scanning.
- [src/gateway/mapping_store.py](/Users/howard/Documents/code/Agent-Privacy-Gateway/src/gateway/mapping_store.py), [src/gateway/materialization_engine.py](/Users/howard/Documents/code/Agent-Privacy-Gateway/src/gateway/materialization_engine.py), [src/gateway/placeholder_parser.py](/Users/howard/Documents/code/Agent-Privacy-Gateway/src/gateway/placeholder_parser.py): signed placeholder lifecycle and tool-call argument materialization.
- [src/gateway/policy_engine.py](/Users/howard/Documents/code/Agent-Privacy-Gateway/src/gateway/policy_engine.py), [src/gateway/audit_logger.py](/Users/howard/Documents/code/Agent-Privacy-Gateway/src/gateway/audit_logger.py), [src/gateway/config.py](/Users/howard/Documents/code/Agent-Privacy-Gateway/src/gateway/config.py): local policy, safe audit logging, and configuration.
- [docs/](/Users/howard/Documents/code/Agent-Privacy-Gateway/docs): design notes, threat model, harness integration contract, roadmap, and validation notes.
- [e2e_agent_tests/](/Users/howard/Documents/code/Agent-Privacy-Gateway/e2e_agent_tests): deterministic and real-upstream realistic agent scenarios.
- [tests/](/Users/howard/Documents/code/Agent-Privacy-Gateway/tests): unit and API-level regression tests.

## Install

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
```

## Configure

Set an upstream API key:

```bash
export APG_UPSTREAM_API_KEY='real-upstream-key'
export APG_SIGNING_SECRET='local-random-secret'
```

Optional settings:

```bash
export APG_UPSTREAM_BASE_URL='https://api.openai.com'
export APG_LOCAL_API_KEYS='apg-local'
export APG_PORT=8765
# Strict mode (default true) refuses to start with the default signing secret
# or the default 'apg-local' API key. Clear it for dev:
#   APG_STRICT=false uvicorn gateway.server:create_app --factory ...
# PII disposition: 'pseudonymize' (default, <APG_PII:handle>),
#                  'redact' (treat PII like a secret — signed placeholder),
#                  'allow' (dev only; passes PII through unchanged).
export APG_PII_MODE='pseudonymize'
```

See [config/example_policy.yaml](/Users/howard/Documents/code/Agent-Privacy-Gateway/config/example_policy.yaml).

## Run

```bash
uvicorn gateway.server:create_app --factory --host 127.0.0.1 --port 8765
```

Point an OpenAI-compatible client at:

```text
base_url=http://localhost:8765/v1
api_key=apg-local
```

Example scripts:

- [examples/openai_client_example.py](/Users/howard/Documents/code/Agent-Privacy-Gateway/examples/openai_client_example.py)
- [examples/curl_example.sh](/Users/howard/Documents/code/Agent-Privacy-Gateway/examples/curl_example.sh)

DeepSeek/OpenCode experiment notes:

- [docs/deepseek_experiments.md](/Users/howard/Documents/code/Agent-Privacy-Gateway/docs/deepseek_experiments.md)
- [docs/real_agent_validation.md](/Users/howard/Documents/code/Agent-Privacy-Gateway/docs/real_agent_validation.md)
- [docs/live_validation_results.md](/Users/howard/Documents/code/Agent-Privacy-Gateway/docs/live_validation_results.md)
- [docs/e2e_test_plan.md](/Users/howard/Documents/code/Agent-Privacy-Gateway/docs/e2e_test_plan.md)

Realistic E2E harness commands:

```bash
.venv/bin/python -m e2e_agent_tests.scripts.run_all
DEEPSEEK_API_KEY='<your key>' .venv/bin/python -m e2e_agent_tests.scripts.run_real_api
```

## Example Behavior

Input:

```text
Email howard@example.com, path /Users/howard/private/project, key sk-proj-...
```

Remote view:

```text
Email <APG_PII:pii_...>, path /workspace/project, key <APG:v1:secret:...>
```

Machine secrets are never sent upstream and are never restored into user-visible text. To support transparent local tool execution, APG stores raw secret values in the local SQLite mapping store for the active session and materializes them only into structured tool-call argument fields.

## Hierarchical Sensitive Information Detection

APG now treats detection as a layered evidence pipeline, not as the final security boundary. Deterministic detectors run first for high-confidence cases such as private keys, provider-like tokens, JWTs, database URLs, bearer tokens, `.env` assignments, PII, local paths, APG placeholders, and redaction markers. Entropy/context heuristics then add candidate evidence for random-looking tokens near sensitive names.

Optional external scanners and local model detectors have plugin interfaces. They are lazy, disabled by default, and must run locally; model output contributes evidence but does not directly allow, block, redact, or materialize anything. The policy engine, materialization engine, signed-placeholder checks, and harness-owned tool/file controls remain the enforcement boundary.

The unified `Finding` schema records source block, original and normalized offsets, type, subtype, confidence, risk, detectors, validators, suggested action, safe preview, and metadata. A risk scorer merges overlapping evidence and hands findings to policy-aware components.

Detector execution is compiled into a linear flow. You can use a built-in preset, override modules/rules, or define a preset from scratch. Project-specific regex rules belong in `detectors.overrides.rules.add` or a custom `regex_rules` module:

```yaml
detectors:
  preset: custom_minimal
  presets:
    custom_minimal:
      modules:
        - id: custom_rules
          type: regex_rules
          rules:
            - id: custom.partner_token
              pattern: "\\bpartner_live_[A-Za-z0-9]{12,}\\b"
              type: MACHINE_SECRET
              subtype: partner_token
              confidence: 0.9
              risk: high
              suggested_action: redact
        - id: entropy
          type: entropy_context
          timeout_ms: 100
```

Supported module types include regex rules, entropy/context heuristics, path detection, Hugging Face token classification, GLiNER, allowlisted external tools, and allowlisted Python plugins. Model support is optional:

```bash
pip install -e '.[models]'
```

Use `POST /v1/apg/detect` with a local API key to dry-run detection. The response includes safe findings, sanitized preview text, and module diagnostics without returning raw sensitive matches.

## Placeholder And Materialization

Signed placeholders look like:

```text
<APG:v1:secret:secr_abc123:sess_abcd:1710000000:mac>
```

Materialization checks the signature, session, workspace, mapping state, expiry, and target sink. Invalid or hallucinated placeholders fail closed. Secrets are blocked for normal prompts, logs, shell commands, and user-visible text.

## How agents use secrets (transparent tool_call materialization)

APG is intentionally an OpenAI/Anthropic-compatible transparent proxy. It does not police tool execution; an agent harness is responsible for deciding which tools may run, which domains a tool may call, and whether a human must approve.

The mechanism that lets harnesses receive real secret values without any custom integration:

1. A prompt containing a raw secret is redacted upstream — the cloud LLM only sees `<APG:v1:secret:...>`.
2. When the LLM responds with a `tool_call` (OpenAI) or `tool_use` block (Anthropic) whose `arguments`/`input` field references the placeholder, APG materializes the raw secret back into that field only.
3. Every other string field in the response (assistant-visible text, reasoning, tool descriptions) stays redacted.
4. The harness receives the tool_call with the real credential and proceeds with its own tool permission, domain allowlist, and approval logic.

This means:

- **Generic.** APG requires no harness-side protocol changes. Any OpenAI/Anthropic-compatible harness transparently observes the real secret in `tool_call.arguments`.
- **APG is not a tool/capability broker.** It does not grant or revoke the right to use a secret for a given tool or domain. Whether the harness actually executes the materialized tool_call (which may exfiltrate to attacker-controlled URLs) is the harness' responsibility.
- **Raw secret storage.** To make materialization possible, APG's SQLite mapping store keeps the raw secret value for the session. The database file is created with mode `0600`; place the database on encrypted storage and restrict access to the user running APG.
- **Residual prompt-injection risk.** A cloud LLM under prompt injection can return a tool_call that points an agent at an attacker URL with the materialized secret. APG cannot prevent this. Harnesses must gate outbound tool execution if exfiltration is a concern.

Invalid or hallucinated placeholders inside `tool_call` arguments are left as-is (fail-closed); the harness usually surfaces a tool call failure rather than execute with a bogus value.

See [docs/harness_integration.md](/Users/howard/Documents/code/Agent-Privacy-Gateway/docs/harness_integration.md) for the full integration contract.

## Threat Model

Protected against:

- Accidental leakage of API keys, tokens, private keys, emails, local paths, and config secrets in prompts
- Cloud LLMs receiving raw machine secrets
- Model output echoing detected secret-like values
- Prompt injection that asks for secrets or placeholder materialization
- Spoofed placeholders in untrusted text
- Invalid or forged placeholders inside tool-call arguments

Not fully protected against:

- Semantic privacy leakage after redaction
- Users intentionally pasting or approving sensitive data
- Agents that bypass this proxy
- Unrestricted local shell access
- Provider-side hosted tools outside local control
- Unknown secret formats missed by detectors
- Malware already running locally
- Unsafe harness execution of materialized tool calls, including exfiltration to attacker-controlled URLs
- Destructive file writes or redacted-view overwrites; those are harness/editor/VCS responsibilities

The security premise is that cloud agents must send local context through APG before it reaches a remote model, and local harnesses must enforce their own tool permissions, domain routing, approvals, and file-write rules. If an agent bypasses APG or a harness executes unsafe tool calls, APG cannot enforce those boundaries.

## Test

```bash
PYTHONPATH=src pytest
```

## Limitations

Streaming responses are scanned per-SSE-delta; a secret split across `delta.content` boundaries may not be redacted because the model has already streamed the tokens. A secret echoed inside a single delta is redacted; secret placeholders are never materialized on the streaming path (they stay as opaque markers). Token accounting is approximate because redaction mutates context. The MCP proxy, runtime tracing, and full semantic-edit APIs are roadmap items. Tool permission brokerage and write-firewall-style file protections live in the agent harness, not in APG.
