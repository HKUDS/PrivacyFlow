# Live Validation Results

Date: 2026-07-02

## DeepSeek Live APG Harness

Command class:

```bash
DEEPSEEK_API_KEY='<redacted>' .venv/bin/python experiments/deepseek_agent_experiment.py --live --model deepseek-v4-flash
```

Result:

- status code: `200`
- model: `deepseek-v4-flash`
- request redactions: `3`
- response redactions: `0`
- returned body contained fake stress secret: `false`

The request included fake stress data for email, local path, and API-key-like text. APG redacted/aliased the request before forwarding it upstream.

## OpenCode With DeepSeek Key

Command class:

```bash
DEEPSEEK_API_KEY='<redacted>' opencode run --model deepseek/deepseek-v4-flash
```

Result:

- OpenCode version: `1.17.9`
- model: `deepseek/deepseek-v4-flash`
- smoke-test response: `APG_DEEPSEEK_KEY_AGENT_OK`

## OpenCode Real-Agent Black-Box Probe

The probe server exposed only `http://127.0.0.1:8766/probe`. OpenCode was run from an empty directory and instructed not to inspect files or edit anything.

This result is historical. It covered the earlier prototype, including
harness-side write protection checks that have since moved out of APG. The
current APG contract is narrower: redact before upstream, preserve local
mappings, scan downstream text, and materialize signed placeholders only inside
structured local tool-call arguments.

Result:

- top-level `ok`: `true`
- `proxy_redaction_blackbox`: `ok=true`
- `placeholder_blackbox`: `ok=true`
- `tool_argument_materialization_blackbox`: not rerun after architecture change
- `deepseek_path_mapping_blackbox`: `ok=true`

Evidence codes:

- `upstream_contains_raw_secret: false`
- `response_contains_raw_secret: false`
- `audit_contains_raw_secret: false`
- `traversal_error: APG_PATH_TRAVERSAL_BLOCKED`
- `fake_error: APG_PLACEHOLDER_INVALID_MAC`
- `mapped_path: /chat/completions`
