# Live Validation Results

Date: 2026-07-02

## Current 11-Scenario Matrix

Date: 2026-07-21

After removing the live-agent `prompt_injection` case, the current matrix was run with Claude Code and OpenCode through APG and a real DeepSeek upstream:

- Claude Code: `11/11` passed.
- OpenCode: `10/11` passed on the first matrix run.
- The only first-run failure was `pii_tool`: the model removed the surrounding angle brackets from an APG placeholder, so APG correctly preserved the malformed value instead of materializing it and the local validator rejected it.
- An isolated OpenCode `pii_tool` rerun passed with three local materializations.
- First matrix run: 22 executions, 68 streams, and 57 materializations.
- Raw canary leak files, final-answer leaks, APG handles in final answers, and provider-key file hits: `0`.

Evidence: `/private/tmp/apg-live-11x2-latest/summary.json` and `/private/tmp/apg-live-11x2-pii-rerun/summary.json`.

## Reproducible Claude Code And OpenCode Runner

Date: 2026-07-10

The current checked-in `run_live_agents` matrix contains 11 scenarios per agent:

- `secret_tool`, `pii_tool`, and `parallel_materialization`
- `config_debug`, `pii_summary`, and `log_analysis`
- `path_alias` and `multi_file_review`
- `safe_env_example`, `sanitized_customer_reply`, and `safe_debug_script`

The following result is historical and predates removal of one scenario from the runnable matrix:

- Claude Code `2.1.206`: `12/12` passed over 35 APG streams and 36 materializations.
- OpenCode `1.17.18`: `12/12` passed over 44 APG streams and 35 materializations.
- All 24 executions contained the APG contract; all 79 final streams had `parse_errors=0` and `termination=completed`.
- Secret, PII, and parallel validators succeeded through locally materialized structured tool arguments.
- Raw canary hits in upstream payloads, APG audit logs, server logs, final answers, and generated/modified files: `0`.
- APG-handle hits in final answers and generated/modified files: `0`.
- Provider-key file hits across both artifact trees: `0`.
- Offline regression: `149 passed`; deterministic E2E: `14/14` passed.

The expanded run exposed and fixed issues that the original three-scenario smoke set did not cover:

- Agent subprocesses inherited the full parent environment, including the provider key. The runner now uses an environment allowlist and gives the provider key only to the APG server.
- Claude used `bypassPermissions`, which defeated its declared tool allowlist. It now uses `dontAsk` with scenario-scoped tools and validator-only Bash patterns.
- Entropy scanning falsely classified `scripts/validate_secret.py`, including stream fragments beginning mid-path, as a secret.
- Path detection included sentence punctuation in aliases, producing paths such as `path_probe.txt.`.
- Child paths received unrelated aliases instead of preserving the workspace hierarchy. Existing parent aliases now produce stable child suffixes such as `/workspace/project-hash/scripts/validate_secret.py`.
- Live assertions now verify actual tool calls, exact workspace changes, validator output, generated-file contents, stream termination, and provider-key absence instead of defaulting non-secret scenarios to success.

Final evidence is local-only at `/private/tmp/apg-live-final-claude-r2/summary.json` and `/private/tmp/apg-live-final-opencode-r2/summary.json`.

## Earlier Focused Stateful Streaming And Tool Calls

Date: 2026-07-10

The final validation used two real coding agents and the same real DeepSeek API through APG:

- Claude Code `2.1.206` used Anthropic `/v1/messages` streaming.
- OpenCode `1.17.15` used OpenAI `/v1/chat/completions` streaming through a temporary `@ai-sdk/openai-compatible` provider.
- Both agents received only a natural task: read `SERVICE_TOKEN` from `.env` and pass the value as the sole argument to a local validator.
- Both validators succeeded through APG-materialized structured tool arguments.
- APG recorded 9 Anthropic requests and 7 OpenAI requests; all 16 upstream payloads contained the APG system-prompt contract.
- Raw canary hits in upstream requests, APG audit logs, final answers, and generated success files: `0`.
- APG-handle hits in final answers: `0`.
- Every stream completion reported `parse_errors=0` and `termination=completed`.

The real agents' own local JSON trajectories contain the materialized tool argument. This is the documented local-transcript boundary: APG controls remote upload and downstream model-visible text, not logging performed by a trusted local agent after it receives a tool call.

Evidence is local-only at `/private/tmp/apg-stream-real-agents-final/summary.json` with the upstream log, safe audit log, and both agent trajectories beside it.

## Claude Code Roleplay Agent Validation

Date: 2026-07-09

This validation is different from asking Claude Code to run the test harness.
Claude Code itself acted as the coding agent in each synthetic scenario: it was
started with `ANTHROPIC_BASE_URL=http://127.0.0.1:8787`, APG proxied its
Anthropic-compatible `/v1/messages` traffic to DeepSeek, and Claude Code used
real `Read`, `Write`, and `Bash` tool calls inside per-scenario test
repositories.

Result after fixes:

- Claude Code version: `2.1.204`
- model through APG: `deepseek-v4-flash`
- scenarios run: `14`
- passed: `14`
- failed: `0`
- upstream raw-secret leaks: `0`
- audit raw-secret leaks: `0`
- final-output / written-file forbidden leaks: `0`

Issues found by the first roleplay run:

- `scenario_06`: Hong Kong address fragment (`Kennedy Town, Hong Kong`) was not
  detected as PII. Fixed with a narrow local address rule.
- `scenario_13`: path aliases such as `/workspace/repo` collided across
  independent synthetic repositories. Fixed by adding a short stable hash to
  path aliases.

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
