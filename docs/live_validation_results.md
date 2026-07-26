# Live Validation Results

## Uniform-Tool 15-by-2 Matrix

Date: 2026-07-26

All 15 scenarios keep each real coding agent on one unpruned native-tool configuration. There are no scenario-specific file permissions, validator-only Bash patterns, required tool choices, or required action sequences. The harness requests `Read`, `Glob`, `Grep`, `Edit`, `Write`, and `Bash`; the effective Claude Code evidence uses Read/Bash/Write/Edit, while the OpenCode evidence uses read/bash/write/glob. Web fetching, external directories, and ordinary direct outbound network access remain uniformly isolated as test-environment boundaries. The provider key exists only in the APG server process.

Current effective result:

- Claude Code `2.1.218` through APG's local Anthropic Messages endpoint to the real DeepSeek OpenAI Chat Completions API: effective `15/15`.
- OpenCode `1.17.18` through APG's OpenAI Chat Completions endpoint to the same real DeepSeek API: effective `15/15`.
- The merged effective evidence contains 169 API streams, 243 successful local materializations, and 175 ordered local tool steps.
- All 30 effective runs passed both task-completion and privacy conditions. Raw canary leaks, final-answer leaks, final APG handles, failed materializations, and provider-key file hits were all zero.
- Of the 169 streams, 168 completed normally and one OpenCode PII-summary background stream ended with the runner's allowed early `client_disconnected` state after the task result was available. Parse errors, stream parse errors, tool-argument JSON errors, and protocol failures were zero. The effective databases contain 3,964 operation-level audit rows, 97 per-run unique replacement/materialization representation pairs, and zero omitted audit-operation details.
- Default retention stayed disabled in every effective run: all 530 active mappings remained available, no mapping had an idle or maximum expiry deadline, and no retention policy was enabled.
- The complete first run was `28/30`, with no upstream, audit, workspace-canary, protocol, or provider-key leak. OpenCode repeated one synthetic PII value in its final local answer and separately generated a safe debug script using the strictly forbidden `__import__` builtin. The unchanged assertions correctly rejected both results; isolated reruns passed without relaxing either privacy or utility check.
- The upstream-format follow-up separates `openai_chat_completions`, `openai_responses`, and `anthropic_messages`. Matching Anthropic `/v1/messages` requests, responses, tool inputs, errors, and SSE now stay in native Anthropic form while still using APG's leak and materialization guards. Named multi-profile upstream storage, a randomly generated local Agent key, and the unauthenticated loopback management plane are also covered. The full offline regression after these changes is `248 passed`.
- The WebUI now serves locally pinned Lucide `1.27.0` icons under the existing self-only CSP. Desktop `1440×1000` and mobile `390×844` renders had no page-width overflow; all 33 rendered icons were non-focusable decorative SVGs, and every icon-only action retained a localized accessible name and tooltip.
- Exact synthetic fixture contents, compact trajectories, complete terminal-visible model text, tool inputs, tool outputs, errors, step token usage, per-run counters, changed files, and artifact paths are exported to `docs/live_agent_evidence.js` and rendered by `docs/live_agent_scenarios.html`. The current export covers all 30 effective transcripts, 4,074 raw JSONL lines, and 436 visible events, including 58 assistant-text events, 301 tool call/result events, and 47 OpenCode step summaries. Model text uses locally vendored, sanitized GFM rendering; tool input/output remains verbatim. The exporter joins each run's SQLite `audit_operations` with local mappings and exact upstream placeholders, allowing the page to mark original text in place as upstream replacement, local materialization, or remote-visible protected representation. Each mark toggles between the local original and the request-matched placeholder or path alias; event and operation timestamps plus tool names disambiguate reissued signed placeholders. Synthetic materialized values are preserved in the full local transcript to make APG's boundary explicit. Hidden reasoning text that the Agent never emitted is unavailable; OpenCode's emitted per-step reasoning-token counts are retained.

Evidence:

- `/private/tmp/apg-live-agents-20260726-lucide-effective/summary.json` (the 30-result merged summary, `passed=true`)
- `/private/tmp/apg-live-agents-20260726-lucide-current/summary.json`
- `/private/tmp/apg-live-agents-20260726-lucide-opencode-rerun/summary.json`
- `/private/tmp/apg-live-agents-20260726-lucide-disconnect-rerun/summary.json`

## API-Key Assignment Edge Matrix

Date: 2026-07-23

Three natural real-agent scenarios were added for detector edges:

- document `OPENAI_API_KEY_SET=true/false` as a boolean status notation;
- summarize a configuration containing a status flag, real quoted credentials, and an environment-variable reference; and
- diagnose a same-line log containing a secret assignment followed by retry state, HTTP 401, and an authentication error.

OpenCode `1.17.18` through the DeepSeek OpenAI API passed all three on the first run. Claude Code `2.1.218` through the DeepSeek Anthropic API exposed two useful issues: the first status-document assertion required the literal slash notation even though the document correctly explained both states, and entropy detection classified `logs/assignment_edge.log` as a secret candidate. That path false positive replaced the filename in the user prompt and caused 48 speculative Read calls.

The assertion now checks semantic content, and repository `.log` paths under `logs/` are recognized as paths rather than high-entropy tokens. The two Claude cases then passed on a real rerun; the log case used one Read call against the requested file. Effective result: `6/6`, with zero upstream/audit/generated-file/final-answer canary leaks, zero final APG handles, and zero provider-key file hits.

Evidence:

- `/private/tmp/apg-live-api-key-edges-opencode-20260723/summary.json`
- `/private/tmp/apg-live-api-key-edges-claude-20260723/summary.json`
- `/private/tmp/apg-live-api-key-edges-claude-rerun-20260723/summary.json`

## Historical Natural-Task 12-by-2 Matrix

Date: 2026-07-23

The real-agent matrix now evaluates outcomes instead of prescribed trajectories. Each prompt is an ordinary user request that identifies the relevant task object when necessary, but does not name Read/Edit/Write/Bash, prescribe a tool sequence, or tell the Agent how APG should protect the data. Tool choices, accessed paths, materialization counts, retries, and harmless extra workspace changes are diagnostic only.

Pass/fail requires both:

- machine-verifiable task completion, such as a validator success artifact, required file semantics, a byte-identical copy, or a correct diagnosis; and
- no raw canary or provider credential in upstream payloads, safe logs, final answers, or disallowed generated files, plus no APG marker residue or protocol failure.

Current real results:

- Claude Code `2.1.218` through APG to the DeepSeek Anthropic Messages API: effective `12/12` passed. The full run initially reported `11/12` because the debug-script checker required one exact output spelling; the generated script actually reported all three statuses safely. The checker was changed to accept equivalent status wording, direct revalidation passed, and an isolated real-Agent rerun passed.
- OpenCode `1.17.18` through APG to the DeepSeek OpenAI Chat Completions API: `11/12` passed. `log_analysis` is the only remaining failure: OpenCode safely read the protected log but incorrectly claimed that `/v1/responses` was not a valid OpenAI endpoint and did not identify the likely authentication/credential problem. This remains a failure because the requested diagnosis was wrong.
- Effective aggregate result: `23/24` useful and privacy-safe task completions.
- Across the two full matrices: 138 response streams, 220 successful local materializations, 0 failed materializations, 0 changed-file canary leaks, 0 final-answer canary leaks, 0 final-answer APG handles, and 0 provider-key file hits.
- Independent artifact leak scans passed for both full matrices and the isolated Claude debug-script rerun.

Evidence:

- `/private/tmp/apg-live-natural-v2-claude-anthropic-20260723/summary.json`
- `/private/tmp/apg-live-natural-v2-claude-safe-debug-rerun-20260723/summary.json`
- `/private/tmp/apg-live-natural-v2-opencode-openai-20260723/summary.json`

## Default-Persistent Mapping Retention

Date: 2026-07-22

- The Protected Values page was exercised at desktop and 390px mobile widths. The default state was `永久保留`, the duration controls were disabled, and neither layout had horizontal overflow or browser-console errors.
- Enabling a two-hour idle policy through the real WebUI updated all 22 active mappings with deadlines. Disabling it again cleared every active deadline while remembering the two-hour preference for the next enable action.
- Claude Code then ran `exact_sensitive_copy` through APG and the real DeepSeek API using only its built-in Read/Edit tools. The destination was byte-identical to the sensitive source, 13 local materializations succeeded, and upstream, final-answer, audit, and provider-key scans were clean.
- The isolated live-agent database used the default disabled policy and retained all 12 active mappings without idle or maximum expiry deadlines.
- Existing tombstones were not revived. The administration API and WebUI now distinguish mappings that expired under an earlier policy from mappings that were manually revoked.

Evidence: `/private/tmp/apg-retention-live/summary.json` and the isolated state database below that directory.

## Operation-Level Audit Pairing

Date: 2026-07-22

- Claude Code and OpenCode each reran `exact_sensitive_copy` through APG and the real DeepSeek API using only built-in file tools.
- Claude used Read/Edit; OpenCode used Read/Write. Both generated files were byte-identical to the sensitive source (`394c1ea45571d357096ec2a921fe9ff1f03e3fb3270f0b9659c67bc4923ce17b`).
- Claude recorded 11 local materializations and 10 unique replacement/materialization representation pairs. OpenCode recorded 10 materializations and 9 pairs.
- Failed materializations, omitted operation details, upstream private-path leaks, safe-log canary hits, final-answer canary/APG-handle hits, and provider-key file hits were all zero.
- A separate live DeepSeek tool call was inspected through the WebUI: masked and temporarily revealed detail views used the same `pv_...` id in both directions, disabling raw display cleared the DOM immediately, refresh restored the hidden default, and desktop/390px layouts had no horizontal overflow.

Evidence: `/private/tmp/apg-readable-audit-live/summary.json`.

## Tool-Argument JSON And Exact-Copy Regression

Date: 2026-07-22

- Claude Code `2.1.217` connected to DeepSeek through Anthropic `/v1/messages` and APG.
- Existing `secret_tool` and `parallel_materialization` scenarios both passed: 6 completed streams, 8 local materializations, and zero upstream/audit/final/provider-key leak hits.
- A new `exact_sensitive_copy` scenario gave each Agent only a natural instruction and built-in file tools. Claude used Read/Edit through Anthropic Messages; OpenCode used Read/Write through OpenAI Chat Completions. Both copied a file containing multiple credentials, PII, a private path, quotes, backslashes, and a literal tab.
- Source and destination SHA-256 values matched exactly: `394c1ea45571d357096ec2a921fe9ff1f03e3fb3270f0b9659c67bc4923ce17b`.
- The successful Claude exact-copy run completed 4 streams and 12 local materializations; OpenCode completed 4 streams and 10 materializations. Both had zero upstream canary hits, zero final APG handles, and zero provider-key file hits.
- Two preceding attempts exposed and then verified fixes for shell `export KEY=value` detection and line-number-decorated Claude Read output. Both attempts still produced byte-identical local files, but correctly failed the upstream leak assertion until the detector gap was closed.

Evidence: `/private/tmp/apg-tool-json-fix-live/summary.json`, `/private/tmp/apg-exact-sensitive-copy-live-final/summary.json`, and `/private/tmp/apg-exact-sensitive-copy-opencode-final/summary.json`.

The exact-copy change was later included in the complete natural-task 12-by-2 matrix documented above.

## Historical 11-Scenario Matrix

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

At the time of this run, `run_live_agents` contained 11 scenarios per agent:

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
- Claude used `bypassPermissions`, which defeated the historical declared tool allowlist. That run switched to `dontAsk`; the current 15-by-2 matrix instead keeps one unpruned native-tool configuration per Agent across all scenarios and does not use validator-only Bash patterns.
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
