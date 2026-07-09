# APG Real API E2E Test Report

Current deterministic scenario set: 14 scenarios.

This file is intentionally not marked as a fresh live pass. The old 20-scenario
real API report covered the removed broker/write-firewall architecture and is no
longer representative of APG's current transparent proxy contract.

To regenerate this report against a real OpenAI-compatible upstream:

```bash
export DEEPSEEK_API_KEY='<your key>'
.venv/bin/python -m e2e_agent_tests.scripts.run_real_api \
  --model deepseek-v4-flash \
  --report e2e_agent_tests/reports/latest_real_api_report.md
```

Expected global fail conditions:

- Any raw machine secret reaches the upstream LLM, normal audit log, memory/vector DB, or user-visible response text.
- Any fake APG placeholder is materialized.
- Tool-call argument materialization leaks into non-tool response fields.
- Upstream/proxy errors leak traceback, raw upstream URLs, or secret-bearing request details.
- Tombstone/unresolved placeholder causes an infinite retry loop.
- SQLite locking breaks concurrent scenarios.
