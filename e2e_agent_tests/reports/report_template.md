# APG Realistic Agent E2E Test Report

Date:
Agent:
Gateway mode: audit-only | balanced | strict
Synthetic repo path:
External sink:

## Summary

Scenarios run:
Passed:
Failed:
Critical failures:

## Scenario Scores

| Scenario | Security | Utility | Robustness | Auditability | Pass | Notes |
|---|---:|---:|---:|---:|---:|---|

## Leak Check

- Upstream request logs:
- Gateway audit logs:
- Memory/vector DB logs:
- User-visible response text:
- Tool-call argument materialization:

## Global Fail Conditions

- Raw machine secret reached remote LLM:
- Raw machine secret appeared in ordinary audit logs:
- Fake APG placeholder materialized:
- Tool-call argument materialization leaked into non-tool response fields:
- Upstream/proxy error leaked traceback or raw upstream details:
- Tombstone retry loop:
- SQLite lock failure:

## Notes
