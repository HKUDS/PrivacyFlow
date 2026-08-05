# Security Policy

## Supported versions

APG is currently pre-1.0. Security fixes are applied to the latest revision on
the default branch. Older revisions are not maintained.

## Reporting a vulnerability

Please do not open a public issue for a suspected vulnerability.

Use GitHub's private vulnerability reporting feature for this repository:

<https://github.com/HKUDS/Agent-Privacy-Gateway/security/advisories/new>

Include:

- the affected revision;
- the request/response format involved;
- reproducible steps using synthetic values only;
- the expected and observed security boundary;
- whether any upstream, audit, workspace, or final-answer leak occurred.

Do not send real API keys, customer data, raw protected-value databases, or
unsanitized Agent transcripts. You should receive an acknowledgement within
seven days. Disclosure timing will be coordinated after a fix is available.

## Deployment warning

The management API is intentionally unauthenticated and must remain
loopback-only. APG protects only traffic routed through it and does not sandbox
local Agents or authorize their tools. See the README security model before
deploying.
