# Documentation

Tracked files in this directory are the public project docs. They describe
how PrivacyFlow works and how to operate it.

| File | Audience |
| --- | --- |
| [`design.md`](design.md) | Architecture, trust boundaries, placeholders, and materialization |
| [`webui.md`](webui.md) | Management API, persistence, raw-value review, and UI security |
| [`threat_model.md`](threat_model.md) | Threats, mitigations, assumptions, and residual risk |
| [`harness_integration.md`](harness_integration.md) | Agent and tool-harness integration |
| [`roadmap.md`](roadmap.md) | Planned work and open design areas |
| [`privacyflow-architecture.png`](privacyflow-architecture.png) | Architecture diagram used by the README |
| [`vendor/lucide-LICENSE.txt`](vendor/lucide-LICENSE.txt) | License for the Lucide icons bundled in the WebUI |

The following files are maintainer-local lab notes. They are gitignored and
must not be committed: live-agent trajectory dumps (`live_agent_evidence.js`),
the HTML viewer (`live_agent_scenarios.html` plus `vendor/marked.*`), and the
run diary (`live_validation_results.md`). Export them locally with
`python -m e2e_agent_tests.scripts.export_live_evidence`.
