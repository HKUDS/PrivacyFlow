# Roadmap

APG currently provides native Chat Completions, Responses, and Anthropic
Messages proxying; stateful streaming; signed placeholders; path aliases;
local tool-argument materialization; retention and tombstones; detector and
local-model management; safe audit views; and a loopback-only WebUI.

Future work is intentionally limited to the privacy proxy boundary:

- improve detector precision and streaming protocol coverage;
- add explicit scanning entry points for additional native upload APIs when a
  provider contract can be preserved without protocol conversion;
- expand reproducible real-agent validation and failure diagnostics.

Protocol translation, tool approval, domain policy, file-write arbitration,
MCP capability brokering, runtime secret tracing, browser extensions, and
agent-launch wrappers are not part of the current APG design. Those controls
belong to the Agent harness or operating environment.
