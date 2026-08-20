# Roadmap

PrivacyFlow currently provides native Chat Completions, Responses, and Anthropic
Messages proxying; stateful streaming; signed placeholders; path aliases;
response-field-classified tool-argument materialization; retention and tombstones;
a fixed built-in detection pipeline; local-model management; safe audit views; and
a loopback-only WebUI.

Future work is intentionally limited to the privacy proxy boundary:

- improve detector precision and streaming protocol coverage;
- add explicit policy enforcement for detector `block` actions and, if kept in
  scope, per-tool materialization rules rather than field-shape classification;
- define scanning contracts for opaque multimodal payloads without corrupting
  native provider formats;
- add explicit scanning entry points for additional native upload APIs when a
  provider contract can be preserved without protocol conversion;
- expand reproducible real-agent validation and failure diagnostics.

Protocol translation, tool approval, domain policy, file-write arbitration,
MCP capability brokering, runtime secret tracing, browser extensions, and
agent-launch wrappers are not part of the current PrivacyFlow design. Those controls
belong to the Agent harness or operating environment.
