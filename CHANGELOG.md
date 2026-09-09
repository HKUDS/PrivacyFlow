# Changelog

All notable changes to PrivacyFlow are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/). PrivacyFlow is pre-1.0: minor
versions may include breaking changes, which are called out explicitly.

## [Unreleased]

## [0.1.0] - 2026-09-09

First public release under the PrivacyFlow name. Earlier revisions were
developed as Agent Privacy Gateway (APG); `privacyflow migrate` and the `apg`
compatibility entry point carry that state forward.

### Added

- Protocol-native local proxy for OpenAI Chat Completions, OpenAI Responses,
  and Anthropic Messages, including stateful streaming without protocol
  conversion.
- Session-bound signed placeholders with lifecycle-aware mappings, retention
  policies, tombstones, and expired-placeholder handling.
- Built-in detector pipelines for credentials, API keys, personal information,
  local paths, entropy checks, and optional local models, with revisioned
  user configurations, built-in and deployment templates, and a detector dry
  run.
- Workspace-level exact-string watchlist that redacts registered values in
  every detector configuration, including the first request, with
  Unicode-normalized duplicate detection.
- Hierarchical local path aliasing and structured tool-argument
  materialization for local tools.
- Loopback-only WebUI (Chinese and English) covering overview, sanitized audit
  records, protected values, detector configuration, local-model management,
  and one-click Agent connectors for Codex, Claude Code, DeepSeek Harness, and
  nanobot with exact restore of pre-connection configuration.
- Sanitized, size-rotated JSONL audit log and safe diagnostics that never store
  raw protected values, test text, or detector patterns.
- Deterministic E2E harness and Playwright WebUI checks in CI.

### Security

- Detector `block` actions reject the complete upstream request with a
  non-retryable `PF_REQUEST_BLOCKED` error so the value never leaves the
  device.
- The streaming response scanner holds back in-progress watchlist prefixes so
  literals longer than the base streaming tail cannot be emitted piecewise.
- Placeholder restoration requires signature, session, expiry, mapping-state,
  and policy checks; fake or foreign placeholders are never materialized.
- Constant-time comparison for local Agent API keys; state files are written
  with mode `0600`; the management API remains loopback-only.

[Unreleased]: https://github.com/HKUDS/PrivacyFlow/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/HKUDS/PrivacyFlow/releases/tag/v0.1.0
