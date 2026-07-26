# Local Management WebUI

APG serves a zero-build management panel at `/ui/`. It is designed for repeated local operations rather than provider traffic and uses an unauthenticated `/api/admin/*` control plane.

## Language

The WebUI supports Chinese and English. The language switch updates static labels, dynamically rendered tables, detector diagnostics, forms, and dialogs without reloading the page. The initial locale follows the browser language; later choices are stored under `apg_locale` in browser `localStorage`.

The zero-build panel vendors Lucide `1.27.0` locally and serves it through `/ui/assets/lucide.min.js`; no icon CDN or additional CSP origin is required. Icon-only actions keep localized `aria-label` and `title` text while their SVGs remain decorative.

The locale preference contains no credential or gateway data. Authentication remains in `sessionStorage`, while the CLI and launcher output remain English-only.

## Security Boundary

The overview can return one configured local Agent credential from `APG_LOCAL_API_KEYS` so it can be copied into an Agent client. This is an APG-local access key, not the upstream provider key. Ordinary control-plane summaries do not return:

- Raw values from the mapping database
- Complete APG placeholders or internal mapping handles
- Mapping fingerprints
- Provider API keys
- Full APG session ids

The upstream-configuration endpoint is the deliberate provider-connection write path. It accepts named configurations over the local control plane, validates the URL, atomically writes each format, Base URL, and API key to `.apg/launcher.json` with mode `0600`, hot-applies the selected profile, clears the browser key input, and returns only configured status, protocol metadata, and non-secret upstream URLs. It never echoes or audits a provider key.

Protected values are identified by an HMAC-derived `pv_...` administration id. The id supports revocation but cannot be used for placeholder materialization. Revocation tombstones the mapping and clears its stored raw value.

The operation-list, request-detail, and protected-value endpoints provide a deliberate opt-in exception. With `include_raw=false` they return `***`; with `include_raw=true` they read an original only while the referenced mapping is active. Audit-operation rows do not duplicate the original or store a complete signed placeholder, and `.apg/audit.jsonl` remains free of both. Every raw read records a safe `view_audit_raw_values` or `view_protected_raw_values` management event without the viewed content.

The WebUI and every `/api/admin/*` data or mutation endpoint require no key. APG binds to `127.0.0.1` by default, which is the management plane's security boundary. Do not bind APG to another interface unless that unauthenticated access is explicitly intended and protected by an external trusted boundary. Set `APG_ADMIN_ENABLED=false` to remove both `/ui/` and `/api/admin/*`.

## Views

### Overview

When the launcher has no complete provider connection, the dashboard requires a configuration name, an explicit upstream API format—OpenAI Chat Completions, OpenAI Responses, or Anthropic Messages—plus a Base URL and API key before the Agent connection strip. Multiple named configurations can be saved, activated, edited, and deleted without restarting APG. Each configuration keeps its own provider key; editing with an empty key field preserves the saved value. Keys are never stored by the browser or returned by APG.

APG does not infer or silently change the upstream API format from the Base URL. Provider-specific suffixes can be suggestive, but generic gateways, self-hosted proxies, and custom routes make URL-only detection unreliable. With an Anthropic Messages upstream, APG uses `/v1/messages`, `x-api-key`, and `anthropic-version: 2023-06-01`; a local `/v1/messages` request stays in native Anthropic JSON/SSE form end to end, apart from APG's privacy transformations and system-contract injection. Legacy stored values `openai` and `anthropic` migrate to `openai_chat_completions` and `anthropic_messages`.

The Agent connection strip displays the OpenAI-compatible and Anthropic local Base URLs simultaneously and provides an independent copy action for each. On a new launcher installation, the local Agent API key is generated with cryptographic randomness and persisted in the private launcher file; existing keys are never rotated by migration. The Agent key stays masked by default, and an eye icon temporarily reveals it. A separate Claude Code action copies a multiline shell environment block containing the local Anthropic URL and local Agent key, DeepSeek `deepseek-v4-pro[1m]` defaults for 1M-context primary work, DeepSeek v4 Flash defaults for Haiku and subagents, and maximum effort. It does not append a `claude` invocation, so users can apply their preferred Claude Code settings and startup command separately. The rest of the view summarizes the latest audit window: requests, interceptions, local tool-argument materializations, active protected values, seven-day activity, and risk distribution. The upstream is represented by hostname only.

| Agent endpoint | Chat Completions upstream | Responses upstream | Anthropic Messages upstream |
| --- | --- | --- | --- |
| `/v1/chat/completions` | Native | Unsupported (`501`) | Converted request, response, and SSE |
| `/v1/messages` | Converted request, response, and SSE | Unsupported (`501`) | Native Anthropic JSON and SSE |
| `/v1/responses` | Unsupported (`501`) | Native | Unsupported (`501`) |
| `/v1/models` | Native | Native | Native Anthropic Models API |

### Audit

The audit view has two independent operation-level lists: **Replacement records** and **Materialization records**. Every row is one distinct recorded transformation rather than an Agent-request summary. The replacement list contains only upstream replacements; the materialization list contains successful and failed local materialization attempts. Both lists support risk, endpoint, and safe metadata filters, and use the same `pv_...` id to connect:

- `original or *** -> exact placeholder/path alias` for upstream replacement
- `exact placeholder/path alias -> original or ***` for local materialization

Repeated uses of one mapping and representation are merged with an occurrence count. Historical JSONL events created before per-operation storage remain available through the compatibility request-summary API, but APG does not invent operation rows for them. The eye control is off by default and requires confirmation; it is not written to browser storage. Turning it off clears the operation list and fetches masked data, while page reload restores the hidden state. Expired, revoked, or unavailable mappings display `原文已清除` rather than recovering an audit copy.

### Protected Values

The registry exposes kind, subtype, scope, lifecycle state, materialization class, timestamps, and whether a local value is currently stored. Originals are masked by default. Its eye control requires confirmation and temporarily fetches originals only for active mappings; closing it immediately clears rendered and in-memory originals and reloads `***`. Automatic clearing is disabled by default, so active mappings display `不自动过期`. The retention control can enable idle-time clearing and set a duration from one minute to 365 days. Enabling starts a fresh deadline for all active mappings; disabling removes their pending deadlines. Active mappings can still be revoked individually, and expired records can be purged. Expired and manually revoked tombstones are displayed separately.

### Detector Configurations

The detector view manages complete, ordered local pipelines. Built-in templates cover credentials and keys, personal information, the local development environment, and comprehensive protection. Templates are read-only; choosing **Copy and edit** creates an independent user configuration.

A user configuration has a name, description, revision, total timeout, core-guard setting, and an ordered module list. It can be copied, renamed, activated, or deleted when inactive. Modules can be added, copied, edited, enabled, disabled, removed, and moved up or down. All enabled modules run in display order and their findings are merged; a match does not short-circuit later modules.

The WebUI can create regular-expression, entropy/context, path, and local-model modules. Regular expressions are checked for length, empty matches, a safe syntax subset, and common ReDoS structures. Local models use a Transformers token-classification or GLiNER adapter, are loaded lazily, and never download unless deployment-level `allow_model_download` permits it. Missing packages or cached models appear as `unavailable` diagnostics. YAML external-tool and Python-plugin modules remain operational but are shown as deployment-managed and read-only.

The dry run tests the selected saved configuration without activating it. The browser highlights findings over the submitted original text and shows module timing, hit count, and errors in execution order. Neither the text nor detector patterns are written to audit records.

Changes are persisted to version 2 of `detector-control.json` beside `state.sqlite3`; the file and migration backup use mode `0600`. Saves require the current revision, with stale updates returning `409`. Saving an active configuration validates and builds a replacement before an atomic persistence and runtime swap. A failed build keeps the previous pipeline active. Version 1 state is migrated once, preserving the selected preset, module switches, and custom rules; YAML presets are exposed as read-only deployment templates.

APG-marker integrity and streaming-boundary protection are fixed, always-on safety mechanisms rather than detector-configuration options. They cannot be disabled through the WebUI or detector-configuration API. Exact valid same-session placeholders are still restored for the local user after signature, session, expiry, policy, and sink checks. APG does not maintain a separate downlink denylist of previously seen secret values: if an upstream model emits a raw value, APG does not hide it merely because the value appeared earlier in the local session.

## Administration API

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `GET` | `/api/admin/overview` | Safe dashboard summary |
| `GET` | `/api/admin/connection` | One local Agent API key and protocol base paths |
| `GET` | `/api/admin/upstream-configuration` | Provider-key configured status and safe upstream metadata |
| `PUT` | `/api/admin/upstream-configuration` | Validate, persist, and hot-apply an upstream Base URL and provider API key without echoing the key |
| `GET` | `/api/admin/audit` | Filtered audit events |
| `GET` | `/api/admin/audit/operations` | Separate replacement or materialization operation list; optional `include_raw=true` |
| `GET` | `/api/admin/audit/requests` | Request-level replacement/materialization summaries |
| `GET` | `/api/admin/audit/requests/{request_id}` | Per-operation detail; optional `include_raw=true` |
| `GET` | `/api/admin/protected-values` | Mapping metadata; optional `include_raw=true` |
| `PUT` | `/api/admin/protected-values/retention` | Save revision-protected automatic-clearing state and idle duration |
| `POST` | `/api/admin/protected-values/{id}/revoke` | Tombstone one mapping |
| `POST` | `/api/admin/protected-values/purge-expired` | Tombstone expired mappings |
| `GET` | `/api/admin/detector-configurations` | Templates, user configurations, active id, and module catalog |
| `POST` | `/api/admin/detector-configurations` | Create an empty configuration or copy one |
| `GET` | `/api/admin/detector-configurations/{id}` | Complete configuration and module diagnostics |
| `PUT` | `/api/admin/detector-configurations/{id}` | Validate and save one revision |
| `DELETE` | `/api/admin/detector-configurations/{id}` | Delete an inactive user configuration |
| `POST` | `/api/admin/detector-configurations/{id}/activate` | Atomically activate a saved configuration |
| `POST` | `/api/admin/detector-configurations/{id}/test` | Local-only dry run of a saved configuration |

All responses use `Cache-Control: no-store`. The UI page applies a restrictive Content Security Policy and cannot be embedded in another page.
