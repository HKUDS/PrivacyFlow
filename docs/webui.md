# Local Management WebUI

APG serves a zero-build management panel at `/ui/`. It is designed for repeated local operations rather than provider traffic and uses the authenticated `/api/admin/*` control plane.

## Language

The WebUI supports Chinese and English. The language switch is available on both the sign-in panel and the authenticated control plane, and updates static labels, dynamically rendered tables, detector diagnostics, forms, and dialogs without reloading the page. The initial locale follows the browser language; later choices are stored under `apg_locale` in browser `localStorage`.

The locale preference contains no credential or gateway data. Authentication remains in `sessionStorage`, while the CLI and launcher output remain English-only.

## Security Boundary

The authenticated overview can return one configured local Agent credential from `APG_LOCAL_API_KEYS` so it can be copied into an Agent client. This is an APG-local access key, not the upstream provider key. Ordinary control-plane summaries do not return:

- Raw values from the mapping database
- Complete APG placeholders or internal mapping handles
- Mapping fingerprints
- Provider API keys
- Full APG session ids

The first-run upstream-configuration endpoint is the deliberate provider-key write path. It accepts a key over the administrator-authenticated local control plane, atomically writes it to `.apg/launcher.json` with mode `0600`, hot-applies it to the running upstream client, clears the browser input, and returns only configured status and the non-secret upstream URL. It never echoes or audits the key.

Protected values are identified by an HMAC-derived `pv_...` administration id. The id supports revocation but cannot be used for placeholder materialization. Revocation tombstones the mapping and clears its stored raw value.

The administrator-only operation-list, request-detail, and protected-value endpoints provide a deliberate opt-in exception. With `include_raw=false` they return `***`; with `include_raw=true` they read an original only while the referenced mapping is active. Audit-operation rows do not duplicate the original or store a complete signed placeholder, and `.apg/audit.jsonl` remains free of both. Every raw read records a safe `view_audit_raw_values` or `view_protected_raw_values` administrator event without the viewed content.

Set a dedicated administrator key where possible:

```bash
export APG_ADMIN_API_KEYS='a-random-local-admin-key'
```

When `APG_ADMIN_API_KEYS` is absent, the WebUI accepts `APG_LOCAL_API_KEYS` for backward compatibility. The browser stores the entered key in `sessionStorage`; it is cleared when the browser session ends. Static UI assets contain no credentials and may load before authentication, while every data and mutation endpoint requires the administrator key.

APG binds to `127.0.0.1` by default. If the gateway is deliberately bound to another interface, terminate TLS in front of it and use a separate administrator key. Set `APG_ADMIN_ENABLED=false` to remove both `/ui/` and `/api/admin/*`.

## Views

### Overview

When the launcher has no provider credential, the dashboard opens an upstream API-key setup form before the Agent connection strip. Saving persists the key locally and enables the current process without a restart; subsequent loads show only configured status and an explicit replace action. The key input is never stored by the browser or returned by APG.

The Agent connection strip switches between the OpenAI-compatible and Anthropic base URLs, keeps the local Agent API key masked by default, and copies either value with one action. An eye icon temporarily reveals the local key. A separate Claude Code action copies a multiline shell environment block containing the local Anthropic URL and local Agent key, DeepSeek `deepseek-v4-pro[1m]` defaults for 1M-context primary work, DeepSeek v4 Flash defaults for Haiku and subagents, and maximum effort. It does not append a `claude` invocation, so users can apply their preferred Claude Code settings and startup command separately. The rest of the view summarizes the latest audit window: requests, interceptions, local tool-argument materializations, active protected values, seven-day activity, and risk distribution. The upstream is represented by hostname only.

### Audit

The audit view has two independent operation-level lists: **Replacement records** and **Materialization records**. Every row is one distinct recorded transformation rather than an Agent-request summary. The replacement list contains only upstream replacements; the materialization list contains successful and failed local materialization attempts. Both lists support risk, endpoint, and safe metadata filters, and use the same `pv_...` id to connect:

- `original or *** -> exact placeholder/path alias` for upstream replacement
- `exact placeholder/path alias -> original or ***` for local materialization

Repeated uses of one mapping and representation are merged with an occurrence count. Historical JSONL events created before per-operation storage remain available through the compatibility request-summary API, but APG does not invent operation rows for them. The eye control is off by default and requires confirmation; it is not written to browser storage. Turning it off clears the operation list and fetches masked data, while page reload, logout, and reauthentication restore the hidden state. Expired, revoked, or unavailable mappings display `原文已清除` rather than recovering an audit copy.

### Protected Values

The registry exposes kind, subtype, scope, lifecycle state, materialization class, timestamps, and whether a local value is currently stored. Originals are masked by default. Its eye control requires confirmation and temporarily fetches originals only for active mappings; closing it immediately clears rendered and in-memory originals and reloads `***`. Automatic clearing is disabled by default, so active mappings display `不自动过期`. The retention control can enable idle-time clearing and set a duration from one minute to 365 days. Enabling starts a fresh deadline for all active mappings; disabling removes their pending deadlines. Active mappings can still be revoked individually, and expired records can be purged. Expired and manually revoked tombstones are displayed separately.

### Detector Configurations

The detector view manages complete, ordered local pipelines. Built-in templates cover credentials and keys, personal information, the local development environment, and comprehensive protection. Templates are read-only; choosing **Copy and edit** creates an independent user configuration.

A user configuration has a name, description, revision, total timeout, core-guard setting, and an ordered module list. It can be copied, renamed, activated, or deleted when inactive. Modules can be added, copied, edited, enabled, disabled, removed, and moved up or down. All enabled modules run in display order and their findings are merged; a match does not short-circuit later modules.

The WebUI can create regular-expression, entropy/context, path, and local-model modules. Regular expressions are checked for length, empty matches, a safe syntax subset, and common ReDoS structures. Local models use a Transformers token-classification or GLiNER adapter, are loaded lazily, and never download unless deployment-level `allow_model_download` permits it. Missing packages or cached models appear as `unavailable` diagnostics. YAML external-tool and Python-plugin modules remain operational but are shown as deployment-managed and read-only.

The dry run tests the selected saved configuration without activating it. The browser highlights findings over the submitted original text and shows module timing, hit count, and errors in execution order. Neither the text nor detector patterns are written to audit records.

Changes are persisted to version 2 of `detector-control.json` beside `state.sqlite3`; the file and migration backup use mode `0600`. Saves require the current revision, with stale updates returning `409`. Saving an active configuration validates and builds a replacement before an atomic persistence and runtime swap. A failed build keeps the previous pipeline active. Version 1 state is migrated once, preserving the selected preset, module switches, and custom rules; YAML presets are exposed as read-only deployment templates.

The APG core guard is enabled by default. Disabling it requires explicit confirmation and disables APG-marker, known-session-secret, and streaming-boundary protection in detection. Placeholder signature, session, expiry, policy, and sink checks in local materialization cannot be disabled.

## Administration API

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `GET` | `/api/admin/overview` | Safe dashboard summary |
| `GET` | `/api/admin/connection` | One local Agent API key and protocol base paths |
| `GET` | `/api/admin/upstream-configuration` | Provider-key configured status and safe upstream metadata |
| `PUT` | `/api/admin/upstream-configuration` | Persist and hot-apply a replacement provider API key without echoing it |
| `GET` | `/api/admin/audit` | Filtered audit events |
| `GET` | `/api/admin/audit/operations` | Separate replacement or materialization operation list; optional administrator-only `include_raw=true` |
| `GET` | `/api/admin/audit/requests` | Request-level replacement/materialization summaries |
| `GET` | `/api/admin/audit/requests/{request_id}` | Per-operation detail; optional administrator-only `include_raw=true` |
| `GET` | `/api/admin/protected-values` | Mapping metadata; optional administrator-only `include_raw=true` |
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
