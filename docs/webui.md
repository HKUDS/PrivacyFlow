# Local Management WebUI

APG serves a zero-build management panel at `/ui/`. It is designed for repeated local operations rather than provider traffic and uses an unauthenticated `/api/admin/*` control plane.

## Language

The WebUI supports Chinese and English. The language switch updates static labels, dynamically rendered tables, detector diagnostics, forms, and dialogs without reloading the page. The initial locale follows the browser language; later choices are stored under `apg_locale` in browser `localStorage`.

The zero-build panel vendors Lucide `1.27.0` locally and serves it through `/ui/assets/lucide.min.js`; no icon CDN or additional CSP origin is required. Icon-only actions keep localized `aria-label` and `title` text while their SVGs remain decorative.

The locale preference contains no credential or gateway data. The management plane has no login state; the CLI and launcher output remain English-only.

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

Local-model installation and download are more restrictive than the rest of the unauthenticated control plane: the APG bind address and actual client address must both be loopback. Remote-bound or remote-client sessions can inspect status but receive `LOCAL_MODEL_SETUP_LOCAL_ONLY` for every mutation. Dependency commands come from a fixed server-side manifest and always target APG's isolated managed Runtime; request bodies cannot supply package names, versions, indexes, or command arguments.

## Views

### Overview

When the launcher has no complete provider connection, the dashboard requires a configuration name, shared Base URL, and API key before the Agent connection strip. Multiple named configurations can be saved, switched, edited, and deleted without restarting APG. Each configuration keeps its own provider key; editing with an empty key field preserves the saved value. Keys are never stored by the browser or returned by APG.

Every configuration exposes all three native formats by default. APG routes each local endpoint to the matching native upstream endpoint without conversion; a provider that does not support the requested format returns its own upstream error. The connectivity tester still lets users choose a format and model so each route can be checked independently. Pasting a complete terminal endpoint such as `/chat/completions`, `/responses`, or `/messages` is normalized to the shared Base URL. Rare providers with unrelated routes can use an optional full-endpoint override per format. Anthropic Messages uses `x-api-key` and `anthropic-version: 2023-06-01`; a local `/v1/messages` request stays in native Anthropic JSON/SSE form end to end, apart from APG's privacy transformations and system-contract injection. Legacy single-format profiles are migrated to expose all three formats, while stored values `openai` and `anthropic` remain accepted as compatibility aliases for the profile's primary format.

The Agent connection strip displays the OpenAI-compatible and Anthropic local Base URLs simultaneously and provides an independent copy action for each. On a new launcher installation, the local Agent API key is generated with cryptographic randomness and persisted in the private launcher file; existing keys are never rotated by migration. The Agent key stays masked by default, and an eye icon temporarily reveals it. APG intentionally does not generate Agent-specific model configuration: users select the model in their Agent and replace only its request URL and API key with the displayed APG connection details. The rest of the view summarizes the latest audit window: requests, interceptions, local tool-argument materializations, active protected values, seven-day activity, and risk distribution. The upstream is represented by hostname only.

| Agent endpoint | Chat Completions upstream | Responses upstream | Anthropic Messages upstream |
| --- | --- | --- | --- |
| `/v1/chat/completions` | Native | Unsupported (`501`) | Unsupported (`501`) |
| `/v1/messages` | Unsupported (`501`) | Unsupported (`501`) | Native Anthropic JSON and SSE |
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

A user configuration has a name, description, total timeout, and an ordered module list. It can be copied, renamed, activated, or deleted when inactive. Modules can be added, copied, edited, enabled, disabled, removed, and reordered by dragging the handle. All enabled modules run in display order and their findings are merged; a match does not short-circuit later modules. An internal revision still protects concurrent saves, but it is not presented as a user setting.

The WebUI can create regular-expression, entropy, path, and local-model modules. Regular expressions are checked for length, empty matches, a safe syntax subset, and common ReDoS structures. High-entropy detection is optional and disabled in built-in templates because it can flag normal code identifiers; users can enable it for strict opaque-token scanning. A local-model module must select a model that the Local model management page has already verified as available. Explicit preparation and download are controlled by that page; deployment-level `allow_model_download` controls only legacy implicit runtime downloads. YAML external-tool and Python-plugin modules remain operational but are shown as deployment-managed and read-only.

The dry run tests the selected saved configuration without activating it. The browser highlights findings over the submitted original text and shows module timing, hit count, and errors in execution order. Neither the text nor detector patterns are written to audit records.

Changes are persisted to version 2 of `detector-control.json` beside `state.sqlite3`; the file and migration backup use mode `0600`. Saves require the current revision, with stale updates returning `409`. Saving an active configuration validates and builds a replacement before an atomic persistence and runtime swap. A failed build keeps the previous pipeline active. Version 1 state is migrated once, preserving the selected preset, module switches, and custom rules; YAML presets are exposed as read-only deployment templates.

APG-marker integrity and streaming-boundary protection are fixed, always-on safety mechanisms rather than detector-configuration options. They cannot be disabled through the WebUI or detector-configuration API. Exact valid same-session placeholders are still restored for the local user after signature, session, expiry, policy, and sink checks. APG does not maintain a separate downlink denylist of previously seen secret values: if an upstream model emits a raw value, APG does not hide it merely because the value appeared earlier in the local session. If a locally materialized protected value later re-enters another upstream request, its active session mapping re-protects the exact value even when the new surrounding syntax would not independently match the original detector.

### Local Model Management

The local-model view combines saved detector references with manually added Hugging Face repositories or local directories. Its primary control is a single model-address input followed by **Add and prepare**. APG recognizes `owner/model`, Hugging Face URLs, and existing local directories, then inspects metadata before doing any large download. Runtime, dependency, cache, and device information lives in a collapsed advanced section.

Adapter and device preferences default to `auto`. Hugging Face `pipeline_tag`, `config.json.model_type`, and `architectures` select GLiNER or Transformers token classification only when the result is unambiguous; otherwise the model enters `needs_input`. Automatic device selection prefers CUDA, then Apple MPS, then CPU. An explicitly selected unavailable device produces an actionable error and is never silently replaced.

Each model can run the combined `inspect → runtime → download → verify` operation or a context-specific repair. APG builds a fixed, versioned environment under `runtimes/model-runtime-v1/` beside the database, verifies it in a temporary directory, and atomically replaces the active Runtime only after success. Model libraries are not installed into APG's own environment.

A persistent private JSON-lines Worker performs `load`, `infer`, `unload`, and `health`. Models are loaded lazily and reused. The Worker uses offline Hugging Face mode, never enables `trust_remote_code`, and receives no upstream API key, Agent key, signing key, or Hugging Face token. A crashed Worker is restarted once; module fail-open/fail-close behavior remains the final failure policy.

Manual entries and validation records persist in the mode-`0600`, version-2 `local-models.json` beside the SQLite database. Hugging Face snapshots use the sibling `models/` cache. APG does not copy or delete user-owned local directories. Managed cache deletion is blocked while an enabled module in the active detector configuration references the model. Explicit user downloads are independent of the runtime `allow_model_download` switch.

The ordinary test suite never installs packages or downloads models. To explicitly exercise a real CPU-only dependency install, tiny Hugging Face snapshot download, load, and inference inside a temporary virtual environment, run:

```bash
APG_RUN_LOCAL_MODEL_INTEGRATION=1 .venv/bin/pytest -q tests/test_local_models_integration.py
```

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
| `GET` | `/api/admin/local-models` | Managed Runtime, devices, model catalog, cache, and active-job status |
| `POST` | `/api/admin/local-models` | Add a model with automatic/explicit source, Adapter, and device; `prepare: true` starts one-click preparation |
| `DELETE` | `/api/admin/local-models/{id}` | Remove a manual catalog entry without deleting shared cache |
| `DELETE` | `/api/admin/local-models/{id}/cache` | Safely remove APG-managed cache when it is not active |
| `POST` | `/api/admin/local-models/prepare` | Start an allowlisted inspect/runtime/download/verification job (`dependencies` remains a runtime alias) |
| `GET` | `/api/admin/local-model-jobs/{id}` | Poll stage, total progress, transfer bytes/speed, and sanitized errors |

All responses use `Cache-Control: no-store`. The UI page applies a restrictive Content Security Policy and cannot be embedded in another page.
