# Local Management WebUI

PrivacyFlow serves a zero-build management panel at `/ui/`. It is designed for repeated local operations rather than provider traffic and uses an unauthenticated `/api/admin/*` control plane.

## Language

The WebUI supports Chinese and English. The language switch updates static labels, dynamically rendered tables, protection diagnostics, forms, and dialogs without reloading the page. The initial locale follows the browser language; later choices are stored under `pf_locale` in browser `localStorage` (an existing `apg_locale` value is migrated on first load).

The zero-build panel vendors Lucide `1.27.0` locally and serves it through `/ui/assets/lucide.min.js`; no icon CDN or additional CSP origin is required. Icon-only actions keep localized `aria-label` and `title` text while their SVGs remain decorative.

The locale preference contains no credential or gateway data. The management plane has no login state; the CLI and launcher output remain English-only.

## Security Boundary

The overview can return one configured local Agent credential from `PF_LOCAL_API_KEYS` so it can be copied into an Agent client. This is a PrivacyFlow-local access key, not the upstream provider key. Ordinary control-plane summaries do not return:

- Raw values from the mapping database
- Complete PF placeholders or internal mapping handles
- Mapping fingerprints
- Provider API keys
- Full PF session ids

The upstream-configuration endpoint is the deliberate provider-connection write path. It accepts named configurations over the local control plane, validates the URL, atomically writes each format, Base URL, and API key to `.privacyflow/launcher.json` with mode `0600`, hot-applies the selected profile, clears the browser key input, and returns only configured status, protocol metadata, and non-secret upstream URLs. It never echoes or audits a provider key. The launcher file and active values in SQLite are local plaintext; PrivacyFlow relies on filesystem permissions, OS-account isolation, and encrypted host storage rather than application-level encryption at rest.

Protected values are identified by an HMAC-derived `pv_...` administration id. The id supports revocation but cannot be used for placeholder materialization. Revocation tombstones the mapping and clears its stored raw value.

The operation-list, request-detail, and protected-value endpoints provide a deliberate opt-in exception. With `include_raw=false` they return `***`; with `include_raw=true` they read an original only while the referenced mapping is active. Audit-operation rows do not duplicate the original or store a complete signed placeholder, and `.privacyflow/audit.jsonl` remains free of both. Every raw read records a safe `view_audit_raw_values` or `view_protected_raw_values` management event without the viewed content. Older `.apg/audit.jsonl` files are handled only by the explicit migration command.

The WebUI and every `/api/admin/*` data or mutation endpoint require no key. PrivacyFlow binds to `127.0.0.1` by default, which is the management plane's security boundary. Do not bind PrivacyFlow to another interface unless that unauthenticated access is explicitly intended and protected by an external trusted boundary. Set `PF_ADMIN_ENABLED=false` to remove both `/ui/` and `/api/admin/*`.

Local-model installation and download are more restrictive than the rest of the unauthenticated control plane: the PrivacyFlow bind address and actual client address must both be loopback. Remote-bound or remote-client sessions can inspect status but receive `LOCAL_MODEL_SETUP_LOCAL_ONLY` for every mutation. Dependency commands come from a fixed server-side manifest and always target PrivacyFlow's isolated managed Runtime; request bodies cannot supply package names, versions, indexes, or command arguments.

Agent Connector mutations use the same double-loopback rule. Connector status may be inspected locally, but connect and restore require both PrivacyFlow's bind address and the actual client address to be loopback. Connector responses and audit events never include dedicated Connector keys.

## Views

### Overview

When the launcher has no complete provider connection, the dashboard requires a configuration name, shared Base URL, and API key before the Agent connection strip. Multiple named configurations can be saved, switched, edited, and deleted without restarting PrivacyFlow. Each configuration keeps its own provider key; editing with an empty key field preserves the saved value. Keys are never stored by the browser or returned by PrivacyFlow.

Every configuration exposes all three native formats by default. PrivacyFlow routes each local endpoint to the matching native upstream endpoint without conversion; a provider that does not support the requested format returns its own upstream error. The connectivity tester still lets users choose a format and model so each route can be checked independently. Pasting a complete terminal endpoint such as `/chat/completions`, `/responses`, or `/messages` is normalized to the shared Base URL. Rare providers with unrelated routes can use an optional full-endpoint override per format. Anthropic Messages uses `x-api-key` and `anthropic-version: 2023-06-01`; a local `/v1/messages` request stays in native Anthropic JSON/SSE form end to end, apart from PrivacyFlow's privacy transformations and system-contract injection.

The Agent connection strip displays the OpenAI-compatible and Anthropic local Base URLs simultaneously and provides an independent copy action for each. On a new launcher installation, the primary local Agent API key is generated with cryptographic randomness and persisted in the private launcher file. The key stays masked by default, and an eye icon temporarily reveals it. This strip is the manual path for unsupported Agents; the dedicated quick-connect view manages supported Agent-specific configuration. The rest of the view summarizes the latest audit window: requests, interceptions, local tool-argument materializations, active protected values, seven-day activity, and risk distribution. The upstream is represented by hostname only.

### Agent Quick Connect

The Agent quick-connect view supports installed user-level Codex, Claude Code, DeepSeek Harness, and nanobot instances. It does not install or start Agents, edit project configuration, or manage nanobot custom `--config` instances. DeepSeek Harness uses its documented endpoint provider configuration; there is no PrivacyFlow dsh plugin.

Before writing, the server refreshes the upstream model catalog and runs exactly one real protocol probe: Responses for Codex, Anthropic Messages for Claude Code, and Chat Completions for dsh and nanobot. PrivacyFlow does not translate protocols. Model discovery first tries the configured Base URL and, after a 404/405/501, retries known compatibility-prefix siblings such as the root `/v1/models` and `/models` routes; the successful endpoint is reported in the result. dsh receives the complete catalog; the other connectors receive the selected default model. A catalog failure permits manual entry for Codex, Claude Code, and nanobot, but blocks dsh because its generated catalog must be complete.

Connect is a filesystem transaction. PrivacyFlow validates regular-file ownership, rejects symbolic links, prepares and parses every result, snapshots original bytes and permissions, then atomically replaces the targets. Dedicated Connector keys are persisted privately and loaded into local request authentication without being returned by an API. Codex obtains its key through `privacyflow credential --connector codex`; the other formats use their documented local credential fields.

If a target already contains a reserved provider, preset, or environment key, the first connect attempt returns `409 CONNECTOR_CONFIG_CONFLICT` with paths only. The WebUI asks for explicit migration confirmation; the confirmed request sends `confirm_existing_config: true`. PrivacyFlow then snapshots the complete original files before replacement, so canceling leaves the configuration untouched and Restore can still return the exact pre-connect state.

Restore is the only connected-state action. It restores the exact original bytes and mode, or removes a file created by PrivacyFlow. A post-connect hash mismatch first returns `409` with paths only. After explicit confirmation, PrivacyFlow saves the current files as a safety backup and restores the baseline. The Connector key is revoked only after successful restoration. Completed transactions and safety backups are retained up to five per Connector.

| Agent endpoint | Native upstream route | Format |
| --- | --- | --- |
| `/v1/chat/completions` | Chat Completions | Native JSON and SSE |
| `/v1/messages` | Anthropic Messages | Native Anthropic JSON and SSE |
| `/v1/responses` | Responses | Native JSON and SSE |
| `/v1/models` | Models | Native |

Each local endpoint is routed to its matching native upstream route without conversion. A provider that does not implement that route returns its own upstream error, which PrivacyFlow normalizes and passes through.

### Audit

The audit view has two independent operation-level lists: **Replacement records** and **Materialization records**. Every row is one distinct recorded transformation rather than an Agent-request summary. The replacement list contains only upstream replacements; the materialization list contains successful and failed local materialization attempts. Both lists support risk, endpoint, and safe metadata filters, and use the same `pv_...` id to connect:

- `original or *** -> exact placeholder/path alias` for upstream replacement
- `exact placeholder/path alias -> original or ***` for local materialization

Repeated uses of one mapping and representation are merged with an occurrence count. The eye control is off by default and requires confirmation; it is not written to browser storage. Turning it off clears the operation list and fetches masked data, while page reload restores the hidden state. Expired, revoked, or unavailable mappings display `原文已清除` rather than recovering an audit copy.

### Protected Values

The registry exposes kind, subtype, scope, lifecycle state, materialization class, timestamps, and whether a local value is currently stored. Originals are masked by default. Its eye control requires confirmation and temporarily fetches originals only for active mappings; closing it immediately clears rendered and in-memory originals and reloads `***`. Automatic clearing is disabled by default, so active mappings display `不自动过期`. The retention control can enable idle-time clearing and set a duration from one minute to 365 days. Enabling starts a fresh deadline for all active mappings; disabling removes their pending deadlines. Active mappings can still be revoked individually, and expired records can be purged. Expired and manually revoked tombstones are displayed separately.

### Protection Pipeline

PrivacyFlow applies one fixed built-in detection pipeline to traffic. It combines
deterministic credential/API-key and personal-information rules with local-path
detection, followed by the fixed placeholder-integrity and streaming-boundary
safety layers. The global PrivacyFlow switch can enable or disable protection,
but it does not change the pipeline.

The WebUI has no detector configuration view or editor. Users cannot create, copy,
edit, activate, delete, reorder, or test detector configurations; toggle detector
modules or presets; attach local models; or choose per-detector fail-open/fail-close
behavior. No detector-configuration CRUD endpoints are exposed by the management
API.

`detector-control.json` is retained as internal fixed-pipeline state and the
global protection toggle, not as a user-editable detector registry. At startup,
stale or malformed legacy editor data is ignored and the fixed built-in pipeline
is used. An explicit `privacyflow migrate` rewrites the copied legacy detector
state to the normalized fixed form while leaving the original `.apg/` state
untouched in a read-only `.apg.legacy/<timestamp>/` backup.

PF-marker integrity and streaming-boundary protection are fixed, always-on
safety mechanisms. Exact valid same-session placeholders are restored in ordinary
client-visible response text (`local_user`) or recognized structured tool-argument
fields (`local_tool`) after signature, session, expiry, mapping-state, and policy
checks. These names classify response fields; they do not authenticate a human,
prove that a tool is local, or approve execution. PrivacyFlow does not maintain a
separate downlink denylist of previously seen secret values: if an upstream model
emits a raw value, PrivacyFlow hides it only when the fixed response detector
recognizes it as a secret. If a locally materialized protected value later re-enters
another upstream request, its active session mapping re-protects the exact value
even when the new surrounding syntax would not independently match the detector.

### Upstream Model Catalog

The model catalog follows a provider-switcher style workflow: a saved profile may provide an explicit catalog URL, otherwise PrivacyFlow derives `/v1/models` and known compatibility siblings. A 404/405/501 is the only condition that advances to the next candidate. Catalog requests use `Accept: application/json` and a stable PrivacyFlow User-Agent (or the optional profile override); an Anthropic-configured profile also sends Bearer auth alongside its native headers so a root OpenAI-compatible catalog such as DeepSeek's can be discovered. Catalog responses are bounded to 500 safe identifiers, preserve provider display names/ownership for the UI, and never persist the response payload or API key. `POST /models/preview` performs the same discovery against unsaved values without writing the launcher file. PrivacyFlow keeps display labels separate from the actual model ID; it does not rewrite model names at proxy runtime.

### Local Model Management

The local-model view manages manually added Hugging Face repositories or local
directories independently of the fixed traffic pipeline. It does not create or
attach detector modules. Its primary control is a single model-address input
followed by **Add and prepare**. PrivacyFlow recognizes `owner/model`, Hugging Face
URLs, and existing local directories, then inspects metadata before doing any large
download. Runtime, dependency, cache, and device information lives in a collapsed
advanced section.

Adapter and device preferences default to `auto`. Hugging Face `pipeline_tag`, `config.json.model_type`, and `architectures` select GLiNER or Transformers token classification only when the result is unambiguous; otherwise the model enters `needs_input`. Automatic device selection prefers CUDA, then Apple MPS, then CPU. An explicitly selected unavailable device produces an actionable error and is never silently replaced.

Each model can run the combined `inspect → runtime → download → verify` operation or a context-specific repair. PrivacyFlow builds a fixed, versioned environment under `runtimes/model-runtime-v1/` beside the database, verifies it in a temporary directory, and atomically replaces the active Runtime only after success. Model libraries are not installed into PrivacyFlow's own environment.

A persistent private JSON-lines Worker performs `load`, `infer`, `unload`, and `health`. Models are loaded lazily and reused. The Worker uses offline Hugging Face mode, never enables `trust_remote_code`, and receives no upstream API key, Agent key, signing key, or Hugging Face token. A crashed Worker is restarted once; Worker errors do not change the fixed traffic pipeline.

Manual entries and validation records persist in the mode-`0600`, version-2 `local-models.json` beside the SQLite database. Hugging Face snapshots use the sibling `models/` cache. PrivacyFlow does not copy or delete user-owned local directories. Because local models are not attached to the fixed traffic pipeline, managed cache deletion is independent of that pipeline. Explicit user downloads are independent of the runtime `allow_model_download` switch.

The ordinary test suite never installs packages or downloads models. To explicitly exercise a real CPU-only dependency install, tiny Hugging Face snapshot download, load, and inference inside a temporary virtual environment, run:

```bash
PF_RUN_LOCAL_MODEL_INTEGRATION=1 .venv/bin/pytest -q tests/test_local_models_integration.py
```

## Administration API

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `GET` | `/api/admin/overview` | Safe dashboard summary |
| `GET` | `/api/admin/connection` | One local Agent API key and protocol base paths |
| `GET` | `/api/admin/agent-connectors` | Installation, paths, protocol, connection, and external-change status without keys |
| `POST` | `/api/admin/agent-connectors/{id}/connect` | Probe the required protocol and transactionally connect an installed Agent |
| `POST` | `/api/admin/agent-connectors/{id}/restore` | Restore the exact pre-connect snapshot, with explicit external-change confirmation |
| `GET` | `/api/admin/upstream-configuration` | Provider-key configured status and safe upstream metadata |
| `PUT` | `/api/admin/upstream-configuration` | Validate, persist, and hot-apply an upstream Base URL and provider API key without echoing the key |
| `GET` | `/api/admin/upstream-configuration/models` | Fetch the active provider catalog; `X-PF-Model-Catalog: rich`, `profile_id`, or `refresh=true` returns display options, source, cache time, and categorized errors |
| `POST` | `/api/admin/upstream-configuration/models/preview` | Fetch an unsaved catalog from `{base_url, protocol, api_key, models_url?, user_agent?}` without persistence or secret echo |
| `GET` | `/api/admin/audit` | Filtered audit events |
| `GET` | `/api/admin/audit/operations` | Separate replacement or materialization operation list; optional `include_raw=true` |
| `GET` | `/api/admin/audit/requests` | Request-level replacement/materialization summaries |
| `GET` | `/api/admin/audit/requests/{request_id}` | Per-operation detail; optional `include_raw=true` |
| `GET` | `/api/admin/protected-values` | Mapping metadata; optional `include_raw=true` |
| `PUT` | `/api/admin/protected-values/retention` | Save revision-protected automatic-clearing state and idle duration |
| `POST` | `/api/admin/protected-values/{id}/revoke` | Tombstone one mapping |
| `POST` | `/api/admin/protected-values/purge-expired` | Tombstone expired mappings |
| `GET` | `/api/admin/local-models` | Managed Runtime, devices, model catalog, cache, and active-job status |
| `POST` | `/api/admin/local-models` | Add a model with automatic/explicit source, Adapter, and device; `prepare: true` starts one-click preparation |
| `DELETE` | `/api/admin/local-models/{id}` | Remove a manual catalog entry without deleting shared cache |
| `DELETE` | `/api/admin/local-models/{id}/cache` | Safely remove PrivacyFlow-managed cache when it is not active |
| `POST` | `/api/admin/local-models/prepare` | Start an allowlisted inspect/runtime/download/verification job (`dependencies` remains a runtime alias) |
| `GET` | `/api/admin/local-model-jobs/{id}` | Poll stage, total progress, transfer bytes/speed, and sanitized errors |

All responses use `Cache-Control: no-store`. The UI page applies a restrictive Content Security Policy and cannot be embedded in another page.
