# Local Management WebUI

APG serves a zero-build management panel at `/ui/`. It is designed for repeated local operations rather than provider traffic and uses the authenticated `/api/admin/*` control plane.

## Security Boundary

The browser receives only operational metadata. The control plane does not return:

- Raw values from the mapping database
- Complete APG placeholders or internal mapping handles
- Mapping fingerprints
- Provider API keys
- Full APG session ids

Protected values are identified by an HMAC-derived `pv_...` administration id. The id supports revocation but cannot be used for placeholder materialization. Revocation tombstones the mapping and clears its stored raw value.

Set a dedicated administrator key where possible:

```bash
export APG_ADMIN_API_KEYS='a-random-local-admin-key'
```

When `APG_ADMIN_API_KEYS` is absent, the WebUI accepts `APG_LOCAL_API_KEYS` for backward compatibility. The browser stores the entered key in `sessionStorage`; it is cleared when the browser session ends. Static UI assets contain no credentials and may load before authentication, while every data and mutation endpoint requires the administrator key.

APG binds to `127.0.0.1` by default. If the gateway is deliberately bound to another interface, terminate TLS in front of it and use a separate administrator key. Set `APG_ADMIN_ENABLED=false` to remove both `/ui/` and `/api/admin/*`.

## Views

### Overview

The dashboard summarizes the latest audit window: requests, interceptions, local tool-argument materializations, active protected values, seven-day activity, and risk distribution. The upstream is represented by hostname only.

### Audit

Audit events can be filtered by phase, risk, endpoint, and safe metadata. Session ids are one-way shortened for correlation. Detection rows expose type, subtype, detector, risk, action, sink, and safe result code; previews and raw values are omitted.

### Protected Values

The registry exposes kind, subtype, scope, lifecycle state, materialization class, timestamps, and whether a local value is currently stored. It never provides a reveal operation. Active mappings can be revoked individually, and expired records can be purged.

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
| `GET` | `/api/admin/audit` | Filtered audit events |
| `GET` | `/api/admin/protected-values` | Safe mapping metadata |
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
