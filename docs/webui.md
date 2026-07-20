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

### Detectors

The detector view manages the compiled local pipeline:

- Select a built-in or configured preset
- Enable or disable individual modules
- Add a token-prefix rule without writing a regular expression
- Add an advanced regular-expression rule with bounded validation
- Remove rules created through the WebUI
- Dry-run the active pipeline without sending text upstream

Changes are persisted to `detector-control.json` beside `state.sqlite3`. The file is mode `0600`. Primary YAML configuration remains the source of built-in and deployment-managed modules; the WebUI state is a small overlay and does not rewrite it.

## Administration API

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `GET` | `/api/admin/overview` | Safe dashboard summary |
| `GET` | `/api/admin/audit` | Filtered audit events |
| `GET` | `/api/admin/protected-values` | Safe mapping metadata |
| `POST` | `/api/admin/protected-values/{id}/revoke` | Tombstone one mapping |
| `POST` | `/api/admin/protected-values/purge-expired` | Tombstone expired mappings |
| `GET` | `/api/admin/detectors` | Active detector catalog |
| `PUT` | `/api/admin/detectors/preset` | Select a preset |
| `PATCH` | `/api/admin/detectors/modules/{id}` | Toggle a module |
| `POST` | `/api/admin/detectors/test` | Local-only dry run |
| `POST` | `/api/admin/detectors/rules` | Add a WebUI rule |
| `DELETE` | `/api/admin/detectors/rules/{id}` | Remove a WebUI rule |

All responses use `Cache-Control: no-store`. The UI page applies a restrictive Content Security Policy and cannot be embedded in another page.
