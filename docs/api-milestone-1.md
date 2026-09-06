# AegisNet — API Surface for Milestone 1

Scope: **Milestone 1 only** — foundation, ingest, normalization, asset inventory, event read.
No detectors, no incidents, no AI in M1. Status: **implemented in Chunks 3 – 6.** The later
milestones' contracts (`api-milestone-2.md`, `-3.md`, `-5.md`) build on the conventions, error
envelope, auth and rate limits set out here.
Last updated: 2026-09-06

Base path: `/api/v1`. All responses `application/json`. All request bodies validated with Pydantic v2
(`model_config = ConfigDict(extra="forbid")` on every DTO).

## Auth model in M1

M1 ships the *minimum viable* auth so ingest is never anonymous; full RBAC hardening lands in M6.

- `Authorization: Bearer <jwt>` for user endpoints (HS256, 15 min; ADR-016).
- `X-Ingest-Token: <token>` for ingest endpoints (service tokens, `ingest_service` role; may also read `/meta/version`).
- Roles present from M1: `admin`, `analyst`, `viewer`, `ingest_service`. Every route declares a required
  permission via a FastAPI dependency; there is no implicit-allow path.

## Standard error shape

```json
{
  "error": {
    "code": "validation_failed",
    "message": "Request body failed validation.",
    "correlation_id": "3f9c1a5e-...",
    "details": [{"field": "body.events[3].timestamp", "issue": "invalid datetime"}]
  }
}
```
No stack traces, no SQL, no internal paths (T-2.7). `correlation_id` matches the server log entry.

## Rate limits (M1 defaults, Redis-backed)

| Endpoint group | Limit |
|---|---|
| `POST /auth/login` | 5 / 15 min per IP **and** per account; 5 consecutive failures lock the account for 15 min (exponential backoff: M6) |
| `POST /ingest/*` | 30 requests/min per token; 200 MB/hour per token |
| Read endpoints | 120 requests/min per user |
| Everything else | 60 requests/min per subject |

Exceeded → `429` with `Retry-After`. If Redis is unreachable, login and ingest refuse (`429`); reads and the default group proceed and log an error (ADR-016).

---

## Endpoints

### Health & meta

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `GET` | `/healthz` | none | Liveness. `{"status":"ok"}` |
| `GET` | `/readyz` | none | Readiness: DB + Redis reachable. `503` when not |
| `GET` | `/api/v1/meta/version` | any authed | App version, git sha, schema revision |

### Auth

**`POST /api/v1/auth/login`**
```json
{ "email": "analyst@example.test", "password": "..." }
```
→ `200 { "access_token": "...", "token_type": "bearer", "expires_in": 900 }` and a `HttpOnly; Secure;
SameSite=Strict` refresh cookie. Generic `401 invalid_credentials` on any failure (no user enumeration).
Audit: `auth.login_success` / `auth.login_failed`.

**`POST /api/v1/auth/refresh`** — rotates the refresh token; reuse of a rotated token revokes the chain → `401`.
**`POST /api/v1/auth/logout`** — revokes the refresh chain. `204`.
**`GET /api/v1/auth/me`** — `{ id, email, display_name, role }`.

### Ingest

**`POST /api/v1/ingest/eve`** — `ingest_service` or `admin`

Two content types:

1. `application/x-ndjson` — raw EVE lines, streamed and parsed line by line.
2. `multipart/form-data` — field `file` (an `.json`/`.ndjson`/`.log` file) + optional `source_label`.

Query/form parameters (validated):

| Param | Type | Default | Notes |
|---|---|---|---|
| `source_label` | str, 1–64 chars, `^[A-Za-z0-9._-]+$` | required | free-form label for provenance |
| `dataset_id` | str NULL | none | must exist in `samples/registry.yml` if supplied |
| `mode` | `sync` \| `async` | `async` | `sync` capped at 1,000 lines, for tests/demos |

Hard limits (T-1.4/T-1.5), all configurable, all enforced **before** parsing:
`max_body_bytes = 50 MB`, `max_lines = 200_000`, `max_line_bytes = 64 KB`, `max_json_depth = 12`,
`max_json_keys_per_object = 200`.

Response `202 Accepted` (async):
```json
{
  "batch_id": "9c2f...",
  "status": "normalizing",
  "events_received": 12045,
  "accepted_at": "2026-08-28T01:22:04Z",
  "poll_url": "/api/v1/ingest/batches/9c2f..."
}
```
Response `200 OK` (sync) returns the completed batch summary including `events_stored`,
`events_duplicate`, `events_rejected`.

Behaviour guarantees:
- Idempotent: a re-posted identical file yields `events_duplicate == events_received` and stores nothing new.
- Partial tolerance: bad lines land in `ingest_rejects`; the batch still completes.
- Never reflects raw log content back in the response body beyond a sanitized 256-char excerpt.

**`POST /api/v1/ingest/import`** — `admin`
```json
{ "dataset_id": "synthetic-portscan-01", "source_label": "demo-run-1" }
```
Resolves `dataset_id` against the committed registry, verifies the recorded checksum, resolves the real path and
asserts it is inside `samples/`, then ingests. **No path parameter is accepted from the client** (T-1.6).
→ `202` with the same batch envelope.

**`GET /api/v1/ingest/batches`** — `analyst`+ · paginated list, filters `status`, `source_label`, date range.
**`GET /api/v1/ingest/batches/{batch_id}`** — `analyst`+ · full batch detail with counts, timings, dataset licence/citation.
**`GET /api/v1/ingest/batches/{batch_id}/rejects`** — `analyst`+ · paginated rejects with `reason_code`, `line_number`, sanitized excerpt.

### Assets

**`POST /api/v1/assets`** — `analyst`+
```json
{
  "hostname": "lab-web-01",
  "environment": "lab",
  "owner": "platform-team",
  "criticality": 4,
  "tags": ["web", "dmz"],
  "description": "Lab web server",
  "networks": [{ "cidr": "192.0.2.10/32", "is_primary": true }]
}
```
Validation: `criticality` 1–5; `environment` enum; `cidr` parsed with `ipaddress`; overlapping CIDRs across
assets rejected with `409 network_overlap`; `tags` max 20 items, each ≤32 chars, `^[a-z0-9-]+$`.
→ `201` with the created asset.

**`GET /api/v1/assets`** — `viewer`+ · filters `environment`, `criticality_min`, `tag`, `q` (hostname substring); paginated.
**`GET /api/v1/assets/{asset_id}`** — `viewer`+
**`PATCH /api/v1/assets/{asset_id}`** — `analyst`+ · partial update; audit-logged with before/after diff.
**`DELETE /api/v1/assets/{asset_id}`** — `admin` · soft delete (`is_active=false`); historical links preserved.
**`POST /api/v1/assets/bulk`** — `admin` · array of assets (max 500) for seeding, atomic.
**`GET /api/v1/assets/resolve?ip=192.0.2.10`** — `viewer`+ · returns the matching asset or `{"matched": false}` using
most-specific-CIDR-wins. Exists so detector/asset-resolution behaviour is testable through the API in M1.

### Events (read-only)

**`GET /api/v1/events`** — `viewer`+

| Filter | Notes |
|---|---|
| `from` / `to` | ISO-8601, required together; max span 30 days |
| `event_type` | enum, repeatable |
| `src_ip` / `dest_ip` | exact or CIDR |
| `dest_port` | int, repeatable |
| `flow_id` | bigint |
| `batch_id` | uuid |
| `asset_id` | uuid — resolves via `asset_networks` |
| `limit` / `cursor` | keyset pagination on `(event_time, id)`; `limit` max 200, default 50 |

> `event_time` is when the event happened, which for a **flow** record is `flow.start` rather
> than the record's own timestamp — Suricata stamps a flow record when it emits it (ADR-022).
> The emission time is in the event's `payload`.

Returns promoted columns plus a **redaction-aware** `payload`. `payload` is included only for `analyst`+; `viewer`
receives promoted columns only. Response includes `X-Query-Duration-ms` for the latency NFR.

**`GET /api/v1/events/{event_id}`** — `analyst`+ · single event with full validated payload.
**`GET /api/v1/events/stats`** — `viewer`+ · counts by `event_type` and by hour over the requested window; powers the M1 sanity dashboard.

### Audit (present from M1, read-only)

**`GET /api/v1/audit`** — `admin` · paginated, filters `action`, `actor`, `result`, date range. No mutation endpoints exist.

---

## Not in Milestone 1

`/detections/*`, `/alerts/*`, `/incidents/*`, `/incidents/{id}/brief`, `/incidents/{id}/report.md`, and all
Perplexity-related routes are specified in later milestones. They are intentionally absent from the M1 OpenAPI
document so the milestone gate is unambiguous.

## Acceptance criteria for the M1 API

- [x] OpenAPI docs generated and reachable at `/docs` (disabled when `ENV=production`) — `tests/integration/test_meta.py`.
- [x] Every route has an explicit permission dependency; a test enumerates routes and fails on any route without one — `tests/security/test_rbac.py` (Chunk 6).
- [x] Posting the committed synthetic sample twice yields identical stored-event counts (idempotency test) — `tests/db/test_ingest_store.py`, `make demo-ingest` twice (Chunk 4).
- [x] Oversized body, oversized line, deep JSON, and traversal attempts all return `4xx` and are audit-logged — an oversized body is refused with `413` and audited as `ingest.refused` (Chunk 6); an oversized line or deep JSON becomes a reject row with a reason code inside an audited batch (Chunk 4); a traversal attempt in `dataset_id` is refused with `422` by validation and audited as `ingest.refused` naming the field, never the value (Chunk 7, `tests/integration/test_ingest_routes.py`).
- [x] `GET /api/v1/assets/resolve` returns the most specific CIDR match under an overlapping-network fixture — `tests/db/test_asset_store.py` (Chunk 5), `tests/integration/test_asset_routes.py` (Chunk 6).
- [x] `viewer` cannot read `events[].payload`; `analyst` can. Asserted in the RBAC matrix test — `tests/security/test_rbac.py`, `tests/integration/test_event_routes.py` (Chunk 6).
