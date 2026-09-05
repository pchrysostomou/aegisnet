# Security

AegisNet is a local, single-tenant security-analytics stack for a lab. Nothing is
released yet and no deployment beyond a developer's machine is supported. This document
records what the code enforces today (Milestone 1, Chunk 6), how to verify it, and what
is deliberately still missing. `THREAT_MODEL.md` carries the threat catalogue this maps
to; `docs/api-milestone-1.md` is the API contract.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting on this repository (**Security → Report a
vulnerability**). Please do not open a public issue for anything exploitable. Include the
commit, the steps, and what you observed; a proof of concept against the committed
synthetic corpus is welcome. Because there is no release yet there is no supported-version
table: fixes land on `main`.

## Authentication

| Credential | Who | Form | Lifetime | Storage |
|---|---|---|---|---|
| Password | users | Argon2id (`argon2-cffi` defaults) | until changed | hash only |
| Access token | users | HS256 JWT, `Authorization: Bearer` | 15 min (`ACCESS_TTL_SECONDS`) | not stored; `jti` denylisted on logout |
| Refresh token | users | 32 random bytes, `HttpOnly; Secure; SameSite=Strict` cookie scoped to `/api/v1/auth` | 14 days (`REFRESH_TTL_DAYS`), rotated on every use | sha256 only |
| Service token | sensors, CI | 32 random bytes, `X-Ingest-Token` | ≤ 365 days, set at creation | sha256 only |

- **Password policy** is length only, 12–128 characters, no leading or trailing
  whitespace. Composition rules are deliberately absent.
- **Login** answers the same `401 invalid_credentials` body for an unknown address, a
  wrong password, an inactive account and a locked account; the reason goes to the audit
  trail, never to the caller. A dummy Argon2id verification runs for unknown addresses so
  the response time does not reveal whether an account exists.
- **Lockout**: after `LOGIN_MAX_FAILURES` (5) consecutive failures the account is locked
  for `LOGIN_LOCKOUT_MINUTES` (15). The counter resets on success. Exponential backoff is
  deferred to Milestone 6.
- **Access tokens** carry `iss`, `sub`, `role`, `email`, `iat`, `exp`, `jti`. Verification
  requires every claim, checks the signature and issuer, and checks `exp`/`iat` against
  the service clock with 30 s of tolerance rather than against PyJWT's wall clock, so a
  token whose lifetime exceeds policy is refused even if it was signed with the real key.
  The stored role wins over the claim: a demoted or deactivated user's tokens die at once.
- **Refresh tokens** rotate on every use. Presenting a rotated or revoked token is
  treated as theft: the whole chain is revoked, `auth.refresh_reuse_detected` is audited,
  and the cookie is cleared. Logout revokes the chain and denylists the current access
  token's `jti` in Redis for its remaining life.
- **Service tokens** are the only credential ingest sensors hold. They carry the
  `ingest_service` role and can do nothing but ingest and read the version route. They are
  minted and revoked from the operator CLI (`make create-service-token`,
  `make revoke-service-token`) and printed exactly once.
- **Users** are created only from the operator CLI (`make create-user`). The password is
  read from stdin, never from argv, so it stays out of shell history and process lists.
  There is no self-registration and no password reset in Milestone 1.

`SECRET_KEY` must be at least 32 bytes; the application refuses to start otherwise.
`make bootstrap` generates one. Every secret is redacted from the JSON logs by value.

## Authorisation

Every route declares the permission it needs through one FastAPI dependency; a security
test enumerates the router and fails on any route without one. The allowlist of
credential-free routes is exactly `GET /healthz`, `GET /readyz`, `POST /api/v1/auth/login`
and `POST /api/v1/auth/refresh`. A present-but-invalid credential is refused with `401`,
never downgraded to anonymous. A denial is `403 forbidden` and is audited as
`rbac.denied` with the route and the permission.

| Permission | viewer | analyst | admin | ingest_service |
|---|:-:|:-:|:-:|:-:|
| `meta.read` — `/api/v1/meta/version` | ✓ | ✓ | ✓ | ✓ |
| `auth.self` — `/auth/me`, `/auth/logout` | ✓ | ✓ | ✓ | |
| `assets.read` — list, get, resolve | ✓ | ✓ | ✓ | |
| `events.read` — list, stats (no payload) | ✓ | ✓ | ✓ | |
| `alerts.read` — alerts, alert detail, the rule registry | ✓ | ✓ | ✓ | |
| `assets.write` — create, patch | | ✓ | ✓ | |
| `events.payload` — payload in lists, `GET /events/{id}` | | ✓ | ✓ | |
| `ingest.read` — batches, rejects | | ✓ | ✓ | |
| `detections.read` — detector runs | | ✓ | ✓ | |
| `assets.admin` — bulk create, deactivate | | | ✓ | |
| `ingest.write` — `POST /ingest/eve` | | | ✓ | ✓ |
| `ingest.import` — `POST /ingest/import` | | | ✓ | |
| `audit.read` — `GET /audit` | | | ✓ | |
| `detections.run` — `POST /detections/sweeps` | | | ✓ | |

Roles nest (viewer ⊂ analyst ⊂ admin) and a service token is not a user: it cannot read
its own batches. The matrix is `ROLE_PERMISSIONS` in `backend/src/aegisnet/domain/auth.py`
and is asserted role by route in `backend/tests/security/test_rbac.py`.

## Audit trail

`audit_log` is append-only for the runtime role (`SELECT`, `INSERT`; `UPDATE`, `DELETE`
and `TRUNCATE` are refused by PostgreSQL, proven by `tests/db/test_grants.py`). Each row
carries the action, target, result, actor (user id or service-token id), client address,
correlation id and a bounded detail object. `detail` is sanitised before it is written:
keys that look like credentials (`password`, `secret`, `token`, `api_key`, `authorization`,
`cookie`, `credential`) are dropped, control characters are stripped, values are capped
at 512 characters, at most 32 keys and one level of nesting are kept.

Actions written today: `auth.login_success`, `auth.login_failed`, `auth.refresh`,
`auth.refresh_reuse_detected`, `auth.logout`, `rbac.denied`, `ingest.batch_created`,
`ingest.import_requested`, `ingest.refused`, `asset.created`, `asset.updated`,
`asset.deactivated`, `user.created`, `service_token.created`, `service_token.revoked`,
`detection.sweep_requested`, `detection.baselines_requested`.
Admins read the trail at `GET /api/v1/audit` (newest first, filters, keyset cursors).

## Rate limits

Fixed windows in Redis, one counter per limit, subject and window; `429` with
`Retry-After` when exceeded.

| Limit | Default | Subject | If Redis is down |
|---|---|---|---|
| Login | 5 / 15 min | client address **and** account (hashed) | refuse (`429`) |
| Ingest requests | 30 / min | token or user | refuse |
| Ingest bytes | 200 MiB / hour | token or user | refuse |
| Reads | 120 / min | principal | allow, log an error |
| Everything else | 60 / min | principal | allow, log an error |

Fail-closed for the routes an attacker would push on, fail-open for reads so an analyst
is not locked out by a cache outage. The client address is the transport peer; proxy
headers are not trusted in Milestone 1 because nothing terminates TLS in front of the API.

## Ingest hardening

- A declared `Content-Length` above `INGEST_MAX_BODY_BYTES` (50 MiB) is refused before a
  byte is read; a body without one is streamed to the spool under the same cap and
  discarded the moment it crosses it. Both refusals are audited as `ingest.refused`.
- `mode=sync` parses at most `INGEST_SYNC_MAX_LINES` (1000) lines inline; larger uploads
  must use `mode=async`, where the API opens the batch row and hands the worker the spool
  entry's name only (ARCHITECTURE TB-5: messages carry ids, never data). The spool is a
  named Docker volume shared by the `api` and `worker` services and nothing else.
- Per-line caps (length, nesting depth, key and item counts), the line budget per batch,
  and the sanitiser that strips control characters from anything that can reach a log or
  a screen are unchanged from Chunks 3 and 4.
- Dataset imports accept a registered dataset id only, never a path.

## What is not there yet

- TLS and a reverse proxy; the API and web ports bind to `127.0.0.1` only. `COOKIE_SECURE`
  defaults to `true`, so a browser will not return the refresh cookie over plain HTTP; the
  quickstart sends credentials as headers and never relies on the cookie.
- Exponential login backoff, password reset, multi-factor authentication, session
  listing, per-user token revocation from the API, user administration over HTTP.
- Read-only container filesystems and image digest pinning (`THREAT_MODEL.md` T-5.1).
- Any outbound integration: no Perplexity call has ever been made.

## Verification

`backend/tests/unit/test_auth_domain.py`, `test_auth_service.py`, `test_audit_service.py`,
`test_redis_adapters.py` (fakeredis), `test_spool.py`, `test_cli_auth.py`;
`backend/tests/security/test_rbac.py` (route enumeration and the matrix);
`backend/tests/integration/test_auth_routes.py`, `test_ingest_routes.py`,
`test_asset_routes.py`, `test_event_routes.py`, `test_audit_routes.py`;
`backend/tests/db/test_auth_store.py`, `test_audit_store.py`, `test_grants.py`. The
`stack` CI job creates a user and a service token through the CLI, proves the version
route answers `401` without a credential, ingests the synthetic corpus over HTTP with a
service token, and reads the finished batch and the audit trail as the user.
