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
| `incidents.read` — cases, their alerts, timeline and notes | ✓ | ✓ | ✓ | |
| `briefs.read` — investigation briefs on a case | ✓ | ✓ | ✓ | |
| `assets.write` — create, patch | | ✓ | ✓ | |
| `events.payload` — payload in lists, `GET /events/{id}` | | ✓ | ✓ | |
| `ingest.read` — batches, rejects | | ✓ | ✓ | |
| `detections.read` — detector runs | | ✓ | ✓ | |
| `incidents.write` — status transitions, notes | | ✓ | ✓ | |
| `briefs.generate` — ask for a brief (spends budget, sends a packet outward) | | ✓ | ✓ | |
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
`detection.sweep_requested`, `detection.baselines_requested`,
`incident.status_changed`, `incident.status_change_refused`, `incident.note_added`,
`brief.generated`.
Admins read the trail at `GET /api/v1/audit` (newest first, filters, keyset cursors).

An incident transition writes `incident.status_changed` on success and
`incident.status_change_refused` with `result: denied` when the workflow forbade the move or
another analyst had already moved the case; the detail names the statuses and the reason, never
the analyst's own words. A note writes `incident.note_added` carrying only the note's id and its
length. **No analyst free text reaches this table**: the 512-character cap and the
control-character strip would make an audited copy differ from the note it claims to be, and the
credential-key filter cannot see into prose. The text lives in `incident_notes`, and a closure
reason lives on the case and in its timeline (ADR-024).

Asking for a brief writes `brief.generated` — `success` when one was produced, `error` when it
could not be, with the reason. The detail carries the version, the status, the source and the
**SHA-256 of the evidence packet**: which question was asked, not the question itself and not the
answer. The packet is written nowhere, because a copy of it would be a second, quieter record of
the same evidence; it is reconstructible from the case, and the hash is what makes two attempts
comparable. The brief's own words live in `investigation_briefs`, which is append-only for the
same reason this table is (ADR-031).

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
| Outbound briefs | `BRIEF_DAILY_BUDGET` / UTC day | the whole deployment | refuse — the counter is the cap |

Fail-closed for the routes an attacker would push on, fail-open for reads so an analyst
is not locked out by a cache outage. The brief budget is the exception to "per principal": it is
one number for the deployment, counted in Redis rather than in each process, because the API, the
worker and the CLI each hold their own client and three private counters are three caps. An
attempt past it is not a `429` — it is a stored brief with `failure_reason: budget_exhausted`. The client address is the transport peer; proxy
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

## The isolated lab

The lab (`infra/lab/`, [ADR-021](docs/adr/ADR-021-isolated-suricata-lab.md)) is the only part
of this repository that touches a network interface, and it is opt-in: every service carries
the `lab` profile, so nothing starts without `--profile lab`, and the application stack never
starts it.

- Its network is `internal: true`, which removes the default route, **and** sets
  `com.docker.network.bridge.inhibit_ipv4`, which leaves the bridge without an address of its
  own. The second matters: without it, a container reaches whatever the Docker host listens
  on at the subnet's first address over its own on-link route, no default route required.
  `make lab-preflight` proves the result from inside a running container instead of trusting
  the declaration, and fails the run if anything answers.
- The sensor runs in **IDS mode only** and cannot act on traffic: no inline transport, no
  `copy-mode`, no IPS flag, and every rule begins with `alert`. Tests assert all of it.
- It is the one place where a capability is added back after `cap_drop: ALL`: `NET_RAW`, on
  the sensor alone, because no capability-less process can open a packet socket. The list is
  pinned by a test, so widening it is a visible decision.
- The generator has exactly one destination, the lab's own target, addressed by compose
  service name. A test walks every committed lab file and fails on any address outside
  documentation and private space, any name outside `example.test`/`example.com`, and any
  mention of scanning or exploitation tooling.
- A capture is written into a Docker volume, not onto the host, and reaches the operator's
  disk only through `make lab-export`. Publishing an excerpt requires `tools/sanitize_eve.py`,
  which strips content-bearing fields and then refuses to write at all if what remains holds
  an unclassified key, an address or hostname outside documentation space (anywhere,
  including inside a list or a URL), or a URL parameter whose name announces a credential.
  `--check` re-runs that refusal against a file as it sits on disk, so it is an assertion
  about the committed bytes.

`docs/evaluation.md` §7 is the pre-flight checklist an operator works through before a run,
and §9 records what the first run found.

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
