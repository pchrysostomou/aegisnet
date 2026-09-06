# Security

AegisNet is a local, single-tenant security-analytics stack for a lab. It runs on one
machine under `docker compose` and binds to loopback; no deployment beyond that is supported.
This document records what the code enforces at v1.0.0 (Milestone 6, Chunk 31), how to verify
it, and what is deliberately still missing. `THREAT_MODEL.md` carries the threat catalogue this
maps to. The API contract is `docs/api-milestone-1.md` together with the additions in
`docs/api-milestone-2.md` (detections), `docs/api-milestone-3.md` (incidents) and
`docs/api-milestone-5.md` (briefs and the Markdown export); Milestone 4 is the dashboard and
added no routes.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting on this repository (**Security → Report a
vulnerability**). Please do not open a public issue for anything exploitable. Include the
commit, the steps, and what you observed; a proof of concept against the committed
synthetic corpus is welcome. There is one release and one supported version, `v1.0.0`: fixes
land on `main` and go out in the next tag, and nothing is back-ported to an older one.

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
- **Lockout**: after `LOGIN_MAX_FAILURES` (5) consecutive failures the account is locked for
  `LOGIN_LOCKOUT_MINUTES` (15), and **each further failure doubles the lock** up to
  `LOGIN_LOCKOUT_MAX_MINUTES` (60) — 15, 30, 60, 60 … The ceiling is an hour rather than a day
  because there is no unlock command, so it is also the longest an operator can be shut out of
  their own deployment with no way back in. The counter resets on a successful login, and a lock
  nobody has touched for `LOGIN_FAILURE_RESET_HOURS` (24) is forgotten, so the escalation is not
  permanent for an account that never manages to log in. None of this is visible to the caller:
  a locked account, a wrong password and an unknown address all answer with the same `401`.
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
  There is no self-registration and no password reset.

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
| `incidents.read` — cases, their alerts, timeline, notes and the Markdown export | ✓ | ✓ | ✓ | |
| `briefs.read` — investigation briefs on a case | ✓ | ✓ | ✓ | |
| `assets.write` — create, patch | | ✓ | ✓ | |
| `events.payload` — payload in lists, `GET /events/{id}` | | ✓ | ✓ | |
| `ingest.read` — batches, rejects | | ✓ | ✓ | |
| `detections.read` — detector runs and baselines | | ✓ | ✓ | |
| `incidents.write` — status transitions, notes | | ✓ | ✓ | |
| `briefs.generate` — ask for a brief (spends budget, sends a packet outward) | | ✓ | ✓ | |
| `assets.admin` — bulk create, deactivate | | | ✓ | |
| `ingest.write` — `POST /ingest/eve` | | | ✓ | ✓ |
| `ingest.import` — `POST /ingest/import` | | | ✓ | |
| `audit.read` — `GET /audit` | | | ✓ | |
| `detections.run` — `POST /detections/sweeps`, `POST /detections/baselines/recompute` | | | ✓ | |

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
`ingest.import_requested`, `ingest.refused`, `asset.created`, `asset.bulk_created`,
`asset.updated`, `asset.deactivated`, `user.created`, `service_token.created`,
`service_token.revoked`, `detection.sweep_requested`, `detection.baselines_requested`,
`incident.status_changed`, `incident.status_change_refused`, `incident.note_added`,
`brief.generated`, `report.exported`, `retention.pruned`.
Admins read the trail at `GET /api/v1/audit` (newest first, filters, keyset cursors).

An incident transition writes `incident.status_changed` on success and
`incident.status_change_refused` with `result: denied` when the workflow forbade the move or
another analyst had already moved the case; the detail names the statuses and the reason, never
the analyst's own words. A note writes `incident.note_added` carrying only the note's id and its
length. **No analyst free text reaches this table**: the 512-character cap and the
control-character strip would make an audited copy differ from the note it claims to be, and the
credential-key filter cannot see into prose. The text lives in `incident_notes`, and a closure
reason lives on the case and in its timeline (ADR-024).

The retention job writes `retention.pruned` — how many rows went from each table and the oldest
cutoff it used, never a row it removed. It is written by the **app** role, which cannot delete;
the deleting is done by `aegisnet_retention`, a third role holding `SELECT, DELETE` on the four
tables with a period and no ability to write anywhere. That split is what lets `audit_log` stay
append-only for the application while still having a bound, and it means a deletion with no
trace would need two credentials (ADR-033).

Exporting a case as Markdown writes `report.exported` with the case number and the document's
size in bytes — never the document. It is the only **read** in this API that writes an audit
row, and it is deliberate: an export is the whole case as plain text in a file somebody can
forward, and FR-10.3 names it an auditable event. It appends nothing to the case itself, so two
exports of an unchanged case are the same bytes (ADR-032).

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

**Statement budgets.** Rate limits bound what a caller may ask for; `DB_STATEMENT_TIMEOUT_MS`
(5 s) bounds what the database then spends on it. The worker, the CLI and the retention prune get
`DB_JOB_STATEMENT_TIMEOUT_MS` (5 min), because a sweep over 200 000 events legitimately does more
work than a request should, and the migrator gets none at all — an index build over a populated
table must never be cancelled half way. A cancelled statement answers `503 service_unavailable`,
which is the honest thing to say: the query asked for too much and a narrower one may work.

| Limit | Default | Subject | If Redis is down |
|---|---|---|---|
| Login, per account | `RATE_LIMIT_LOGIN_PER_15MIN` (5) | account (hashed) | refuse (`429`) |
| Login, per address | `RATE_LIMIT_LOGIN_IP_PER_15MIN` (5) | client address | refuse (`429`) |
| Ingest requests | 30 / min | token or user | refuse |
| Ingest bytes | 200 MiB / hour | token or user | refuse |
| Reads | 120 / min | principal | allow, log an error |
| Everything else | 60 / min | principal | allow, log an error |
| Outbound briefs | `BRIEF_DAILY_BUDGET` / UTC day | the whole deployment | refuse — the counter is the cap |
| Brief asks, per analyst | `BRIEF_USER_DAILY_LIMIT` / UTC day | the user | refuse |
| Brief asks, per case | `BRIEF_INCIDENT_DAILY_LIMIT` / UTC day | the incident | refuse |

Three of these have been *measured* under concurrency rather than merely declared — the read
bucket, the default bucket and login. `make load-test` fires whole budgets at once against a running stack and
`docs/evaluation.md` §10 records what came back: 120 of 180 concurrent reads allowed, `429` with a
usable `Retry-After` for the rest, reads and writes counted apart, login refused after five wrong
passwords, and the fixed-window edge costing exactly one extra budget and never more.

The two ingest limits now have load tests of their own — the request limit fired as a whole
budget at once, and a refused ingest checked for anything left behind in the spool — so the
suite is seven tests rather than five. **They have not been run for a release**: `make load-test`
needs a stack somebody owns and spends fifteen-minute login budgets, so
`docs/RELEASE_CHECKLIST.md` leaves that box deliberately unticked and `docs/evaluation.md` §10
still records only the four limits measured in Chunk 26. Written and not yet measured is a
weaker claim than measured, and it is the true one. The three brief limits are not in
that suite at all: their window is
a day, so firing a budget at once would leave the deployment unable to ask for a brief until
midnight. They are held instead by `tests/security/test_brief_limits.py`, which exhausts each one
over HTTP and proves each fails closed on its own.

**One limit is not a counter.** `INGEST_UPLOAD_TIMEOUT_SECONDS` (120 s) bounds how long a request
body may take to arrive. Every other ingest limit bounds a *size*, and no size cap is ever reached
by a body delivered one byte at a time; past the deadline the partial upload is discarded, the
refusal is `408 request_timeout`, and it is audited as `ingest.refused` like any other (T-1.4).

Fail-closed for the routes an attacker would push on, fail-open for reads so an analyst
is not locked out by a cache outage. The brief budget is the exception to "per principal": it is
one number for the deployment, counted in Redis rather than in each process, because the API, the
worker and the CLI each hold their own client and three private counters are three caps. An
attempt past it is not a `429` — it is a stored brief with `failure_reason: budget_exhausted`.
The client address is the transport peer; proxy headers are not trusted, because nothing
terminates TLS in front of the API.

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
- Password reset, multi-factor authentication, session listing, per-user token revocation
  from the API, user administration over HTTP. **Exponential login backoff is no longer on
  this list** — it arrived in Chunk 29 and is described above.
- An unlock command. Nothing but a successful login clears a lock, which is why the backoff
  ceiling is an hour rather than a day.
- Image **digest** pinning. Kept as minor tags deliberately, because at the time nothing here
  bumped a digest and pinning without an updater stops security patches arriving; the image
  scan is the compensating control and `THREAT_MODEL.md` R-10 records what it does not cover.
  `.github/dependabot.yml` has since become that updater, so the decision now rests on inertia
  rather than on that argument — revisiting it is [#14](https://github.com/pchrysostomou/aegisnet/issues/14).
  Read-only container filesystems are **no longer** on this list either — every service has
  one since Chunk 30 (T-5.1).
- Any outbound integration: no Perplexity call has ever been made.

## Verification

`backend/tests/unit/test_auth_domain.py`, `test_auth_service.py`, `test_audit_service.py`,
`test_redis_adapters.py` (fakeredis), `test_spool.py`, `test_cli_auth.py`;
`backend/tests/security/test_rbac.py` (route enumeration and the matrix);
`backend/tests/integration/test_auth_routes.py`, `test_ingest_routes.py`,
`test_asset_routes.py`, `test_event_routes.py`, `test_audit_routes.py`;
`backend/tests/db/test_auth_store.py`, `test_audit_store.py`, `test_grants.py`,
`test_statement_timeout.py` (the two statement budgets above, and the migrator's absence of
one, against real PostgreSQL). The `stack` CI job creates a user and a service token through
the CLI, proves the version route answers `401` without a credential, ingests the synthetic
corpus over HTTP with a service token, and reads the finished batch and the audit trail as the
user.
