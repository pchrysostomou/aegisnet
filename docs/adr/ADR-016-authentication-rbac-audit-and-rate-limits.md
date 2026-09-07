# ADR-016 — Authentication, RBAC, audit and rate limits in Milestone 1

- Status: accepted
- Date: 2026-09-05
- Milestone: 1, Chunk 6

## Context

ADR-014 held every HTTP route back until authentication existed, so Chunk 6 had to ship
the credential model, the permission dependency, the audit writer and the rate limiter
together with the routes for ingest, batches, assets, events and audit. The API contract
(`docs/api-milestone-1.md`) fixes the shapes: bearer access tokens, an `HttpOnly`
refresh cookie, `X-Ingest-Token` for sensors, four roles, a route-enumeration test, and
`429` with `Retry-After`. What it leaves open is how tokens are verified, where the
decisions are made, how an upload reaches the worker, and what happens when Redis is
unavailable.

## Decision

1. **One permission dependency, deny by default.** `api.deps.require(permission)` is the
   only way a route authenticates. It resolves a bearer access token or a service token,
   refuses a present-but-invalid credential with `401` (never anonymous), checks the
   principal's permission set and audits a denial as `rbac.denied` before answering
   `403`. The dependency object carries the permission as an attribute so
   `tests/security/test_rbac.py` can enumerate every `APIRoute` and fail on one without
   it; the credential-free allowlist is the two health probes, login and refresh.
   `/api/v1/meta/version` now requires `meta.read`.
2. **Permissions derive from the stored role, not the token.** `ROLE_PERMISSIONS` in
   `domain/auth.py` is the matrix (viewer ⊂ analyst ⊂ admin; `ingest_service` = ingest
   plus version). `authenticate_access` reloads the user and refuses the token if the
   account is inactive or its role no longer matches the claim, so a demotion takes effect
   immediately without a revocation list.
3. **HS256 access tokens verified against the service clock.** A single process signs
   and verifies, no third party needs to check tokens, so a shared secret of at least 32
   bytes is enough; asymmetric keys would add a key-management burden with no verifier to
   serve. PyJWT's own `exp`/`iat` checks are switched off and the claims are compared to
   the injected clock with a 30-second tolerance, which makes the lifetime rules testable
   with a fake clock and lets the service refuse a token whose `exp − iat` exceeds policy
   even when it carries a valid signature. Logout puts the `jti` on a Redis denylist for
   the token's remaining life.
4. **Refresh and service tokens are opaque and stored hashed.** 32 random bytes,
   `sha256` in the table, looked up by hash. Refresh tokens rotate on use; a rotated or
   revoked token presented again revokes its whole chain (`revoke_chain` walks
   `rotated_to`). The refresh cookie is scoped to `/api/v1/auth` so it never travels with
   an API call. A refused refresh answers `401` *and* clears the cookie; the route builds
   that response itself rather than raising, because an exception handler cannot reach
   the cookie the route wanted to set.
5. **Rate limits are fixed windows, fail-closed where it matters.** One Redis counter per
   `(limit, subject, window)`; login is limited per client address and per hashed account,
   ingest per principal by request count and by bytes. If Redis raises, login and ingest
   answer `429` while reads and the default group proceed and log an error. A burst
   straddling two windows can briefly reach twice the limit; that is accepted for M1.
6. **Uploads go through a spool, messages carry the spool name.** The request body is
   streamed to `SPOOL_DIR` under a hard byte cap before anything parses it, into an entry
   whose name the route mints *before* reading a byte, so no path is ever derived from
   upload content; reads and writes go through `anyio` so the loop that serves
   `mode=sync` is not blocked on disk I/O; `mode=sync`
   runs the ingest service inline up to `INGEST_SYNC_MAX_LINES`, `mode=async` opens the
   batch row and enqueues `import_upload(batch_id, spool_name, source_label)`. The worker
   resolves the name inside the spool directory only (a name is 32 hex characters plus
   `.ndjson`, nothing else resolves) and removes the entry when done. In Compose the spool
   is the named volume `ingest_spool`, mounted by `api` and `worker` only.
7. **Audit detail is bounded at the writer.** `services.audit_service.bounded_detail`
   drops credential-like keys, strips control characters, caps values, keys and nesting,
   so no route can put a secret or a raw log line into the append-only table by accident.
   Every write is its own short transaction so a rolled-back request keeps its trail.
8. **Users and service tokens are created from the CLI only.** `create-user` reads the
   password from stdin; `create-service-token` prints the token once. Both audit
   themselves with `via: cli`. There is no registration route in Milestone 1.
9. **Routes take their services from one injected factory.** `main.create_app` accepts a
   `services_factory(settings, engine, cache) → AppServices`; production wiring lives in
   `build_services`, the test suite passes `tests.fakes.FakeWiring.factory()` and gets
   in-memory stores, a settable clock, a fake limiter that can be told Redis is down, and
   an inspectable audit sink. The integration suite therefore exercises the real routers,
   dependencies and error handlers without a database.

## Consequences

- The version route, the CI stack probe and the README quickstart all need a credential;
  CI mints one through the CLI and also proves the unauthenticated `401`.
- Settings grew `ACCESS_TTL_SECONDS`, `REFRESH_TTL_DAYS`, `LOGIN_MAX_FAILURES`,
  `LOGIN_LOCKOUT_MINUTES`, `COOKIE_SECURE`, `SPOOL_DIR`, `INGEST_SYNC_MAX_LINES` and the
  five `RATE_LIMIT_*` values. Names avoid the words the `.env.example` secret-name policy
  test treats as secrets.
- Argon2id verification is intentionally slow; the test suite injects a cheap
  `PasswordHasher` and the login path performs a dummy verification for unknown accounts
  so timing does not reveal existence.
- Deferred to Milestone 6: ~~exponential backoff~~ (delivered in Chunk 29, ADR-036), password reset, MFA, session management
  over HTTP, trusting proxy headers behind TLS termination, ~~read-only root filesystems~~
(delivered in Chunk 30, ADR-037).
