# Changelog

All notable changes to AegisNet are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Nothing is released yet. There is no tagged version.

## [Unreleased]

### Added
- **Read-only root filesystems on every service** (T-5.1), with sized `tmpfs` mounts for exactly
  what each one writes. Those paths were measured, not guessed: `docker diff` against a stack that
  had been up seven hours said db writes only its socket directory, api/worker/scheduler write only
  dramatiq's Prometheus directory, and redis and web write nothing at all. Verified by rebuilding
  and starting the stack — six healthy containers, `touch /app/probe` refused, a 1.9 MB multipart
  upload accepted through the api's tmpfs, and no rootfs writes afterwards.
- **A container image scan** (T-5.6). `pip-audit` and `pnpm audit` read lockfiles, and a lockfile
  cannot see a base image. The `images` job builds what the stack builds and scans it with Trivy
  alongside the two images the stack pulls. It fails the job rather than uploading SARIF, because
  code scanning is not enabled on a private repository and a report nobody can read is not a
  control; it ignores unfixed findings, because a gate nobody can pass is a gate people switch off.
- **The lab's pre-flight now runs in CI** (T-5.5), asked of a running container rather than of a
  manifest. Only the lab target comes up, so Suricata is never pulled. A check that lives in a
  Makefile recipe is a check nobody runs.

### Fixed
- `/app/samples` did not exist in the api image, so Docker created the bind-mount destination at
  container start — a write to the container layer, which `read_only` forbids. Both that and the
  web cache directory are created in their Dockerfiles now. Measuring before changing is what
  caught it; a compose-only change would have shipped and broken the stack.

### Changed
- **Decision F-5 re-examined and kept.** Base images stay pinned by minor tag rather than by
  digest, because nothing in this repository bumps a digest — there is no Dependabot configuration
  — and pinning without an updater freezes the images and stops security patches arriving. The
  image scan is the compensating control. Recorded as residual risk **R-10**, including what it
  does not cover: a tag that moves to something malicious but free of known CVEs.
- `THREAT_MODEL.md` §6 is **thirty-six verified rows and no `partial`**. Of the eight gaps the
  coverage matrix found in Chunk 27, six were closed by writing code or tests and two by deciding
  in the open that the mitigation as first worded was wrong for a single-node lab (R-10, R-11).

### Added
- **A lockout that lengthens** (T-2.1). Each failure past the threshold doubles the lock — 15, 30,
  60, 60 minutes — so a batch of guesses costs more than the last instead of a flat fifteen
  minutes. A lock nobody has touched for a day is forgotten, or the escalation would be permanent
  for an account that never manages a successful login; the anchor is `locked_until` and
  deliberately not `updated_at`, which a role change also touches. The ceiling is an hour rather
  than a day because there is no unlock command, so it is also the longest an operator can be shut
  out of their own deployment. Nothing about the escalation is visible to the caller.
- **Statement timeouts, in two budgets** (T-2.6). Rate limits bound what a caller may ask for and
  nothing bounded what the database then spent. `DB_STATEMENT_TIMEOUT_MS` (5 s) holds the request
  path; `DB_JOB_STATEMENT_TIMEOUT_MS` (5 min) holds the worker, the CLI and the retention prune,
  because a sweep over 200 000 events legitimately does more work than a request should. The
  migrator gets none at all, asked for explicitly, because an index build over a populated table
  must never be cancelled half way. A cancelled statement answers `503`, not `500`.
- `RATE_LIMIT_LOGIN_IP_PER_15MIN`, so the per-address and per-account login budgets are separate
  numbers at the same default. One setting fed both, which meant an office behind one NAT address
  could only buy itself room by also widening how many guesses an attacker gets at one account.

### Changed
- `create_engine(settings)` is gone. `create_api_engine` and `create_job_engine` name the budget a
  call site is asking for, and the keyword is required — a default is how the gap above would
  re-open. Engines also set `hide_parameters=True`, the companion to `echo=False`: untrusted bound
  values stay out of the string form of any driver error.

### Added
- **A deadline on an upload, because no size cap is reached by a body that simply stops** (T-1.4).
  `INGEST_UPLOAD_TIMEOUT_SECONDS` (120 s) bounds the body read itself, including the multipart
  parse, which is where a multipart body is actually read. The partial spool entry is discarded and
  the refusal is `408 request_timeout`, audited as `ingest.refused` — deliberately not `413`, which
  would make a stall indistinguishable from an oversized body in the audit trail.
- **Per-analyst and per-case daily limits on asking for a brief** (T-3.4).
  `THREAT_MODEL.md` had claimed both since the planning phase and neither existed: one
  deployment-wide budget is not a limit on anybody in particular. The case's share is spent before
  the analyst's, so a loop on one case cannot cost that analyst every other case they are working,
  and both fail closed — a test breaks one at a time so each is proven on its own.
- **The dashboard writes out the characters that change what text says** (T-4.4).
  `U+202E` and nineteen others render as `<U+202E>`, from the same list and in the same notation the
  exported report has used since Chunk 24 — so the screen and the document stop telling different
  stories about the same note. A Python test compiles both lists and fails if they ever diverge,
  and a renderer test fails if any text node forgets the call.

### Fixed
- **The renderer's block grammar swallowed the characters it was meant to show.** Its markers
  matched `\s`, and JavaScript's `\s` and `String.trim()` both include `U+FEFF`, so a line
  beginning with one was read as a quote and the character was consumed by the marker — gone from
  the screen and absent from it, while the report wrote it out. Every marker now matches `[ \t]`,
  which is what the grammar always meant. Python's `str.strip()` does not strip format characters,
  which is why the backend never had this.
- The two `[^>]*` patterns in the renderer's test file, which SonarCloud's `S8786` flags as
  super-linear. Not new code, but this chunk touched the file, and the rule fires on a file the
  moment it is next changed.

### Fixed
- Two assertions that could not fail, both found by SonarCloud's reliability gate.
  `assert render_report(**case) == render_report(**case)` reads as a tautology and the analyser
  is right to say so — the two calls are bound to variables now, which is also how the test says
  what it means. And `[^>]*` in a tag-stripping helper is quadratic on a run of `<`, because a
  class that can swallow the opening delimiter lets one failed attempt overlap the next.
- **A code span in a table cell cannot be made safe, so it is not one.** The pipe escape that
  fixed the first version of this was itself broken: a backslash cannot be escaped inside a code
  span, so a value already containing `\|` emits two backslashes and a renderer that consumes
  the escaped backslash reads the pipe as a live delimiter again. Table cells are escaped text
  now, like every other untrusted string — `escape` escapes the backslash too, so nothing
  survives to be re-read. Monospace in a table is worth less than a rule with no exceptions.
- **An indented line became a code block.** Every CommonMark block construct opens on ASCII
  punctuation except the indented one, which opens on four spaces or a tab — the one thing an
  escaper cannot reach. A pasted log excerpt in a note turned into a code block the report never
  wrote, and inside one a backslash stops being an escape, so the analyst's own evidence arrived
  full of visible `\/` and `\=`. Leading whitespace is stripped now.
- **A viewer's export named ingest batches they may not read.** The provenance appendix carries
  each batch's source label, dataset and line counts, and reading those is `ingest.read` — which
  a viewer does not hold. The export is not a way around a permission: the appendix is rendered
  only for a caller who holds it, and everyone else is told it was withheld and why. The honest
  statement of the determinism promise is therefore "the same case and the same permission
  produce the same bytes".
- **`make export` on a well-formed but unknown uuid printed a traceback**, because that
  reference reaches the store rather than the case-number lookup and comes back as an exception
  rather than as `None`. `make brief` had the same hole since Chunk 23. Both print the envelope
  every other command prints.
- **A `$`-anchored check guarded a response header.** In Python `$` also matches immediately
  before a trailing newline, so `AEG-2026-0001\n` would have passed the case-number check on its
  way into `Content-Disposition`. `fullmatch` now.
- `FakeEventStore.get(include_payload=False)` built a fresh row rather than returning the one it
  held, so `batch_id` was a uuid belonging to no batch and the report's provenance appendix
  always rendered its empty branch — the populated table had no integration coverage at all. The
  same class of defect as the `FakeAlertStore` one above: a fake that answers differently from
  the port it stands in for hides exactly the code it exists to cover.
- **The dashboard's own fetch budget was shorter than the API's.** `generateBrief` used the
  default ten seconds, while the API allows a thirty-second call and two retries — so a brief the
  model answered at twelve seconds was reported to the analyst as a failure while the API quietly
  finished and stored it, and the obvious next move was to press the button again and write a
  second version. Asking now waits as long as the API may take; the export waits a minute.
- **A lookup table read with `in` walks `Object.prototype`.** A `failure_reason` or a
  recommendation `action` called `toString` found a function and rendered as nothing; one called
  `__proto__` found an object and threw, which in a server component with no boundary above it
  blanks the whole case page. Both are unconstrained strings on purpose, precisely so a value the
  domain adds later shows itself, and this was the one path where it would not. `Object.hasOwn`
  now, with the prototype keys in the tests.
- A brief that could not be generated was badged **generated**, one line above the sentence
  saying it could not be. The badge is the only place the panel states provenance (ADR-031), so
  it reads the status before the source.
- **A code span inside a table cell is not safe, and the report's own security test found it on
  its first run.** GFM splits a row on `|` before it parses anything inline, so a pipe inside a
  code span ends the cell, leaves the backticks unmatched, and turns the rest of somebody else's
  text into ordinary Markdown — an entity value containing `| a | b |` made a `javascript:` URL
  two cells later into a link. Table cells use a pipe-escaping code span now.
- The report service's page loop could exceed its own cap: when the last page happened to finish
  the list, the loop returned everything gathered and called it complete, so a case with 510
  notes rendered all 510 under a cap of 500. It reads one row past the cap now and decides
  completeness from what exists rather than from where the cursor ran out.
- `FakeAlertStore.get` raised `KeyError` for an alert with no link rows, where the SQL store
  returns empty tuples — a test that put a row in `rows` directly got a 500 instead of an answer.
- The browser suite's XSS probe asserted on a marker that is unique only on a fresh stack. A note
  is never edited or deleted, so running `pnpm e2e` twice against one stack left two identical
  probes and a strict-mode violation; the assertion takes the first match now.

- **Chunk 16 — two defects the adversarial review found before the change was committed.** A
  keyset cursor built as `(Column.a, Column.b) < (x, y)` is a *Python* tuple comparison, not a
  SQL row comparison: CPython compares element 0, `bool(Column == x)` is `False`, and the
  predicate collapses to `Column.a < x`, silently dropping every row that shares the boundary
  instant. Three queries in the incident store had it — `list` shipped that way in Chunk 15 —
  and the `# type: ignore[operator]` on each was suppressing the mypy error that names it. All
  three now use `tuple_()`, like every other store, and a database test pages one entry at a
  time across three entries sharing an instant.
- `SqlIncidentStore.extend` now re-reads the case's status under a row lock and refuses a case
  that closed under it. Correlation reads a case as open in one transaction and extends it in
  another; until this chunk nothing could close a case in between. Linking into a closed case
  would have been permanent, because the alert flips to `correlated` and can never be relinked.
- **Chunk 14 — the two defects the lab found (ADR-022).** A **flow** event is now filed under
  `flow.start` rather than under the record's own timestamp, which is when Suricata's flow
  manager emitted it. Every other event type is unchanged. The emission time stays in the
  stored payload; `flow.start` is read best-effort and falls back to the timestamp when it is
  absent or unreadable; the freshness window (T-1.7) is checked against both instants.
  Deduplication is untouched, because the event hash is built from the record's own timestamp
  — a test pins that, since the whole change rests on it.
- A DNS record's direction now comes from its own `type` — `answer` in EVE v2, `response` in
  v3 — and only a reply's `rcode` is promoted. Suricata 8 puts an `rcode` on requests too, so
  reading "has an rcode" as "is an answer" made every real record look like an answer: no
  query name was ever tallied and every lookup was attributed to the resolver. An unfamiliar
  `type` is treated as a question.
- Neither generator accepts a path on its command line any more; each resolves its own
  destination under the checkout it finds, the rule every other tool here already followed.
- Both generators had the same assumptions inside them and were corrected: a flow record now
  carries `flow.start = when` and `timestamp = when + age`. The committed corpus (generator
  version 2, new sha256) and all 34 labelled fixtures were regenerated. The normalised event
  times did not move, so the `make eval` table in `docs/evaluation.md` §8 did not either —
  which is the point worth noticing: the T1 and T2 numbers were identical before and after a
  change that took two rules from blind to working on real data.
- **On the committed real capture, four of the five rules now fire** — D-001, D-002, D-003 and
  D-004 — where two did before; D-005 still abstains for want of 24 hourly baseline samples.
  The two fidelity tests that recorded the defects now hold the fixes down, and 28 new tests
  cover the semantics on hand-built lines (missing, malformed and naive `flow.start`, the
  window checked both ways, hash stability, all four DNS shapes and the fallbacks), the
  timestamp parser, and the invariants the generators must hold from here: a flow starts
  before it is emitted, in the corpus and in every labelled case, and the corpus carries both
  EVE DNS shapes so T1 and T2 exercise the one that broke D-003.

### Added
- **Chunk 26 (Milestone 6) — the rate limits, measured under concurrency.** `SECURITY.md`
  publishes four limits and two failure modes, and every one of them was asserted one request at a
  time. That is the wrong shape for the question: a fixed-window counter is only correct if its
  increment is atomic, and a serial test cannot tell an atomic `INCR` from a read-modify-write that
  has not raced yet. `make load-test` fires whole budgets at once — 180 concurrent reads against a
  budget of 120, and exactly 120 are allowed.
- **The documented weakness is now a number.** `rate_limiter.py` has always said a burst
  straddling two windows can reach twice the limit; a run timed onto a boundary allows exactly 240
  against a limit of 120 — the ceiling, not a number that grows with the burst. That test waits up
  to a minute for a real boundary rather than skipping most runs or manufacturing one.
- The suite is opt-in (marker `load`), joins the running stack's own network rather than starting
  one, and deletes the budgets it burns: the login limit is per-IP and fails closed, so leaving it
  spent would lock the operator out of their own deployment for fifteen minutes.
- `docs/evaluation.md` §10 records the numbers, the command to reproduce them, and what they do
  not say — that the limits are the right numbers is a tuning question no test can answer.

- `bootstrap_env.py` takes no path any more. `--example` and `--out` are gone; both files are
  resolved from the checkout the script lives in. SonarCloud rated the change that added a second
  read and an append through those arguments as a security finding on new code — a path from
  `argv` reaching file I/O, the same taint already removed from both generators,
  `eval-detectors` and the capture sanitiser. The flags had no user outside the tests, which now
  build a fake checkout in `tmp_path` and point `_repo_root` at it, so they cannot touch the real
  `.env` either.
- **Chunk 25 (Milestone 6) — the retention policy, and a third role to carry it out (ADR-033).**
  `docs/data-model.md` has described a retention table since Milestone 0 and three places in the
  code said the job "arrives in a later milestone". The reason it kept being deferred is that it
  collides with a property three decision records rest on: the runtime role cannot delete
  anything, because an audit trail the application can edit is not evidence.
- So **deletion is a different principal**. `aegisnet_retention` holds `SELECT, DELETE` on
  `events`, `ingest_rejects`, `detector_runs` and `audit_log`, plus `SELECT` on `alert_events`,
  and can write nothing anywhere. `audit_log` and the brief tables stay append-only for the
  application. The record of a prune is written by the app role, which cannot delete, so getting
  a deletion into this database without a trace takes two credentials.
- **Nothing a case rests on is ever old enough.** `alert_events.event_id` is `ON DELETE CASCADE`,
  so deleting a sampled event does not fail — it strips an alert of its evidence and leaves the
  alert standing, and the exported report's provenance appendix would go blank with nothing
  saying why. Any event an alert still points at is kept regardless of age.
- Every statement is a literal chosen from a fixed map — no table or column name reaches SQL from
  a variable — and deletes are batched, each pass its own transaction, with a per-run ceiling so a
  first prune of a neglected table finishes and leaves the rest for tomorrow rather than holding
  locks. A run that stopped short says so instead of reporting success.
- **Off by default.** `RETENTION_ENABLED` is false, `make retention` prints what would go and
  removes nothing, and `APPLY=1` refuses when the setting is off: a flag on one invocation should
  not overrule the deployment's decision. `nightly_retention` is sent every night regardless and
  reads the setting itself, so turning the policy on is one variable and a worker restart.
- `make db-roles` and `bootstrap_env.py --add-missing`, because the role is created by an init
  script that only runs on an empty data directory and the variables are appended to an existing
  `.env` by nothing. Without both, an existing deployment would have the setting and not the role.

- **Chunk 24 (Milestone 5) — the case as a document, and the brief on the screen (ADR-032).**
  `GET /api/v1/incidents/{id}/report.md` and `make export REF=AEG-2026-0001` render one case as
  Markdown, and **the same case renders to the same bytes**: every collection sorted to a key
  that is unique, dictionaries serialised with sorted keys, floats to a fixed precision, a naive
  timestamp read as UTC rather than against the machine's zone, and no "generated at" line
  anywhere. Two exports can be diffed, and a difference means the case changed.
- The export **writes nothing to the case**. A report that recorded its own export in the
  timeline would change the case the next export renders — the defect Chunk 23 found in the
  evidence packet — so `report_exported` stays a timeline type this project does not write. It
  is still audited as `report.exported` (FR-10.3), because the audit log is not something the
  report renders.
- **Nothing in the document can become markup.** A rule id, an entity value, an analyst's note
  and a model's summary are all strings this project did not write, and a Markdown viewer is a
  renderer like any other. Every untrusted value is backslash-escaped — every ASCII punctuation
  character, which CommonMark defines as escapable, rather than a chosen subset — or fenced with
  a fence longer than anything inside it. The test renders the document with a real CommonMark
  parser and asserts on the tokens, given a case poisoned in every string field at once.
  Characters that reorder text without being visible — bidirectional overrides, zero-width
  spaces, the byte-order mark — are written out as their own code points (`<U+202E>`) rather than
  stripped: a report about somebody who used one must still show that they did.
- The report carries the case verbatim, **including the parts that never leave** — real
  addresses, real hostnames, the analyst's own words — and says so in its own first paragraph.
  `domain/redaction` is for the other direction, where the reader is a third party.
- It has every section FR-9.1 names — the case and how its severity was derived, the assets the
  inventory matched, every alert with its evidence, the timeline, the briefs with their claims and
  sources, what the document does not cover, and an appendix naming the ingest batches the
  evidence rests on — plus the notes, which FR-9.1 does not ask for and an analyst reading a case
  would miss.
- **The dashboard's brief panel** shows the newest brief: the summary, claims, recommendations
  in the analyst's own words, sources and limitations, with every uncited external claim tagged
  `UNVERIFIED` and the committed offline sample labelled as not-a-model. Model prose goes through
  `SafeMarkdown`, exactly like an analyst's note. A viewer reads it; only an analyst is offered
  the control that asks for one.
- **`CitationList` is the first anchor to somewhere else this dashboard has ever drawn.** A
  source is a link only when it is `https` — parsed with `new URL`, not prefix-matched — and
  carries `rel="noopener noreferrer nofollow"` and `target="_blank"`. Credentials are refused
  too, because `https://attack.mitre.org@evil.test` goes to `evil.test`. Anything else is printed
  as text with a line saying why, since a source nobody can follow is still evidence of what the
  model said.
- The download is a route handler in the dashboard, not a link to the API: the browser never
  learns the API's address, so the bytes come through this app.

- **Chunk 23 (Milestone 5) — briefs are stored, served, and append-only (ADR-031).** Revision
  `0005_brief_tables` adds `investigation_briefs` and `brief_citations`, and the runtime role
  gets `SELECT, INSERT` on both and nothing else — the grant `audit_log` has, for the same
  reason. A brief records what a model said next to the hash of exactly what was asked; one that
  can be edited afterwards is evidence of nothing. Asking again writes v2 rather than replacing
  v1, and the version is allocated inside the writing transaction so a race loses instead of
  overwriting.
- **A failure is a stored brief, not an error.** Disabled, unconfigured, out of budget, a 503, an
  answer that would not parse, an answer the safety filter refused — each becomes a row with
  `status: failed` and a short reason, answered `201`. Two check constraints keep those rows
  honest: a complete brief must have a summary and a failed one must have a reason. "The API was
  down at 03:10" is worth keeping; a 502 that threw it away is not.
- `POST /api/v1/incidents/{id}/briefs` (analyst), `GET …/briefs` and `GET …/briefs/{version}`
  (viewer), `make brief REF=AEG-2026-0001`, and `docs/api-milestone-5.md`. Generating appends one
  `brief_generated` timeline line and one `brief.generated` audit row carrying the packet hash —
  never the packet, never the answer. A test compares the whole case before and after: severity,
  status, title, rule count and linked alerts are byte-identical, which is T-4.1 asserted rather
  than merely typed.
- **A checkout with no key still sees the feature work.** `samples/briefs/offline-brief.json` is
  served when the feature is off or unconfigured, stored under `source: offline_fixture` so
  nothing can present it as something a model said, and admitted through the same schema,
  citation and safety checks a real answer faces — a fixture that could not be admitted would be
  a fixture that lies. A real failure is never replaced by it.

- **Chunk 22 (Milestone 5) — the client and the contract for what comes back (ADR-030).**
  `adapters/perplexity/` is the only code in this project that talks to somebody else, and
  `domain/briefs/` decides what may be stored. **Both are off by default and no call has been
  made from this repository**: every test runs against committed fixtures through a mock
  transport, which is also the only way to assert what *would* have been sent.
- Recommendations are an **enum** of nine things a person does — investigate, review with the
  owner, check the baseline, collect evidence, correlate, monitor, document, escalate, or
  nothing. A model that invents an action is refused rather than approximated. An incident tool
  whose AI output says "block 203.0.113.5" in a structured field is one integration away from a
  tool that does.
- An external claim must cite an https source the brief carries. A citation id pointing at
  nothing is a refusal — a dangling reference is a fabricated citation wearing a number. An
  external claim with *no* citation is kept and marked `UNVERIFIED`, because a reader deciding
  what to trust is better served than by a silent deletion.
- A brief has no field for a severity, a status or a verdict, and a test asserts the exact field
  set: successful prompt injection still has no channel to change what the detectors concluded.
- The call is bounded everywhere — one timeout, two jittered retries on the statuses worth
  retrying and none on the ones that will not change, a response byte cap checked before
  parsing, `max_tokens`, a content-addressed cache so an unchanged case costs nothing, and a
  daily budget with a hard stop.
- The API key is a `SecretStr`, travels only in a header, and is in `secret_values()` so the log
  scrubber would catch it even if the client were wrong. A transport failure records the
  exception's *type*, because an httpx error carries the request and the request carries the
  header. `verify` is never mentioned and no setting could disable it — a test greps for that.
- [`docs/perplexity-integration.md`](docs/perplexity-integration.md) says what is sent, what is
  accepted, how to turn it on, and every way it fails.

### Changed
- The daily brief budget moved from process memory into Redis. The API, the worker and the CLI
  each build their own client, so a counter inside one of them capped that one and let the other
  two spend the same allowance again; an operator who set 50 got 150. It is now one key per UTC
  day, incremented before the call rather than after it, so a broken endpoint cannot be retried
  without limit.

### Fixed
- **The runtime image did not carry `httpx`.** It was a dev dependency, the Perplexity client
  has imported it since Chunk 22, and nothing in the *runtime* import graph reached that client
  until this chunk wired the brief service into the app. Every local check passed — ruff, mypy,
  1150 tests, the database suite — and the api container then failed to start on the runner with
  `ModuleNotFoundError`. `httpx` is a runtime dependency now, and so is `starlette`, which two
  modules import directly and which had been relied on as fastapi's transitive. A new test walks
  `src/` and requires every third-party import to be declared, so the next one is caught before
  a container is built.
- **Generating a brief changed the next brief's question.** The evidence packet included every
  timeline summary, and generating appends a `brief_generated` line — so asking twice about an
  unchanged case produced two different `packet_hash` values. The content-addressed cache could
  therefore never hit on the one case it exists for, and the model was being handed the note that
  somebody had asked it to explain the incident. Lines that record what this tool did
  (`brief_generated`, `report_exported`) are no longer part of the packet. Found by running
  `brief` twice against the stack and watching the hash move; a test pins it now.
- **The safety filter was a pydantic validator, which made it unable to do its job.** Pydantic
  converts any `ValueError` raised inside a validator into a `ValidationError`, so "the model
  recommended attacking something" arrived indistinguishable from "a field was too long" and
  the client could only ever record `schema_rejected`. Shape is validation; policy is now its
  own step (`enforce_safety`), and `safety_rejected` is a record that can actually happen.

- **Chunk 21 (Milestone 5) — the outbound boundary, and nothing else (ADR-029).**
  `domain/redaction/` turns a case into a `CaseEvidencePacket`: derived numbers, stable tokens
  and timestamps. **No client, no configuration and no API key ship in this chunk** — there is
  nothing here that can perform I/O. TB-3 is the threat model's highest-consequence boundary,
  so it is proven before anything exists that could cross it.
- The packet is an **allow-list**. Every evidence key is classified as numeric, address-shaped,
  a closed vocabulary, a timestamp, or explicitly dropped; anything unclassified is dropped and
  recorded in `dropped_fields` with the reason. A new detector's evidence sends nothing new
  until somebody reviews it, visibly rather than silently.
- Addresses and hostnames leave only as stable per-case tokens (`asset-A`, `int-1`, `ext-1`,
  `domain-1`), carrying which side of the perimeter they are on and no topology. The mapping
  stays local. Tokens are deterministic, so the same case serialises to the same bytes.
- Because what goes out is arithmetic rather than prose, indirect prompt injection (T-4.1) has
  a structural answer: an attacker's text never reaches the model at all.
- A denylist sits behind the allow-list for emails, AWS key ids, private keys, JWTs, bearer
  tokens, credential assignments, provider tokens and base64 blobs. It records which rule
  matched and never the matched text.
- Everything is bounded — 24 kB, twelve alerts, eight items a list — and truncation is explicit.

### Fixed
- **A leak the canary suite found on its first run.** `correlation_service` writes timeline
  summaries like `D-001 fired on src_ip 10.10.0.42`. They are written by this project rather
  than by a sensor, so the credential denylist had no objection to them — and they quote the
  entity, so a real address would have left inside an ordinary English sentence while every
  structured field around it was carefully tokenised. The pseudonymiser now reads sentences
  too: `D-001 fired on src_ip asset-A` is as useful to a model and says nothing about a network.

- **Chunk 20 (Milestone 4, the last) — the asset inventory, the audit viewer, and the browser
  suite (ADR-028).** `/assets` lists what the detectors attribute traffic to; `/audit` is the
  admin-only view of the append-only trail, and is not drawn for anybody else because the API
  would refuse them anyway.
- **Fourteen Playwright tests against a running stack, with nothing mocked.** They cover what
  the other tiers cannot reach: a stored payload rendering as inert text in a real browser, a
  viewer being drawn no control and refused `403` when the request is forged anyway, and a case
  being reachable and workable from the keyboard alone.
- The XSS test asserts what is *there*, not what is absent: the payload must be visible as
  text, no dialog may open, `window.__pwned` must never be set, and the notes list must contain
  no `script`, `img`, `svg`, `a` or `iframe`. Asserting only that a string is absent would pass
  for a renderer that silently dropped an analyst's note, which is a worse bug.
- WCAG AA contrast is computed from `globals.css` in a test rather than described in a
  document, for both themes. Numbers in prose go stale the first time somebody adjusts a hex.
- `docs/screenshots/` is generated by `pnpm e2e:shots` from the committed multi-stage scenario,
  so the images show data a reviewer can reproduce.
- CI gained an `e2e` job that starts the stack, loads the scenario, mints two accounts and runs
  the suite, keeping the results and the stack logs as artefacts on failure.

### Fixed
- **A defect only a browser could find.** `src/app/incidents/[id]/actions.ts` exported a
  constant beside its two server actions. Next allows only async function exports from a
  `"use server"` module and enforces that when the action *runs*, so `tsc`, ESLint, 84 unit
  tests and `next build` all passed while the note form was broken in production. The first
  browser test to submit a note found it in seconds; the constant moved to its own module.

- **Chunk 19 (Milestone 4) — the case view and `SafeMarkdown` (ADR-027).** A case now opens on
  its own page: the linked alerts, the timeline typed and in order, the notes analysts wrote,
  and — for an analyst — a status control and a note form. The status control offers exactly
  the moves the API said were legal in `allowed_transitions`; the workflow is never recomputed
  in the browser, so a client cannot disagree with the server about what a case may do.
- **Markdown is parsed into React elements, never into an HTML string.** The usual answer is a
  markdown library plus a sanitiser, which is a bet that the sanitiser understands everything
  the parser can produce. `components/safe-markdown.tsx` takes the other route: a small fixed
  grammar — paragraphs, breaks, bullets, quotes, fenced code, inline code, bold, italic —
  parsed straight into elements. Nothing serialises to HTML, so there is nothing for a
  sanitiser to miss and no `dangerouslySetInnerHTML` to reach for (T-1.3, T-4.4).
- Links and images are deliberately not supported. A note is read by somebody deciding whether
  a host is compromised: a link is how that reader gets taken elsewhere, and a rendered image is
  how a note phones home with the reader's address when the case is opened. An indicator belongs
  in a code span, where it can be copied and cannot be clicked.
- Raw HTML in a note renders as the characters typed rather than being stripped, because an
  analyst writing about a payload must not find their evidence silently edited.
- 15 hostile inputs are rendered in the suite and checked two ways: every tag emitted must be
  one of eleven inert elements, and nothing outside those tags may contain `<` or `>`. The
  assertions are on the tags, not on forbidden substrings — a note whose *text* reads
  `onerror=alert(1)` is what an analyst investigating an attack writes, and it must render.

- **Chunk 18 (Milestone 4) — the dashboard's foundation and the incident queue (ADR-026).**
  Sign in and sign out, the incident queue with status, severity and open-only filters and the
  API's keyset paging, and a typed boundary: `src/lib/api/schemas.ts` restates the API's DTOs
  as zod schemas and every response is parsed before a component sees it, so a renamed field
  fails in one place instead of rendering `undefined` into a case somebody is reading.
- **The browser holds no credential.** The API's access token and refresh cookie live in this
  app's own `HttpOnly`, `SameSite=Lax` cookies; the browser talks to Next and Next talks to the
  API, so neither a token nor the API's address ever reaches a script. `AEGISNET_API_URL` is a
  server variable, deliberately not `NEXT_PUBLIC_`. An XSS bug in a dashboard whose whole job
  is rendering strings from other people's packets can still act as the analyst while the page
  is open, but it cannot walk away with a credential that keeps working (T-1.3, T-2.4).
- A server component cannot write a cookie, so `middleware.ts` rotates an expired session
  before the render rather than bouncing an analyst to the login form every fifteen minutes.
  A refresh the API refuses — including a replayed token it revoked the chain for — clears both
  cookies and lands on the form with an explanation.
- `dangerouslySetInnerHTML`, `innerHTML` and `outerHTML` are banned by an ESLint rule that
  names T-1.3 in its message. The ban was proven by writing a component that trips it before
  being relied on.
- Frontend tooling: ESLint 10 flat config with `typescript-eslint` type-aware rules, vitest,
  and 32 unit tests over the schemas, the client, the session and the redirect allow-list.
  CI's frontend job now runs `typecheck`, `lint`, `test` and `build`.
- Where a sign-in may land is an allow-list that *rebuilds* the destination from what a
  pattern captured, rather than checking a prefix and passing the string through. `//evil.test`
  and `/\\evil.test` defeat the prefix check in some parsers; there is no path from the
  parameter's bytes to the redirect's here. `AEGISNET_API_URL` is parsed and its origin rebuilt
  the same way, so a configured value carrying credentials, a path or a query fails loudly.

- **Chunk 17 (Milestone 3, the last) — the multi-stage scenario and the correlation metrics
  (ADR-025).** `samples/scenarios/multi-stage-01.ndjson` is 303 committed EVE records: a week
  of ordinary hourly traffic from one host, then one hour in which that host scans a
  neighbour on forty ports, fails twelve logins in ninety seconds, beacons to an external
  address every minute and uploads 400 MiB — while a second, unrelated host scans beside it,
  and the first host scans again six hours later as a separate story. Registered with a
  pinned sha256 and a manifest carrying the ground truth.
- Ground truth is declared by scenario window, never derived from the entity key correlation
  groups on. The first version of the harness read it off the key, which made grouping
  precision and case contamination algebraic identities — 1.00 and 0.00 for every possible
  input. Two scenarios now share a host and differ only in time, so widening the join gap to
  24 hours moves the numbers to precision 0.60 and contamination 0.50, and a test asserts it.
- The week of history is part of the scenario rather than scaffolding around it: it is what
  lets the baseline job produce the baseline D-005 needs. Without it the rule abstains, and
  the four-rule claim would quietly have been three.
- `make demo-scenario` runs the whole story on the stack — seed the assets, ingest, recompute
  baselines as of the scenario's own hour, sweep, correlate, list the cases — and produces
  exactly what `docs/delivery-plan.md` M3 asks for: one incident with four alerts from four
  distinct rules at an escalated severity, and a separate case for the bystander.
- `domain/correlation_eval.py` scores a grouping against known truth **pairwise**: for every
  pair of alerts, did correlation put them together and should it have. Case counting alone
  would hide both failure modes — lumping everything into one case, and splitting one story
  into many — because each is wrong by the same number of incidents.
- `make eval` now refreshes both halves of `docs/evaluation.md` §8. The correlation block
  reports grouping precision and recall, case fragmentation and case contamination against
  the targets §4 sets, and a test pins the committed block to what the harness produces.
- `recompute-baselines --until` summarises the complete hours before a given instant instead
  of before now, which is how a committed corpus dated in the past is replayed as of the hour
  it describes.
- `make gen-scenario` regenerates the scenario from its fixed seed; a test proves the bytes
  come back identical, which is what makes the registry's checksum a fact rather than a
  snapshot.

- **Chunk 16 (Milestone 3) — the incidents API, audited transitions and the role matrix
  (ADR-024).** Six routes under `/api/v1/incidents`: list a case with filters, open one with its
  linked alerts and the newest 200 lines of its story, page the whole timeline, read and write
  notes, and move a case through the workflow. Two permissions: `incidents.read` for viewers,
  because an incident is the readable form of alerts a viewer may already read, and
  `incidents.write` for analysts, because changing a case is a judgement.
- A status change is a compare-and-set: the status the caller believed the case held is part of
  the `UPDATE`'s `WHERE`, so two analysts deciding in the same second cannot both win, and the
  one who loses is told the case moved rather than silently overwriting a decision they never
  saw. `closed_at` and `closure_reason` move in that same statement, in both directions, because
  the check constraint that ties them to the status is an equality.
- Every change is recorded twice, on purpose: a line in the case's own timeline, written inside
  the transaction that changed the status, and a row in the append-only audit log, written after
  it commits. A move the workflow forbids — including a move to the status the case already
  holds — answers `409` and is audited as `incident.status_change_refused` with `result: denied`.
  The route writes that record, not an exception handler, because a handler cannot see the
  principal a dependency resolved and a denial nobody can attribute is not a denial record.
- Notes: free text, cleaned of control characters but keeping the paragraphs somebody wrote, and
  refused rather than truncated when too long. A note's body is stored once, in `incident_notes`.
  The timeline says `"Note added"` and the audit log says `{note_id, length}` — no analyst prose
  reaches either, because the audit writer's 512-character cap would make its copy differ from
  the note and its credential filter cannot see into free text.
- `allowed_transitions` on the case detail, read from the same table the server enforces, so a
  client never keeps its own copy of the workflow.
- [`docs/api-milestone-3.md`](docs/api-milestone-3.md) documents the workflow table, every route
  and every audit action a transition writes.

- **Chunk 13 (Milestone 2, the last) — the isolated Suricata lab, and what it found.**
  `infra/lab/` is an opt-in stack of three containers behind the `lab` profile on a Docker
  network with `internal: true`: a `target` that listens (HTTP, a beacon port, a minimal DNS
  responder), a `generator` whose only destination is that target, and `jasonish/suricata:8.0`
  pinned by digest, sharing the target's network namespace and watching it in IDS mode. Every
  service drops all capabilities; the sensor adds back exactly `NET_RAW`, the repository's one
  such exception, pinned by a test (ADR-021).
- The lab network sets `com.docker.network.bridge.inhibit_ipv4` as well as `internal: true`.
  `internal: true` alone leaves the subnet's first address on the host side of the bridge,
  and a container reaches it with no default route at all — before this, a lab container
  could open a connection to a service listening on `203.0.113.1`. `make lab-preflight` now
  proves the result from inside a container (`infra/lab/preflight.py`): no default route, and
  nothing answering at the first address of its own subnet or outside. The check was verified
  to fail on a network without the option.
- `tools/sanitize_eve.py`: drops sensor records, strips every content-bearing key at any depth,
  bounds strings, and then refuses to write anything at all if what remains holds a key that is
  on neither the strip list nor the published-key allowlist, an address or hostname outside
  documentation space **anywhere** (inside a list, inside a URL, inside a certificate subject),
  or a URL parameter whose name announces a credential. `--check` re-runs that refusal against a
  file as it sits on disk, so it asserts something about the committed bytes rather than about a
  repaired copy of them. Its output is a normal registered
  dataset: `samples/lab/lab-capture-01.ndjson` (463 real Suricata records) with a manifest, a
  sha256 in `samples/registry.yml` and an asset seed.
- `make lab-preflight`, `lab-up`, `lab-traffic`, `lab-capture`, `lab-export`, `lab-sanitize`,
  `lab-down`, `lab-clean`, `eval-lab` and `test-security`; the lab runbook at
  `infra/lab/README.md`; the L-0 – L-5 pre-flight checklist in `docs/evaluation.md` §7, ticked
  and renumbered from E-0 – E-5 so it stops colliding with `docs/STATUS.md`'s evidence rows.
- **What the lab found**, recorded in `docs/evaluation.md` §9 and pinned by
  `tests/unit/eve/test_lab_capture_fidelity.py`: 463 of 463 real records ingest with zero
  rejects and D-001 and D-002 fire on real traffic; but **D-004 cannot see a real beacon**
  because a flow record is stamped when it is emitted, not when the flow started (jitter 0.330
  against a limit of 0.15, where `flow.start` says 0.001), and **D-003 cannot read real DNS at
  all** because Suricata 8 writes EVE DNS v3, where a request carries an `rcode` too, and the
  rule reads "has an rcode" as "is an answer". Both are open defects with a chunk of their own;
  neither is fixed here, because both change `event_hash` and therefore the corpus, the
  fixtures and the pinned metrics table.
- 111 hermetic tests: the lab policy suite (`backend/tests/security/test_lab_policy.py`), the
  sanitiser (`backend/tests/unit/test_sanitize_eve.py`) and the fidelity suite over the real
  capture. The lab manifest joins the shared compose policy checks and the CI `manifests` job.
- **Milestone 2 closes.** Every acceptance criterion in `docs/delivery-plan.md` is ticked with
  its evidence, and `docs/STATUS.md` records the gate (E-54).
- **Chunk 12 (Milestone 2) — the periodiq schedule, the post-ingest sweep, `make eval`.**
  A sixth Compose service, `scheduler`, runs `periodiq aegisnet.workers.main` (Redis only,
  no volume, no port) and sends two periodic actors from `workers/schedule.py`:
  `scheduled_sweep` every `SWEEP_CADENCE_MINUTES` (10) over the last
  `SWEEP_LOOKBACK_MINUTES` (60) on a fixed grid, and `nightly_baselines` at
  `BASELINE_RECOMPUTE_HOUR` (02:00) over `BASELINE_WINDOW_DAYS` (7). The broker carries
  `PeriodiqMiddleware` with `SCHEDULE_SKIP_DELAY_SECONDS` (300) so stale ticks are skipped
  rather than replayed (ADR-020).
- A batch that completes with stored events queues `run_detectors` over the hour-aligned
  span of its event times (`EventWindowStore.batch_span`, `services/schedule.py`), from the
  worker after `import_dataset` and `import_upload` and inline after a `mode=sync` upload,
  which now audits `sweeps_queued`; `POST_INGEST_SWEEP=false` turns it off.
- `aegisnet eval-detectors` and `make eval`: the labelled cases through their rules (T1) and
  every rule over the benign corpus on its own grid (T2), rendered into the marked block of
  `docs/evaluation.md` §8 with strict verdicts and a note that D-005 abstains without
  baselines; `tests/detectors/test_evaluation.py` pins the committed block to the harness.
  The case loader moved from the test suite into `adapters/files/labelled.py`; the verdict
  and metrics arithmetic live in `domain/detectors/evaluation.py`.
- The CI stack job waits for the post-ingest sweep to record D-005 and checks the scheduler
  registered both periodic actors; compose policy tests cover the new service. 29 hermetic
  tests and 1 database test; `periodiq` added as a dependency.
- **Chunk 11 (Milestone 2) — D-004 beaconing, D-005 outbound volume, the baseline job.**
  `domain/detectors/beaconing.py`: per host and `destination:port`, inter-arrival intervals
  with a jitter bound and a minimum interval; internal destinations, DNS/DHCP/NTP/mDNS and
  operator-listed destinations excluded. `domain/detectors/volume_anomaly.py`: an hour's
  outbound bytes against the asset's baseline (mean + 3σ, 2 × p95, a 50 MiB floor),
  abstaining without a usable baseline. `domain/detectors/addresses.py` (the explicit
  internal-address list) and `baselines.py` (mean, population stddev, nearest-rank p95).
  `EventWindow.baselines` carries address-keyed statistics into the rules (ADR-019).
- `services/baseline_service.py` and `SqlBaselineStore`: one `asset_baselines` row per asset
  with outbound history over the last N days, from a grouped hourly aggregation on the
  event read store; the sweep maps those rows to the addresses in the window. The
  `recompute_baselines` actor, CLI `recompute-baselines` and `baselines`,
  `make recompute-baselines`, `make baselines`, `GET /api/v1/detections/baselines`
  (`detections.read`) and `POST /api/v1/detections/baselines/recompute` (`detections.run`,
  audited as `detection.baselines_requested`).
- Fourteen labelled cases for D-004 and D-005 (the fixture generator renders hour-long
  windows and puts baselines in `labels.yml`); specifications, guards and limitations in
  `docs/detection-rules.md`; 42 new hermetic tests and 3 database tests.
- **Chunk 10 (Milestone 2) — D-002 auth-failure burst and D-003 DNS anomaly.**
  `domain/detectors/auth_burst.py`: Suricata alerts whose signature or category reads like an
  authentication failure, tallied per source; fires on the count only when the densest
  two-minute span holds the whole threshold, so a steady monitoring probe never trips it.
  `domain/detectors/dns_anomaly.py`: per querying client (answers attributed to their
  destination), three signals with separate thresholds: many high-entropy names under one
  base domain, an NXDOMAIN storm by count and share, a stream of over-long labels; CDN and
  cloud suffixes allow-listed. Both registered, so every sweep runs three rules.
- Thirteen labelled cases (three positives and four hard negatives for D-002, three and
  three for D-003) rendered by `tools/gen_labelled_fixtures.py`, which gained `alert` and
  `dns` record builders; specifications, guards and limitations in `docs/detection-rules.md`;
  28 new detector tests.
- **Chunk 9 (Milestone 2) — the sweep, alert storage and the alerts API.** Revision
  `0003_detection_tables` (`detection_rules`, `detector_runs`, `alerts` with a UNIQUE
  `dedup_key`, `alert_events`, `alert_assets`, `asset_baselines`; six enum types; runtime
  role SELECT/INSERT/UPDATE, no DELETE). `services/detection_service.py`: registry synced
  from code, one bounded load per interval sliced on each rule's `window_seconds` grid,
  severity from the resolved asset's criticality with a stored rationale, dedup at the
  database, one `detector_runs` row per rule with per-rule failure isolation (ADR-018).
  `adapters/db/detection_store.py`, the `EventWindowStore` loader on the event read store,
  the `run_detectors` actor on the `detection` queue, CLI `run-detectors`, `alerts`,
  `alert`, `detector-runs`, `make run-detectors`, `make alerts`.
- Routes `GET /api/v1/alerts`, `GET /api/v1/alerts/{id}`, `GET /api/v1/detections/rules`,
  `GET /api/v1/detections/runs`, `POST /api/v1/detections/sweeps` with the permissions
  `alerts.read` (viewer), `detections.read` (analyst), `detections.run` (admin);
  `docs/api-milestone-2.md`. The CI stack job queues a sweep over HTTP and waits for the
  worker's `success` run. 54 new hermetic tests and 3 database tests (the stores, and the
  sweep end to end over an ingested labelled fixture).
- **Chunk 8 (Milestone 2) — the detector contract and D-001 port scan.**
  `domain/detectors/`: `EventWindow` (aware, sorted, at most 24 h and 200 000 events, every
  event inside the window), `DetectionResult` with evidence bounded at construction (no raw
  line can travel in it), `Entity`, sampled event ids, the `dedup_key`
  `rule_id:entity=value:window_bucket`, `RuleSpec`, the `Detector` Protocol; `severity.py`
  with the recorded formula and `reproduce`; the in-process registry; `PortScanDetector`
  counting distinct `(host, port)` targets per source with inclusive thresholds, unanswered
  flows raising confidence (ADR-017, `docs/detection-rules.md`).
- `tools/gen_labelled_fixtures.py` and seven labelled D-001 cases (three positive, four
  negative incl. the backup-client hard negative) under `backend/tests/fixtures/labelled/`,
  pinned byte for byte by a test; `make test-detectors`, `make gen-fixtures`; 38 detector
  tests (bounds, severity, D-001 behaviour and purity, registry, every labelled case).
- **Chunk 7 — the documents at the Milestone 1 gate.** A `dataset_id` that fails its grammar
  on `POST /api/v1/ingest/import` is now audited as `ingest.refused` with the caller and the
  field name (never the value), which closes the last API acceptance criterion. The
  delivery plan's M1 acceptance boxes point at their evidence; `ARCHITECTURE.md` gained an
  implementation-status section and reflects the M1 topology; `THREAT_MODEL.md` carries the
  gate review; `docs/evaluation.md` states that no detector exists and accuracy is
  unmeasured; `docs/STATUS.md` reconciles the Definition-of-Done checklist.
- **Chunk 6 — authentication, RBAC, audit, rate limits and the HTTP routes.**
  `domain/auth.py`: the permission set, the role matrix (`viewer ⊂ analyst ⊂ admin`,
  `ingest_service` = ingest + version), principals, the length-only password policy,
  opaque tokens stored as sha256. `services/auth_service.py`: Argon2id users, login with
  generic failures, timing equalisation and lockout, HS256 access tokens verified against
  the service clock, rotating refresh tokens with reuse detection that revokes the chain,
  logout with a Redis `jti` denylist, service tokens with expiry and revocation.
  `services/audit_service.py`: bounded, credential-free audit detail. `api/deps.py`: the
  deny-by-default `require(permission)` dependency, rate-limit dependencies and the
  `AppServices` factory injection (ADR-016).
- HTTP routes: `/api/v1/auth/{login,refresh,logout,me}`, `/api/v1/ingest/eve` (NDJSON
  body or multipart, `mode=sync|async` through a capped spool), `/api/v1/ingest/import`,
  `/api/v1/ingest/batches[/{id}[/rejects]]`, `/api/v1/assets` (create, bulk, resolve,
  list, get, patch, deactivate), `/api/v1/events[/stats|/{id}]`, `/api/v1/audit`.
  Response DTOs in `api/schemas.py`; new error codes `unauthenticated` (with
  `WWW-Authenticate: Bearer`), `invalid_credentials`, `forbidden`, `rate_limited` (with
  `Retry-After`), `payload_too_large`.
- Adapters: `adapters/db/auth_store.py` (users, refresh tokens, service tokens),
  `adapters/db/audit_store.py`, `adapters/cache/rate_limiter.py` (fixed-window limiter and
  token denylist on Redis), `adapters/files/spool.py`; the `import_upload` worker actor
  finishes an async upload from the spool; Compose gains the `ingest_spool` volume shared
  by `api` and `worker` only.
- CLI: `create-user` (password from stdin), `users`, `create-service-token` (printed
  once), `revoke-service-token`, `service-tokens`; Makefile targets `create-user`,
  `users`, `create-service-token`, `revoke-service-token`, `service-tokens`.
- `SECURITY.md`: the credential model, the RBAC matrix, the audit actions, the rate-limit
  policy, ingest hardening, known gaps and disclosure.
- 184 new hermetic tests (auth domain and service, audit service, Redis adapters on
  fakeredis, spool, CLI, the RBAC route-enumeration and 19 × 4 matrix suite, route
  integration for auth, ingest, assets, events and audit) and 5 database tests (SQL auth
  and audit stores, the auth service end to end on PostgreSQL). The `stack` CI job now
  creates a user and a service token through the CLI, proves the unauthenticated `401`,
  ingests the synthetic corpus over HTTP and reads the finished batch and the audit trail.
- **Chunk 5 — asset inventory and event reads.** `domain/assets.py`: validated
  `AssetSpec`/`AssetPatch` (hostname grammar, tags, criticality 1–5, strict CIDRs, one
  primary network), cross-asset overlap detection and the reference `resolve_ip`
  (longest prefix, then primary, then oldest). `services/asset_service.py`: create, bulk
  create (atomic, ≤500), upsert-by-hostname seeding, get, filtered keyset-paginated list,
  partial update that replaces networks, soft-delete, resolve. `services/
  event_read_service.py`: window ≤30 days, page size ≤200, cursor validation, payload on
  request only; `stats` by type and hour. Batches and rejects are listable with cursors
  (ADR-015).
- `domain/pagination.py`: opaque base64url keyset cursors, strictly validated (T-2.6).
- SQL stores `adapters/db/asset_store.py` (resolution as an `ORDER BY`, hostname
  uniqueness mapped to `HostnameConflictError`) and `adapters/db/event_read_store.py`
  (keyset on `(event_time, id)`, address/CIDR/port/flow/batch/asset filters, stats).
- Revision `0002_asset_network_delete_grant`: the runtime role may DELETE from
  `asset_networks` so a PATCH can replace them; nothing else gains DELETE.
- Seed file `samples/assets/lab-assets.yml` (14 lab hosts matching the synthetic corpus)
  and `make seed`; CLI commands `seed-assets`, `assets`, `asset`, `resolve`, `events`,
  `event-stats`, `batches`, `rejects`.
- 94 new hermetic tests (domain rules, cursors, both services against fakes, CLI parsing
  and the seed loader, the T-2.6 pagination-bounds suite) and 15 database tests (the
  asset store incl. resolution precedence and atomic bulk create; the event read store
  incl. a full pagination walk, the asset filter, stats; batch and reject listing).
- **Chunk 4 — ingest service.** `services/ingest_service.py` streams NDJSON line by line
  through the normaliser, writes events in chunks with `INSERT … ON CONFLICT (event_hash)
  DO NOTHING` so a re-ingest stores nothing and reports every line as a duplicate, writes
  one `ingest_rejects` row per bad line, and records counts, provenance and outcome on the
  batch. Exceeding `INGEST_MAX_LINES` marks the batch `failed` and keeps the valid events
  already stored; a bad line never fails a batch (ADR-014).
- `domain/ports.py` (the `IngestStore` Protocol and the batch value objects),
  `adapters/db/ingest_store.py` (SQLAlchemy implementation, running as the runtime role)
  and `adapters/db/session.py`.
- The first Dramatiq actor, `import_dataset`, in the new entrypoint layer
  `aegisnet.workers` (`dramatiq aegisnet.workers.main`). Messages carry ids only and are
  enqueued by actor name through `adapters/queue/ingest_queue.py`; the actor does not retry.
- Operator CLI `python -m aegisnet.cli` (`datasets`, `import-dataset --mode sync|async`,
  `batch`); `make demo-ingest` (`DATASET=`, `LABEL=`, `MODE=`) and `make batch ID=` run it
  inside the api image. The HTTP ingest routes ship together with authentication in
  Chunk 6.
- Settings for the ingest limits and `SAMPLES_DIR` (documented in `.env.example`);
  `./samples` bind-mounted read-only into `api` and `worker`; `worker` now depends on `db`
  as well as `redis`.
- import-linter layers are now entrypoints (`api | workers | cli`) over `services` over
  `adapters` over `domain`.
- 25 new hermetic tests (the service against an in-memory store: counts, chunking,
  intra-batch duplicates, the line budget, storage failure, provenance from the registry;
  CLI usage) and 5 database tests (idempotent corpus import matching the manifest, the
  provenance row, persisted rejects, promoted columns, and the actor end to end through a
  `StubBroker`).
- **Chunk 3 — EVE domain and synthetic corpus.** `domain/eve/`: parse limits enforced
  before parsing (byte cap, bracket-depth scan of the raw text, then depth, key and item
  counts on the parsed shape), a sanitiser that strips C0/C1 control characters and caps
  every string and key, a Pydantic schema for the EVE common fields and the `alert`, `dns`,
  `http`, `flow`, `tls`, `fileinfo`, `anomaly` and `ssh` sub-objects with unknown keys kept,
  a versioned canonical `event_hash`, and a pure, clock-free normaliser producing
  `NormalizedEvent` or a `Reject` carrying one of the seven documented reason codes and no
  input value (ADR-013). `domain/models.py` holds the frozen value objects.
- `adapters/files/registry.py`: `samples/registry.yml` loader and dataset resolution by id
  only — relative path confined under `samples/`, symlinks refused at every component,
  sha256 verified before a byte is read, and error messages free of paths (T-1.6).
- `tools/gen_synthetic_eve.py`, a standard-library, seeded generator; the committed corpus
  `samples/synthetic/benign-baseline-01.ndjson` (2000 events, 937 KB, RFC 1918/5737
  addresses and example.test/example.com names only) with its manifest, registered in
  `samples/registry.yml`; `samples/README.md`; `make gen-synthetic`.
- import-linter contracts (`domain` imports no infrastructure; `api` over `adapters` over
  `domain`), run by `make lint` and the CI backend job. Ruff and the pre-commit hooks now
  also cover `tools/`.
- 125 new hermetic tests: sanitiser, limits, schema, hash and normaliser over hand-built
  benign and hostile fixtures (`backend/tests/fixtures/eve/`), payload-limit and
  path-traversal security suites, generator determinism and safety, and an integrity test
  tying the committed corpus, its manifest and the registry checksum together.
- **Chunk 2 — schema baseline.** Alembic revision `0001_m1_baseline` creates the nine
  Milestone 1 tables from `docs/data-model.md` (`users`, `service_tokens`, `refresh_tokens`,
  `audit_log`, `ingest_batches`, `events`, `ingest_rejects`, `assets`, `asset_networks`),
  nine PostgreSQL enum types, every documented index including `UNIQUE (event_hash)`,
  `GIST (cidr inet_ops)`, `GIN (payload jsonb_path_ops)` and the partial indexes, and
  check constraints for hash lengths, port ranges, criticality and text caps. It runs as
  the migrator role and grants the runtime role `SELECT, INSERT, UPDATE` on the ordinary
  tables, `SELECT, INSERT` on `audit_log` plus `USAGE` on its identity sequence, and
  `SELECT` on `alembic_version`; no `DELETE` anywhere and no DDL (T-2.5, T-5.3).
  `audit_log` has no foreign keys so no referential action can rewrite it. The migration
  environment ships inside the package (`adapters/db/migrations/`), `alembic.ini` carries
  no URL, and `env.py` reads the migrator credentials from `Settings.migration_url`
  (ADR-012).
- SQLAlchemy 2.0 models for the same nine tables (`adapters/db/models.py`) and the schema
  enumerations in `domain/enums.py`, the first module of the pure domain layer.
- `schema_revision()` in `version.py` reads the head of the packaged revisions;
  `/api/v1/meta/version` now reports it (`0001_m1_baseline`).
- `make migrate` (`alembic upgrade head` inside the api image), `make migrate-status`, and
  `make test-db`, which runs the new database suite against an ephemeral PostgreSQL 16
  started from `docker-compose.test.yml --profile db` (`db-test`, `tests-db`; decision F-2)
  and tears it down afterwards. The hermetic `tests` service is unchanged.
- Database suite `backend/tests/db/` (marker `db`, opt-in via `AEGISNET_DB_TESTS=1`):
  the nine tables and nothing else, `alembic_version` equals the packaged head, Alembic's
  `compare_metadata` reports no difference between the models and the migrated schema,
  enum labels, specialised index definitions, the `event_hash` length and uniqueness
  constraints, case-insensitive `users.email` (citext), server-side defaults, the runtime
  role's exact privilege matrix and table ownership, refusal of UPDATE/DELETE/TRUNCATE on
  `audit_log` and of every DDL and DELETE statement, and a head → base → head round trip
  that leaves nothing behind.
- CI job `migrations` runs that suite on every push; the `stack` job now applies the
  migrations with `alembic upgrade head` inside the started stack and asserts the version
  endpoint reports the head.
- The init script grants the migrator `CREATE` on the database so a revision can install
  the trusted `citext` extension; the runtime role never receives it.
- Repository scaffolding: ignore rules that treat secrets, packet captures, and live sensor
  output as never-committable; Docker ignore rules; MIT licence; this changelog.
- `.gitattributes` normalising every text file to LF on every platform, so files that are
  bind-mounted or copied into Linux containers (the PostgreSQL init script above all) are
  not broken by a CRLF checkout.
- `.env.example` environment template using `__REPLACE_ME__` placeholders, and
  `infra/scripts/bootstrap_env.py` (`make bootstrap`) which generates a local
  development-only `.env` with cryptographically random secrets, idempotently and without
  printing any value (ADR-011).
- Pre-commit configuration: whitespace and merge-conflict hooks, Ruff, gitleaks, and a hook
  that hard-fails if `.env` is ever staged.
- Milestone 0 planning package: PRD, architecture, threat model, repository structure, data
  model, Milestone 1 API contract, six-milestone delivery plan, evaluation plan, and status
  record.
- ADR-009 (defer the isolated Suricata lab to Milestone 2), ADR-010 (defer the scheduler and
  periodiq to Milestone 2), ADR-011 (bootstrap-generated development secrets).
- Docker Compose topology for five services (`db`, `redis`, `api`, `worker`, `web`): every
  published port bound to `127.0.0.1`, no host port at all on `db`, `redis` or `worker`,
  `cap_drop: ["ALL"]` and `no-new-privileges:true` everywhere, every container running as a
  non-root user, dependency ordering via healthchecks. The worker probe is process liveness
  only and makes no readiness claim.
- Multi-stage backend and frontend images, both ending on a non-root `USER`, with matching
  `.dockerignore` files; a hermetic test/lint runner in `docker-compose.test.yml`; an example
  local override file, with `docker-compose.override.yml` itself gitignored.
- PostgreSQL initialisation creating two least-privilege roles, `aegisnet_migrator` and
  `aegisnet_app`. It validates every interpolated role name and secret against a strict
  allowlist and fails closed, and it creates no tables.
- hadolint configuration waiving only DL3006 and DL3008, each with a recorded reason.
- Backend FastAPI application: settings whose secrets are `SecretStr` and which refuse to
  load while any value is still a `.env.example` placeholder outside `ENV=test`; JSON
  logging with correlation-ID propagation, literal-secret scrubbing and control-character
  neutralisation of untrusted values; a single error envelope that discloses no traceback,
  SQL or path; `GET /healthz`; `GET /readyz`; `GET /api/v1/meta/version`.
- Async PostgreSQL engine and async Redis client, connectivity only. A Dramatiq broker
  factory (`adapters/queue/broker.py`) with an explicitly authenticated Redis client and a
  separate worker entrypoint (`adapters/queue/worker.py`) that registers **zero** actors
  (ADR-010), so the worker's topology is proven without inventing a workload.
- `backend/uv.lock`, committed so `uv sync --frozen` and the image build are reproducible.
- Next.js health placeholder for the `web` service: one server-rendered page and
  `GET /api/health`, standalone output, conservative response headers, pinned `pnpm` via
  `packageManager`, committed lockfile. No authentication UI, no business UI (F-9).
- Backend test suite, 124 hermetic tests needing no database or Redis:
  - unit: settings placeholder refusal, `SecretStr` non-disclosure, URL credential escaping,
    log sanitisation (C0/C1, ANSI, CR/LF), secret scrubbing by value and by key name,
    exception records carrying the type only, broker authentication (regression), zero
    actors, `bootstrap_env.py` guarantees;
  - integration: liveness, readiness against faked probes including the timeout path and
    the no-component-detail rule (F-15), version metadata with the git SHA withheld in
    production, interactive docs disabled in production, correlation-ID handling;
  - security: the error envelope leaks nothing (T-2.7); the Compose manifests, both
    Dockerfiles, `.env.example`, `.gitignore` and the pre-commit config satisfy the declared
    policies (T-5.1, T-5.2, T-5.4), read as data.
- `make test`, `test-cov`, `compose-test`, `build`, `up` and `down`. `check` now runs the
  suite after the static checks; `lint`/`format` cover `tests/` too.
- GitHub Actions: `ci.yml` (ruff, ruff format, mypy, pytest with an 85% coverage gate, tsc
  and `next build`, compose config and hadolint, and a `stack` job that runs
  `docker compose up --build --wait` and curls every published endpoint) and `security.yml`
  (gitleaks, pip-audit over the exported uv lockfile, pnpm audit; on push, pull request and
  weekly). On the first push `ci` was green end to end — the stack job reached healthy on
  the runner — and `security` failed on the genuine dependency findings fixed below.

### Changed
- The version route reports `0003_detection_tables`; the stack probe and the README expect it.
- README rewritten for the public repository: architecture diagrams (topology, layering,
  the upload pipeline, request handling), the RBAC matrix, a repository map, the roadmap,
  workflow and quality-gate badges. `CONTRIBUTING.md` and a pull-request template added;
  the repository is public with topics, Dependabot alerts, secret scanning and push
  protection enabled.
- `Spool.write(name, chunks, max_bytes)` takes a caller-minted name (`Spool.new_name()`)
  and returns the byte count; `Spool.lines(name)` reads an entry asynchronously. The
  ingest route mints the name before it reads the body. `anyio` is a direct dependency.
- `.sonarcloud.properties` declares the source roots and `backend/tests` as tests for
  SonarCloud automatic analysis, so ratings reflect main code (E-39).
- `/api/v1/meta/version` requires a credential (`meta.read`); the CI stack probe and the
  README quickstart obtain a service token first (Chunk 6).
- `IngestService.ingest` accepts a pre-opened `batch_id` so the worker can finish a batch
  the API opened; `bounded_detail` keeps one level of nested mapping (Chunk 6).
- The hermetic coverage gate now also excludes the SQL stores and the worker package,
  which the database suite and the stack exercise; both results are recorded in
  `docs/STATUS.md`.
- The worker entrypoint moved from `adapters/queue/worker.py` to `aegisnet.workers.main`;
  the Compose `worker` command and liveness probe follow. `adapters/queue` keeps the broker
  factory plus the queue and actor names (ADR-014).
- Request-derived text is neutralised at the sink, not only by the log formatter.
  `untrusted_text` strips CR and LF explicitly, then every other control character, and
  truncates; `safe_value` delegates to it for strings. The unhandled-exception log call
  passes the request path and method through it, and the correlation-ID middleware
  re-renders the inbound id from the parsed UUID and passes it through the same strip
  before echoing it in the response header (`canonical_correlation_id`). Behaviour is
  unchanged; the guard is now visible at each sink to a reader and to static taint
  analysis. Prompted by the SonarCloud quality gate, which has failed on *Security Rating
  on New Code C* since its first analysis; the project is private on sonarcloud.io and the
  check exposes no finding, so this addresses the two flows its Python taint rules cover.
- GitHub Actions: every action moves to a release that runs on the Node 24 runtime
  (`actions/checkout` v6, `actions/setup-node` v7, `actions/upload-artifact` v7,
  `gitleaks/gitleaks-action` v3, `astral-sh/setup-uv` v10.0.1). Every job of both workflows
  was annotated "Node.js 20 is deprecated", and GitHub removes Node 20 from hosted runners
  on 2026-09-16, after which the previous majors would not run at all. `setup-uv` publishes
  no major tags from v8 on and is pinned to an exact release. The `hadolint` action is a
  Docker action and is unaffected.
- Ruff now also enforces `BLE` (blind `except`). The one intentional broad catch, a failed
  readiness probe, carries an explicit waiver.
- The Dramatiq worker is started with `dramatiq aegisnet.adapters.queue.worker`; the broker
  module is now a side-effect-free factory so it can be imported and tested.
- `README.md`, `docs/STATUS.md` and this file now describe what exists and what has been
  verified locally, with the evidence listed in `docs/STATUS.md`. Earlier revisions claimed
  no application code existed after it had been committed, and referred to tests that had
  not been written.

### Security
- The echoed `X-Correlation-ID` is rebuilt from the parsed UUID's integer, never from the
  inbound string; the unhandled-error log records the matched route template and a
  fixed-set method instead of the request path and method (E-40).
- Chunk 6: no route answers without a permission dependency; a present-but-invalid
  credential is `401`, never anonymous; refresh-token reuse revokes the chain and clears
  the cookie; refused uploads and permission denials are audited; login and ingest rate
  limits fail closed when Redis is unavailable; passwords never appear in argv and tokens
  are stored only as hashes (ADR-016, `SECURITY.md`).
- The first `security` workflow run flagged real, known-vulnerable dependencies; both
  findings are fixed by upgrade, verified by a clean local `pip-audit --strict` and
  `pnpm audit --prod --audit-level=high`, with the suite unchanged at 124 passed:
  - starlette 0.46.2 (pulled in by the fastapi `<0.116` pin) carried nine advisories.
    fastapi moves to 0.141, uvicorn to 0.52, and a `constraint-dependencies` entry bars the
    resolver from any starlette below 1.3.1 (now 1.6.0). The two status-code constants
    starlette renamed are updated (`HTTP_413_CONTENT_TOO_LARGE`,
    `HTTP_422_UNPROCESSABLE_CONTENT`); the wire format is unchanged.
  - next 14.2.35 carried ten high advisories patched only in the 15.5 line. The web
    placeholder moves to next 15.5.24 with react 19, and a pnpm override forces the
    bundled postcss to ≥8.5.18 (next still pins 8.4.31, which has two high advisories).
- The `web` image base moves from `node:20-alpine` (end of life April 2026) to
  `node:22-alpine`, matching the CI node version.

### Fixed
- The last SonarCloud quality-gate condition (*Security Rating on New Code C*): a
  redundant `Path.chmod` after creating `.env` with mode 0600 in `bootstrap_env.py`,
  located by bisecting the analysis scope (E-41). The gate passes.
- Dependabot GHSA-6w46-j5rx-g56g: pytest upgraded to 9.x (with pytest-asyncio 1.x); both
  suites unchanged.
- Sonar `python:S7493` (a synchronous `Path.open()` inside an `async def`) in the dataset
  importer and the upload actor, the two Major bugs behind the *Reliability Rating on New
  Code C*: NDJSON is now read through `anyio` and `IngestService.ingest` accepts a sync or
  async line source (E-39).
- The `ingest_spool` named volume was mounted root-owned while the api and worker run as
  uid 10001, so the first HTTP upload failed with `500`. The image now creates `/app/spool`
  owned by the runtime user (a named volume inherits it on first use) and both processes
  run `Spool.ensure_writable()` at startup so a wrong mount fails loudly, not per request
  (Chunk 6, E-37).
- The `security` workflow's pip-audit job used the same uv cache key as the `ci` backend
  job. Finishing first, it saved a cache that held only pip-audit's own dependencies, so the
  backend job could never save the runtime set it had just installed; setup-uv v10 surfaces
  this as "Unable to reserve cache". The pip-audit job now runs with the cache disabled.
- `.env.example` no longer places comments on the same line as an assignment. Docker Compose
  `env_file` does not strip a trailing `# comment`, so `SECRET_KEY` would have been delivered
  to the container with the comment text appended to its value.
- The log sanitiser now strips LF and CR. It previously allowed both, so a newline inside an
  untrusted value survived; the JSON encoder escaped it, but any future non-JSON log sink
  would have made log-line forgery possible.
- `backend/pyproject.toml` declared `readme = "../README.md"`. A readme outside the project
  directory is rejected by the build backend, which made the package impossible to build or
  install; `backend/README.md` now holds the package-level readme.
- `docker-compose.test.yml` inlined four literal credential values. It now sets no secret
  variables at all and relies on the placeholder defaults, which only `ENV=test` accepts. The
  "no inline secret literals" policy test covers every Compose file, including this one.
- The worker never authenticated to Redis. `RedisBroker(url=..., password=...)` builds its
  own connection pool from the URL and redis-py ignores `password` when a pool is supplied,
  so the first Redis command would have failed with `NOAUTH`. The broker now receives an
  explicitly authenticated client, and a regression test pins the connection arguments.
- The worker liveness probe always passed: `pgrep -f 'dramatiq …'` matched the `sh -c`
  wrapper running the probe, whose command line contains the pattern. The pattern is now
  `[d]ramatiq …`, which cannot match itself.
- The stack could not start. Under `cap_drop: ALL` the official `postgres` and `redis`
  images fail to drop from root to their service user (`setresuid failed: Operation not
  permitted`) and restart-loop. Both services are now started directly as that user via
  `user:`, keeping the capability drop intact. This was the first time the stack was started;
  every service now reports healthy.
- CRLF checkouts on Windows made `infra/postgres/init/01_roles.sh` unusable when
  bind-mounted into the database container; fixed by `.gitattributes`.

### Not yet present
Database migrations, ORM models, Suricata EVE schemas and normalisation, ingestion
endpoints, dataset registry, background actors, asset and event APIs, authentication, RBAC,
audit logging, rate limiting, detectors, correlation, Perplexity integration, reports,
dashboard, `SECURITY.md`.
