# AegisNet — Milestone 5 API additions

Status: **Chunks 23 and 24 implemented — investigation briefs (generate, list, read one
version) and the deterministic Markdown export.**
Conventions, the error envelope, auth and rate limits are those of
[`api-milestone-1.md`](api-milestone-1.md). Permissions: `briefs.read` (viewer and above),
`briefs.generate` (analyst and above), and `incidents.read` for the export. What may leave the deployment is
[ADR-029](adr/ADR-029-nothing-leaves-that-was-not-named.md); what may come back is
[ADR-030](adr/ADR-030-the-model-is-a-witness-not-an-authority.md); how a brief is stored and
served is [ADR-031](adr/ADR-031-a-brief-is-append-only-and-a-failure-is-a-brief.md); the export is
[ADR-032](adr/ADR-032-the-report-changes-nothing-and-escapes-everything.md).

### Three things to know before reading the endpoints

**It is off by default.** `BRIEF_ENABLED` is false and there is no key in a fresh checkout. In
that state `POST` still answers `201`, with the committed sample in `samples/briefs/` and
`"source": "offline_fixture"`. Nothing leaves the machine, and nothing in the response
pretends a model wrote it.

**A failure is stored, not raised.** Every way the call can go wrong — the feature is off, no
key, the daily budget is spent, a 503, an answer that would not parse, an answer the safety
filter refused — is a row with `"status": "failed"` and a short `failure_reason`, answered
`201`. The one thing that is *not* a brief-level failure is an unknown case, which is `404`.

**A brief never changes the case.** It appends one `brief_generated` timeline entry and one
`brief.generated` audit row. It cannot move a severity, a status or an alert; there is no field
in the response through which it could try.

### Briefs

**`POST /api/v1/incidents/{id}/briefs`** — `briefs.generate` · no body. Builds the redacted
evidence packet, asks, and stores the outcome as the next version. `201` with the brief;
`404 not_found` if there is no such case. Rate limited as a default-class write.

**`GET /api/v1/incidents/{id}/briefs`** — `briefs.read` · every version ever written about the
case, newest first. Not paginated: versions are few by construction and the daily budget bounds
them.

**`GET /api/v1/incidents/{id}/briefs/{version}`** — `briefs.read` · one version, `1`-indexed.
`404 not_found` for an unknown case or an unwritten version; `422` for a version below 1 or
above 10 000.

A brief is:
```json
{ "id": "…", "incident_id": "…", "version": 1,
  "status": "complete", "source": "offline_fixture",
  "packet_hash": "5f2c…", "packet_truncated": false, "model": null,
  "summary": "Four short outbound connections from asset-A to ext-1 …",
  "limitations": "The packet carries no process or user context …",
  "claims": [ { "text": "asset-A contacted ext-1 fourteen times in fourteen minutes.",
                "kind": "observed", "citations": [], "verified": true },
              { "text": "Regular low-variance intervals are a common beaconing signature.",
                "kind": "external", "citations": [1], "verified": true } ],
  "recommendations": [ { "action": "investigate_host",
                         "detail": "Confirm what on asset-A opened the connections." } ],
  "citations": [ { "id": 1, "url": "https://attack.mitre.org/techniques/T1071/", "title": "…" } ],
  "has_unverified": false, "failure_reason": null, "created_at": "…" }
```

`status` is `complete` or `failed`. `source` is `perplexity` or `offline_fixture` — the second
is the committed sample and never anything a model said. `model` is null unless a model
actually answered.

`packet_hash` is the SHA-256 of exactly what was sent. It is the record of *which* question was
asked, and it is what the audit trail carries; the packet itself is written nowhere.
`packet_truncated` is true when the case was large enough that the packet was trimmed to its
cap, which is worth seeing next to a thin summary.

A claim's `kind` is `observed` (it follows from the packet) or `external` (the model's own
research, which must cite a source). `verified` is false when an external claim cited nothing;
such a claim is kept and marked, never silently dropped, and `has_unverified` is the summary of
that for a client that wants to badge the whole brief. Every citation `url` is `https`, checked
in the domain and again by the database.

`recommendations[].action` is one of `investigate_host`, `review_with_asset_owner`,
`check_baseline`, `collect_more_evidence`, `correlate_with_other_cases`, `monitor`,
`document_and_close`, `escalate`, `no_action_needed`. There is no vocabulary for acting on a
system, and an answer that recommends one is refused whole.

`failure_reason` is short and machine-readable: `disabled`, `unconfigured`,
`budget_exhausted`, `response_too_large`, `malformed_json` (the HTTP body), `no_content`,
`malformed_brief` (the model's own answer), `schema_rejected`, `safety_rejected`, `http_<status>`
for a status the API returned, or an httpx exception's class name (`ConnectTimeout`,
`ReadTimeout`, `ConnectError`, …) when the request never completed. The exception's *type* and
never the exception: an httpx error carries the request, and the request carries the
`Authorization` header.

### What it records

The timeline gains one entry per attempt:
```json
{ "entry_type": "brief_generated", "summary": "Investigation brief v1 generated",
  "detail": { "version": 1, "status": "complete", "source": "offline_fixture" } }
```
and the audit log one `brief.generated` row, `success` or `error`, whose detail carries the
version, the status, the source, the `packet_hash` and — on a failure — the reason. Never the
packet and never the answer.

### The Markdown export

**`GET /api/v1/incidents/{id}/report.md`** — `incidents.read` · the whole case as a Markdown
document: the case and how its severity was derived, the assets the inventory matched, every
alert with the evidence its rule recorded, the timeline, the notes, every investigation brief
with its claims and sources, what the document does not cover, and an appendix naming the
ingest batches the evidence rests on (FR-9.1). `404 not_found` for an unknown case.

Answers `text/markdown; charset=utf-8` with
`Content-Disposition: attachment; filename="AEG-2026-0001.md"`, `Cache-Control: no-store` and
`X-Content-Type-Options: nosniff`. Errors are the ordinary JSON envelope: only a `200` is
Markdown.

**The same case gives the same bytes** — the same case *and the same permission*, precisely.
Two exports can be diffed, and a difference means the case changed rather than the renderer did.
Four things follow, and are worth knowing:

- **The export writes nothing to the case.** No timeline entry — one would change the case the
  next export renders — so `report_exported` is a timeline type this project does not write.
- **There is no "generated at" line.** The document dates the case; the export is dated by the
  file it lands in.
- **It is still audited.** `report.exported` records who took a copy, of which case, and how
  many bytes — never the document. The audit log is not rendered by the report, so recording
  the export cannot move the bytes (FR-10.3).
- **The provenance appendix needs `ingest.read`.** It names the ingest batches behind the case —
  source label, dataset, line counts — and those are an analyst's to read. A viewer's export
  carries every other section and says the appendix was withheld, rather than being a way around
  the permission.

**Nothing in it can become markup.** A rule id, an entity value, an analyst's note and a
model's summary are all strings this project did not write, and a Markdown viewer is a renderer
like any other. Every untrusted value is backslash-escaped or fenced, so it renders as itself:
a note containing `# ` is a note about a hash, not a heading. Citation URLs are printed rather
than linked, so reading the document cannot navigate anywhere on its own. The guarantee is
checked against a real CommonMark parser with GFM tables; the one thing outside it is GFM's
literal autolink extension, which re-scans text after escapes resolve and can still turn a bare
email address into a `mailto:` link.

**It is not redacted.** The document carries the case as it is — real addresses, real
hostnames, the analyst's own words — because it is written for the operator, who can already
read all of it through this API. `domain/redaction` is for the other direction (ADR-029). The
document says so in its first paragraph.

A viewer may export, because everything in the document is something a viewer can already read
as JSON.

### The daily budget

`BRIEF_DAILY_BUDGET` caps calls per UTC day across the whole deployment: the counter lives in
Redis, so the API, the worker and the CLI spend from one number rather than three. An attempt
past the cap is a stored brief with `failure_reason: budget_exhausted`. An identical packet is
answered from the process's cache without spending anything.

### From the command line

```bash
make brief REF=AEG-2026-0001            # the brief, as JSON
make export REF=AEG-2026-0001 > case.md # the case, as the document above
```
Both go through the same services the routes do. `export` writes the document to stdout rather
than through the CLI's usual JSON wrapper, because the point of it is the bytes: running it
twice on an unchanged case produces two identical files.

(The delivery plan wrote these as `INCIDENT=`; the repository's neighbouring case-scoped targets
all use `REF=`, and these match them.)
