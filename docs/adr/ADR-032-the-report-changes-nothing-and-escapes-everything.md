# ADR-032 — The report changes nothing, and escapes everything

- Status: accepted
- Date: 2026-09-06
- Milestone: 5 (Chunk 24), which it completes; follows
  [ADR-027](ADR-027-markdown-is-parsed-into-elements-never-into-html.md),
  [ADR-029](ADR-029-nothing-leaves-that-was-not-named.md),
  [ADR-030](ADR-030-the-model-is-a-witness-not-an-authority.md) and
  [ADR-031](ADR-031-a-brief-is-append-only-and-a-failure-is-a-brief.md)

## Context

Milestone 5 asks for two last things: a case exported as Markdown, byte-identical across two
runs, and the brief on the analyst's screen with its citations and its `UNVERIFIED` tags.

They look like a rendering chore. They are not, quite: the export is the first thing this
project produces that is meant to leave the deployment in a human's hands, and the panel is
the first place model-written prose about attacker-influenced input is shown to a person.

## Decision

### The export writes nothing to the case, and is audited anyway

Those are two different statements and the difference is the whole of this section.

**Nothing is written to the case.** A report that recorded its own export in the timeline would
change the case it renders, so the next export would differ from this one and the acceptance
criterion would fail on its first run. This is not hypothetical: Chunk 23 shipped exactly this
defect in the evidence packet, found it by running `brief` twice against the stack, and fixed
it with a `BOOKKEEPING` exclusion — which protects the packet and not a document. A `GET` that
appends to the case would also let a viewer, holding `incidents.read`, mutate one.

**`TimelineEntryType.report_exported` therefore stays unwritten**, as `brief.requested` and
`brief.egress` — both named in `docs/data-model.md`'s illustrative list of audit actions — were
left unwritten before it. An enum value is a vocabulary, not a promise.

**An audit row is written.** FR-10.3 names an export an auditable event, and an export is not
an ordinary read: it is the whole case as plain text in a file somebody can forward. It cannot
affect determinism, because the report renders the case and the audit log is not part of the
case. `report.exported` carries the case number and the document's size — never the document,
which would make the audit log a second copy of the evidence.

This is the first read in this API that writes an audit row, and the objection to it was worth
checking rather than assuming: does an audited read hand a viewer an append primitive into a
table with no `DELETE` grant and no retention job? It does not, because they already have one.
`rbac.denied` is written for every refused request, so any authenticated principal can append
at the read rate limit today by asking for something they may not have — verified against the
running stack, three refused requests, three rows. Retention for that table is Milestone 6's
problem, and it is one problem rather than two.

### A viewer may export, and the appendix is the exception that proves it

Everything in the document is something the caller can already read as JSON through
`incidents.read` and `briefs.read`. Gating the *format* would protect nothing and would teach an
operator that the export is the sensitive part, which is the wrong lesson: the sensitive part is
the case.

That premise was very nearly false, and the review caught it. The provenance appendix names
ingest batches — source label, dataset, line counts — and reading those is `ingest.read`, which
a viewer does not hold. A report that carried them would have been a way around a permission,
justified by a sentence that had stopped being true the moment the appendix was added. The
appendix is therefore rendered only for a caller holding `ingest.read`, and everyone else is
told it was withheld and why rather than left to wonder whether the case had one.

That refines the promise honestly: **the same case and the same permission produce the same
bytes**. Determinism was never a claim that the document is independent of who asked; it is a
claim that nothing about *when* you asked can change it.

### Determinism is a property of the renderer, not of the query

`domain/reports.py` is a pure function of records — no clock, no I/O, no settings — which is
what makes the claim testable without a database in the room. Every collection is sorted there
rather than trusted to arrive ordered, and **every sort ends in a unique key**, because two
rows sharing an instant have no order at all and a query plan is not a contract. Dictionaries
are serialised with sorted keys, floats are formatted to a fixed precision, and a naive
datetime is read as UTC rather than against whatever zone the machine is in.

The single most tempting way to break it is a "generated at" line. There is none. The document
dates the case; the export is dated by the file it lands in.

### The document's structure is ours; its content is inert

A Markdown document is rendered by something. A note containing `# ` becomes a heading in the
viewer the analyst opens it in; one containing `[go](http://…)` becomes a link; one containing
`<img src=…>` may become a request from whoever opened it. None of that text was written by
this project.

So every untrusted string is **backslash-escaped for prose or fenced for machine data**, and
the escape is total — every ASCII punctuation character, which CommonMark defines as escapable
— rather than a chosen subset. An allow-list of "the constructs that matter" is how a renderer
surprises you. It costs raw readability and buys a property that can be stated in one line.

This is [ADR-027](ADR-027-markdown-is-parsed-into-elements-never-into-html.md) pointed the
other way. There, hostile text is parsed into React elements so no markup can exist; here,
hostile text is escaped into a document so no markup can form.

The test is the Chunk 19 lesson applied to a document: it does not check that the output lacks
a substring, it **renders the document with a real CommonMark parser** and asserts on the
tokens. Given a case poisoned in every string field with every construct at once, the parser
must build no link, no image, no HTML and no heading the report did not write — and the poison
must still be readable, because a renderer that dropped hostile text would pass and lose the
evidence.

Characters that change how text *looks* without being visible get the same treatment from the
other direction. A right-to-left override turns `emoc.live` into something else on the page, and
in a document about an attack that is the attack. They are not stripped — a report about
somebody who used one must still show that they did — so each is written out as its own code
point: `<U+202E>`. The evidence survives and the trick does not.

**That test found a defect on its first run, and the adversarial review found the fix was
wrong.** A code span inside a GFM table cell is not safe: GFM splits a row on `|` before it
parses anything inline, so a pipe inside a code span ends the cell, unmatches the backticks, and
turns the rest of somebody else's text into ordinary Markdown — an entity value containing
`| a | b |` made a `javascript:` URL two cells later into a link. Escaping the pipe as `\|`
looked like the answer and was not: **a backslash cannot itself be escaped inside a code span**,
so a value already containing `\|` emits two backslashes and a renderer that consumes the
escaped backslash reads the pipe as live again. There is no way to render an arbitrary value as
a code span in a table. So a table cell is escaped text like everything else, and monospace in a
table turned out to be worth less than a rule with no exceptions.

The same review found the one construct escaping structurally cannot reach: the **indented code
block**, which opens on four spaces or a tab rather than on punctuation. A pasted log excerpt
became a code block the report never wrote, and inside one a backslash stops being an escape, so
the analyst's evidence rendered full of visible `\/` and `\=`. Leading whitespace is stripped.

The limit of the claim, stated rather than glossed: the guarantee is against CommonMark and
GFM's tables, checked with a real parser. GFM's *literal autolink* extension is a different
mechanism — it re-scans text after escapes are resolved, so a bare email address in a note can
still become a `mailto:` link on a host that enables it. That is a link the report did not write,
and it is the one gap the escaping strategy cannot close by construction.

### The report is not redacted, and says so

It carries the case as it is: real addresses, real hostnames, the analyst's own words. That is
correct — it is written for the operator, who can already read every one of those — and
`domain/redaction` exists for the other direction, where the reader is a third party (ADR-029).
The document states this in its own first paragraph, so nobody learns it from a leak instead.

### The dashboard renders a citation as a link, and that is new

`SafeMarkdown` renders no links, on purpose. A citation is the one case where the link *is* the
point: a claim about the outside world is worth nothing if the analyst cannot go and check it.

So `CitationList` is a separate component that builds anchors from the structured `citations[]`
array and never sees a markdown string — ADR-027's property is untouched, because this simply
is not a markdown renderer. Each anchor is `https` only (parsed with `new URL`, not
prefix-matched), `rel="noopener noreferrer nofollow"`, `target="_blank"`. Credentials are refused too:
`https://attack.mitre.org@evil.test` is a perfectly good https URL that goes to `evil.test`, and
the part a reader recognises is the part that means nothing. A URL that fails any of these is
shown as text with a line saying why — a source nobody can follow is still evidence of what the
model said. The API refuses the same URLs; this is the copy of the check that sits next to the
`href`, which is the one that has to be right.

This is the first anchor to an external origin this dashboard has ever rendered. It is worth
arguing for rather than slipping in.

### The download goes through this app, never to the API

The browser never learns the API's address (ADR-026), so the case page links at
`/incidents/{id}/report.md` — a route handler in the dashboard that reads the session cookie,
asks the API, and passes the bytes through unchanged. A link straight at `AEGISNET_API_URL`
would put the API's address into the HTML, which is the one property the whole session design
exists to hold.

## Consequences

- Positive: two exports of an unchanged case are the same file, so a diff between them means
  the case changed. That is what makes an exported report usable as a record.
- Positive: the export cannot write to the case at all, so it is safe to leave rate-limited
  rather than gated, and safe to give a viewer. The one row it does write goes to a table any
  authenticated principal can already append to through `rbac.denied`.
- Positive: hostile content in a case survives into the document *and* stays inert, proven
  against a real CommonMark parser rather than against a list of strings.
- Negative: the raw Markdown is uglier than it needs to be. `asset\-A did four things\.`
  renders correctly everywhere and reads badly in a text editor. The alternative was escaping
  fewer characters and being wrong somewhere.
- Negative: `report.exported` makes this the first audited read here, so "audit is for writes
  and denials" stops being true of the codebase and has to be read as "audit is for writes,
  denials, and taking a copy of a case".
- Neutral: `make export` is `REF=`, not the delivery plan's `INCIDENT=`, matching the
  neighbouring `brief` and `incident` targets. The plan's `GET .../report.md` path is kept
  exactly.
