# ADR-034 — The threat model is checked by the suite

- Status: accepted
- Date: 2026-09-06
- Milestone: 6 (Chunk 27); answers the sentence
  [`THREAT_MODEL.md`](../../THREAT_MODEL.md) §5 has carried since Milestone 1 — that
  `docs/RELEASE_CHECKLIST.md` blocks `v1.0.0` until every mitigation has a named passing test or
  an explicit accepted-risk entry

## Context

`THREAT_MODEL.md` has had a *Verified by* column since the planning phase, and it has been kept
honest by hand: at every milestone gate somebody read the rows, found the ones whose wording had
gone stale, and rewrote them. That worked because the same person wrote the tests the same week.

It does not survive a release. The column is prose — "`tests/security/test_rbac.py` — Chunk 6",
"Log-scrubbing unit test", "Client config test" — and prose does not fail when a test is renamed.
Two of those three examples never named a function at all, which means the model asserted coverage
that nobody could check without going to look. That is exactly the artefact a reviewer opens first,
and it is the one thing in this repository with no test behind it.

M6's acceptance criterion — *every mitigation maps to a named passing test or an accepted-risk
entry* — cannot be ticked by reading. It needs a form a machine can read.

## Decision

### The matrix is data, and §6 is where it lives

A new section of `THREAT_MODEL.md` carries one row per threat, between
`<!-- coverage:begin -->` and `<!-- coverage:end -->`: the threat id, a status, the references, and
what is still missing. `backend/tests/security/test_threat_coverage.py` parses it and §3 and §4
together and fails on a threat with no row, a row for no threat, a status the evidence does not
support, a residual-risk id §4 does not define, or a reference that no longer resolves.

Three reference shapes are understood and a fourth is an error rather than something to skip:
`path::name` is a pytest node id resolved against the file's syntax tree, `path::"title"` a vitest
or Playwright title matched literally in the source, and `.github/workflows/*.yml::job` a CI job
looked up in the workflow. A reference the checker cannot read is a reference nobody is checking,
so it is refused instead of ignored.

It asserts each reference *resolves*, not that it passed. Running pytest inside pytest would buy a
weaker guarantee than the run this test is already part of; and the failure that actually rots a
matrix is not a test that starts failing — CI catches that on the same push — but a test that
quietly stops existing under the name the document uses. Seven mutations were tried against the
finished matrix (rename a function, reword a Playwright title, rename a CI job, delete a row, add a
threat, relabel a `partial` as verified, invent a risk id) and each one fails the suite.

### Three statuses, and `partial` is not a footnote

`test` — the mitigation as written is verified; the last column is `—` or names a residual risk it
deliberately does not close. `partial` — the named tests hold part of it, and the column says what
is missing, in words, and cannot be empty. `accepted` — no test, and §4 says why.

Writing the thirty-six rows is what this chunk was for, and it is where the value was:

- **Five gaps were already known** and are now in one place instead of five — no upload timeout
  (T-1.4), no exponential backoff on lockout (T-2.1), no query timeout (T-2.6), no read-only root
  filesystem or digest pinning (T-5.1), and a lab whose running check is a command an operator runs
  rather than a test (T-5.5).
- **Three were not.** T-3.4's mitigation claims per-user and per-incident rate limits on brief
  generation and neither exists — one deployment-wide daily number is the whole cap. T-5.6's claims
  an image scan in CI and there is none; both audits read lockfiles. And T-4.4: nothing in a brief
  or a note can *run*, but `SafeMarkdown` renders bidi overrides and zero-width characters as
  themselves, so text can still be made to *read* in an order it is not stored in. The exported
  report writes them out as `<U+202E>` and the renderer does not — the same defect, fixed on one
  side only, and the matrix is what put the two next to each other.

None of the three is a new vulnerability. All three are places the model claimed more than the code
did, which is the failure mode a coverage matrix exists to catch, and it caught them on the first
pass rather than at a release review.

### Where a published number's bytes live

The same chunk closes the other half of the same criterion. `docs/evaluation.md` §6 has asked since
Milestone 2 that every published number carry the command, the corpus sha256, the rule versions and
the generator seed; §8 carried the first two. It now carries all four, plus the commit the corpus
was last changed in — the one question a content hash cannot answer, because it says *these are the
right bytes* and not *here is where to get them*.

`adapters/files/provenance.py` resolves it, and three things about how are deliberate:

- **Not `HEAD`.** The corpus does not change on every commit, so pinning HEAD would make §8 stale on
  the next unrelated push and teach everybody to scroll past it. The last commit to touch the
  labelled cases or the corpus stays put until they do — today that is Chunk 14's, which is when
  ADR-022 last regenerated them, and that is the right answer.
- **Uncommitted bytes are refused.** There is no honest commit for bytes that live nowhere, so
  `make eval` stops and says to commit the corpus first. Regenerating is commit-then-`make eval`, in
  that order.
- **Rendering stays pure.** The commit is a parameter of `render()`, not something it resolves, so
  the same report and the same commit produce the same bytes on a machine with no git. The pin in
  `tests/detectors/test_evaluation.py` reads the sha back out of the document and renders with it —
  which holds every number without needing a history, since CI checks out one commit deep — and a
  second test asks git whether that sha is the right one, skipping with a reason where git cannot
  answer.
- **A shallow clone is refused**, and this is the one the first push got wrong. The reasoning was
  that a truncated history would make `git log -1 -- <paths>` come back empty and the check would
  skip. It does not: the files exist at the graft point, so git names the **boundary commit** as the
  one that introduced them. CI checks out one commit deep, so the check compared the true commit
  against the sha of the commit that had just added the check — a confident wrong answer, which is
  the worst kind, and precisely what a provenance line must never produce. `corpus_commit` now asks
  `git rev-parse --is-shallow-repository` first and refuses, and a test clones a real repository
  with `--depth 1`, asserts that git does give the graft point, and asserts the refusal.

### One process, on a list

This is the first `subprocess` in `src/`, in a project whose T-1.2 mitigation says no shell is
reached by event-derived input. `git log` with a fixed argv is not what that forbids, but the
distinction is easy to lose, so the exception becomes a list rather than a habit:
`test_only_the_provenance_adapter_starts_a_process` walks `src/` and fails on any other module that
imports `subprocess`, `pty` or `multiprocessing`, or calls `os.system`/`os.popen`/`os.exec*`. A
companion test fails if the allowlisted module stops needing it, so a stale entry cannot sit there
excusing the next one. This is the same shape as the lab sensor's single `NET_RAW` capability
(ADR-021): the exception is pinned to one place with its reason beside it.

## Consequences

- Positive: the coverage claim cannot rot silently. A renamed test breaks the document that cites
  it, on the same run, with the row's id in the message.
- Positive: M6's remaining work is now a list somebody can read off the table rather than a review
  somebody has to perform. Eight rows, named, with what is missing written out.
- Positive: §8 satisfies §6's own reproducibility requirement for the first time, and a test says
  so rather than a paragraph.
- Negative: `make eval` now needs a git checkout with history. A tarball or a shallow clone cannot
  run it — which is correct for a command that publishes provenance, and is stated in the error.
- Negative: the matrix is another thing to update when a threat is added, and the suite will insist.
  That is the point, and it is still a cost.
- Neutral: `partial` rows make the document look worse than the old prose did. They were always
  true; three of them were not written down before.
