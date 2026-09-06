# Release checklist

What is checked before a tag, and — where it matters — *why that check and not a more obvious one*.
A generic checklist would say "tests pass". This one says what has actually gone wrong in this
repository, because those are the checks worth running twice.

Ticked below for **v1.0.0 (2026-09-06)**, Chunk 31. Every box was checked against the repository at
the commit being tagged, not from memory.

---

## 1. The suites

- [x] `make check` — ruff, `ruff format --check`, mypy (strict on `domain/`), `lint-imports`, and
      the hermetic suite. **1334 passed, 100 skipped.**
- [x] `make test-db` — **95 passed** against a real PostgreSQL 16. The grant matrix, the migration
      round trip and the statement timeouts only mean anything here.
- [x] Frontend: `tsc --noEmit`, `eslint .`, `vitest run` (**158 passed**), `next build`.
- [x] Coverage: **98% on `domain/`** (gate ≥85), **94% overall** (gate ≥70).
- [x] CI green on the tagged commit — all thirteen checks (E-95), including `lab`, `trivy`,
      `e2e`, `update-uv-graph` (which fired because the version bump changed `uv.lock`) and
      SonarCloud's quality gate.
- [ ] `make load-test` — **not run for this release, and that is a decision.** It spends real
      fifteen-minute login budgets against a deployment, so it belongs to an operator with a stack
      they own. Its numbers are recorded in `docs/evaluation.md` §10 from Chunk 26.

## 2. The claims

The largest class of defect this project has produced is not a broken test. It is a document that
was true when written and quietly stopped being true. Before v1.0.0 an audit of every factual claim
found **19 blocking** stale statements — including a README headline three milestones out of date
and a `SECURITY.md` "not there yet" list naming two things that had shipped.

- [x] `THREAT_MODEL.md` §6 parses and every reference resolves — `test_threat_coverage.py`, which
      fails on a renamed test, a deleted row, or a residual-risk id §4 does not define.
- [x] §6 holds only `test` and `accepted`. **Thirty-six `test`, no `partial`.**
- [x] Every "not yet", "deferred", "planned", "M6" and "arrives in" in `README.md`, `SECURITY.md`,
      `ARCHITECTURE.md` and `THREAT_MODEL.md` re-read against the code. Grep for those words; do
      not trust that the last chunk updated them, because the last chunk updated only what it
      touched.
- [x] The package's own docstring and `__version__` describe the project as it is.
- [x] `docs/STATUS.md`'s milestone tracker, phase row and open-risks table agree with its own
      chunk tracker. They disagreed before this audit.
- [x] Test counts in `README.md` and `docs/STATUS.md` match what pytest actually reports.

## 3. Reproduction

- [x] A fresh clone, following **only** the README — `docs/fresh-clone-transcript.txt`.
      It failed once, and the transcript keeps the failure: a `db_data` volume from an earlier
      checkout carried the roles of an older `.env`, so `make migrate` died with `password
      authentication failed`. `make up` now warns about exactly that. **Do not re-run a
      reproduction until it looks clean and then commit the clean one** — the failure is the
      finding.
- [x] `make demo-scenario` produces the documented result: `AEG-2026-0001`, four rules on one host,
      severity 5 escalated, and a bystander case that is *not* folded into it. 12 seconds.
- [x] `make export REF=…` twice gives byte-identical output.
- [x] `docs/demo-script.md` walks in under three minutes, with timings measured on the fresh clone.

## 4. Supply chain

- [x] `gitleaks` clean on history and diff.
- [x] `pip-audit --strict` and `pnpm audit --prod` clean.
- [x] The image scan gates on the images this project builds and reports on the two it pulls
      (R-10). It found a CRITICAL in npm's bundled `tar` on its first working run — a package no
      lockfile audit can see, because it is not in any lockfile here.
- [x] **No action pinned to a deprecated runtime.** `grep -hoE "uses: [^ ]+" .github/workflows/*.yml
      | sort -u` and check each. This has bitten twice: Node 20 removal caught
      `actions/upload-artifact@v4` ten days before it would have broken, and only because an
      unrelated failure prompted the audit.
- [x] Every action pinned to an exact release, not a moving major.

## 5. The tag

- [x] Version bumped in all three places that carry it: `backend/src/aegisnet/__init__.py`,
      `backend/pyproject.toml`, `frontend/package.json`. No test pins the literal — the meta test
      reads `APP_VERSION` — so a partial bump would not have failed anything. Check all three.
- [x] `CHANGELOG.md`'s `[Unreleased]` converted to a dated release heading.
- [x] The two standing disclaimers survive the release and are still true: **detector accuracy on
      real traffic is unmeasured**, and **no outbound API call has ever been made from this
      repository**.
- [x] `git tag -a v1.0.0` on a commit whose CI is green, annotated with what the release is and
      what it does not claim.

---

## What this checklist would not have caught

Worth writing down, because a checklist that reads as exhaustive is its own hazard.

- **Accuracy.** Nothing here tests whether the detectors are any good on real traffic. §8 measures
  them against data this repository generated; §9 is one lab run. A green release says the rules do
  what their specifications say, not that the specifications are right.
- **The datastore images.** `postgres:16-alpine` and `redis:7-alpine` are scanned and *reported*,
  not gated. A HIGH finding there will print and will not stop a release (R-10).
- **A tampered upstream tag.** Base images follow minor tags, so an image that changes to something
  malicious but free of known CVEs passes every check here. That is what digest pinning would have
  covered, and R-10 records why it was not applied.
- **Anything a single maintainer cannot see about their own work.** The claims audit above was run
  by an adversarial reviewer against the files, and it found nineteen blocking defects that the
  person who wrote them had read past a dozen times.
