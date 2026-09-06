# ADR-028 — A browser suite for what the other tests cannot see

- Status: accepted
- Date: 2026-09-06
- Milestone: 4 (Chunk 20); closes the M4 acceptance criteria

## Context

By the end of Chunk 19 the dashboard had 84 unit tests, strict TypeScript, a type-aware linter
and a passing production build. Every one of those is a statement about code in isolation. The
Milestone 4 criteria are not: they are statements about what a **browser** does with data the
**pipeline** produced — that a stored payload renders as inert text, that a role is drawn no
control it may not use, that a case can be reached and worked from the keyboard.

Chunk 20 then produced the argument for itself. `src/app/incidents/[id]/actions.ts` exported a
constant alongside its two server actions. Next allows only async function exports from a
`"use server"` module, and it enforces that **when the action runs** — not at build time. So
`tsc` passed, ESLint passed, 84 unit tests passed, `next build` passed, and the note form was
broken in production. The first browser test to submit a note found it in seconds.

## Decision

### Playwright, against a running stack, with nothing mocked

`frontend/e2e/` runs a real Chromium against `make up`: the real API, the real database, the
real correlation output. Fourteen tests covering the three criteria the other tiers cannot
reach, plus the queue and the inventory rendering at all.

Nothing is mocked, deliberately. A browser test against a mocked API tests the mock, and the
defect above lived precisely in the seam between the framework and the running process — the
place a mock removes.

### The XSS test asserts what is *there*, not what is absent

The payload must be **visible** on the page, as text, and must not have become an element or
executed anything. Three assertions: no dialog opened, `window.__pwned` was never set, and the
notes list contains no `script`, `img`, `svg`, `a` or `iframe` — while still containing the
characters `<script>` and `onerror=` for a reader to see.

Asserting only "the string is absent" would pass for a renderer that silently dropped the
note, which is a different bug and a worse one: an analyst's evidence deleted without a word.

### One sign-in per role, kept in `storageState`

Not an optimisation. The API allows five logins per account per fifteen minutes and fails
*closed* on that path (ADR-016), so a suite that signed in per test would spend its run
measuring the rate limiter — which is exactly what the first draft did. One file per role, so a
run signs in only as the role it is about.

The saved state holds a live session cookie, so `frontend/playwright/.auth/`,
`playwright-report/` and `test-results/` are gitignored, and `make verify-ignore` covers them.
Credentials come from the environment with no default: a misconfigured run fails with a
sentence rather than silently testing an anonymous session.

### Contrast is computed from the stylesheet, not asserted in prose

`src/app/contrast.test.ts` parses the palette out of `globals.css` and computes WCAG relative
luminance for both themes. Severity colours must clear 3.0 against the surface they are drawn
on, body and muted text and links 4.5. Numbers in a document go stale the first time somebody
adjusts a hex value; a test does not.

Colour is never the only carrier in any case — every severity badge prints its number and its
word — but a label nobody can read is not a label.

### Screenshots are generated, not taken

`pnpm e2e:shots` writes `docs/screenshots/` from the committed multi-stage scenario, so the
images in the repository show data a reviewer can regenerate rather than a moment from
somebody's laptop. It is a separate command from the smoke suite because it writes into the
repository, and that should be a decision rather than a side effect.

### The CI job runs after `stack`, not beside it

`e2e` depends on `stack`: there is no point starting a browser if the stack cannot come up, and
the failure is clearer when the simpler job reports first. It loads the multi-stage scenario so
there are real cases to open, mints its two accounts with masked random passwords, and keeps
`test-results/` and the stack logs as artefacts on failure.

## Consequences

- Positive: the three M4 criteria that are statements about a browser are now tested in one,
  and Milestone 4's acceptance criteria are all met with named evidence.
- Positive: the seam between Next's runtime and this code is covered. That is where Chunk 20's
  own defect lived, and it is the seam no other tier watches.
- Positive: the contrast floor is enforced rather than described, so a palette change that
  breaks it fails the suite.
- Negative: CI gained a job that downloads a browser and starts the whole stack — the slowest
  in the workflow. It runs on every push, which is the price of the criteria being real.
- Negative: the browser suite needs credentials in the environment and a stack that is up, so
  it is not part of `pnpm test` and a developer has to choose to run it. Making it implicit
  would make `pnpm test` fail for anybody without Docker running.
- Neutral: three screenshots are committed and will age with the UI. They are regenerated by
  one command, and the test that produces them fails if the pages they show stop rendering.
