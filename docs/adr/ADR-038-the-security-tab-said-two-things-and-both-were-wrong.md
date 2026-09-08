# ADR-038 — The Security tab said two things and both were wrong

- Status: accepted
- Date: 2026-09-07
- Milestone: post-`v1.0.0` maintenance. Amends [ADR-037](ADR-037-the-last-three-rows-are-about-the-deployment.md)
  (which half of the Trivy job publishes) and the T-5.4 row of [`THREAT_MODEL.md`](../../THREAT_MODEL.md)
  (what the secret scan actually covers on a push)

## Context

The repository was called closed out on 2026-09-07 with "CI 12/12 green". That was read off the
*workflow* list. The **Security tab** was not read, and it said two things:

1. **74 open HIGH and CRITICAL code-scanning alerts.**
2. **A failing `security` workflow run** — the scheduled one, from 12:39 that morning.

Both had been true for longer than the close-out claim. Neither is visible from the place the
close-out looked, which is the point worth keeping: a green check next to the last push says
nothing about a scheduled run, and nothing at all about alerts.

### 1. The alerts were somebody else's CVEs, filed against this project

Every one of the 74 came from `trivy-postgres`. Forty-six were in `usr/local/bin/gosu` and
twenty-eight in `library/postgres` — the `gosu` findings are Go standard-library CVEs in a
statically linked binary that `postgres:16-alpine` ships. Alert 30, the single CRITICAL, is
`CVE-2025-68121`: `stdlib` at `v1.24.6`, fixed in Go 1.24.13.

Fixed in Go, that is. Not fixed in the image, because the image has not been rebuilt with a newer
Go, and nothing in this repository decides when it will be. `ignore-unfixed: true` does not filter
them for exactly that reason — upstream Go *has* a fix, so Trivy correctly calls them fixable, and
the party who can apply it is not us.

So: 74 alerts that could not be closed, that returned on every push, and that a reader of a public
repository's Security tab sees as 74 vulnerabilities in AegisNet. ADR-037 argued that a gate nobody
can pass is a gate people learn to switch off. This is the same failure in alert form, and it ends
the same way — the tab stops being read, and the day it holds something real nobody notices.

The irony is that ADR-037's correction got the direction right and the target wrong. It reasoned
that a report belongs somewhere durable, which is true, and then published the *pulled* images,
which are the half where a durable record helps nobody here.

### 2. The secret scan had two scopes and only one was ever watched

`gitleaks-action` scans the commits of a **push**. On a `schedule` — or any other event — it scans
the **entire history**.

Seven secret-shaped literals were committed on 2026-09-05 in four commits, noticed, and rewritten
to be built at runtime (`".".join(...)`, `"ghp" + "_" + ...`). That cleared the push scan. It did
nothing whatever for the history scan, because the literals are still in the objects those commits
left behind, and no follow-up commit can remove them.

The result: every push green, every Monday red, starting the moment the note *"the action scans
the push's own commits, so a follow-up commit clears it; no history rewrite needed"* was written
down. That note is true and it is not the whole truth, and the missing half was never checked
because the weekly run is not where anyone looks after a push goes green.

All seven are the same four strings: a test signing key in four files, a JWT canary whose payload
decodes to `{"sub":"canary"}`, a GitHub PAT canary with the word `canary` in the token body, and an
`api_key=` value in a URL fixture that exists to prove `api_key=` is stripped from logged URLs.
None has ever been valid anywhere.

## Decision

### Trivy publishes the images this project builds, and only those

`aegisnet-api` and `aegisnet-web` are scanned twice: once as a `table` that **fails the job**, once
as `sarif` that **files an alert**. `postgres:16-alpine` and `redis:7-alpine` are scanned once, as a
table, printed in full, weekly — exactly what R-10 has always promised and all it ever promised.

The line is *can anybody here close this finding*, and it is now the same line for the gate and for
the report. What was given up is a durable record of somebody else's CVEs. What was bought is a
Security tab in which everything present is actionable, which is the only kind that gets read.

The 74 existing alerts do not close on their own: an alert closes when a later analysis in the same
category reports it fixed, and this category stops being uploaded. The `trivy-postgres` and
`trivy-redis` analyses were therefore deleted through the API. They are reproducible at any time by
re-running the workflow, so nothing was lost that a `docker pull` cannot recreate.

The reporting pass carries `exit-code: "0"`, because the gate already ran on the same image and
failing twice on one finding would skip the upload and lose the report it was meant to produce.
Every step after the first gate carries `if: always()` for the same reason: the run that most needs
a report is the run where the gate failed.

### The secret scan gets a config, and the config allows values rather than places

[`.gitleaks.toml`](../../.gitleaks.toml) extends the default rule set — every detector stays on —
and allows the four strings by anchored regex against the secret itself.

**The one-line version of this fix is a hole.** `paths = ['^backend/tests/']` clears the same seven
findings and also means a real credential pasted into a test file is never reported again, and
`backend/tests/security/` is precisely where somebody debugging a redaction failure would paste one.
`tests/security/test_secret_scan_config.py` asserts that the allowlist carries no `paths`, `files`,
`commits` or `stopwords` key, that every regex is anchored, that `regexTarget` is the secret and not
the line, and that `useDefault` is on — without which the config *replaces* the rule set and a green
scan means nothing.

It was checked by probe rather than by reading: one character changed, the same value with a suffix,
and an unrelated PAT are all still findings; the two allowed values are not. And because an
allowlist is a statement about history that must not quietly become one about the present, a test
walks the tree and fails if any of the four reappears as a literal — it caught one immediately, in
the docstring of the test asserting the values are never quoted.

**Rewriting history was considered and rejected.** Four fake strings do not justify changing every
commit hash in a published repository that other clones and every issue cross-reference point at.

### The report stays wider than the gate, and the first run proved why

Aiming SARIF at the built images produced **11 open alerts immediately**, and the honest first
reaction was that something was misconfigured: the gate had just passed on the same image in the
same job. It had. The job log explains it — `Building SARIF report with all severities`. The
trivy action applies `severity:` to the exit code and **not** to the SARIF file unless
`limit-severities-for-sarif: true` is set.

The obvious fix is to set it. That would have been the wrong fix, and the 11 findings are the
argument:

| package | count | trivy severity | fix available |
|---|---|---|---|
| `pip` 25.0.1 | 6 | MEDIUM, LOW | yes — 25.3, 26.0, 26.1, 26.1.2, 26.2.0 |
| `libpcre2-8-0` 10.42-1 | 5 | UNKNOWN | yes — `10.42-1+deb12u1` |

All eleven are in `aegisnet-api`, an image this project builds. All eleven have a fix. **Not one
would ever have failed the gate**, because none is HIGH or CRITICAL. Trimming the report to match
the gate would have hidden all of them behind a comfortable zero.

So `limit-severities-for-sarif` stays unset, and the two findings were fixed rather than filtered:

- **pip is deleted from the runtime image**, with `ensurepip` alongside it. The application runs
  from `/opt/venv`, built by uv in the `deps` stage and copied in whole; nothing in this container
  installs anything at run time, so pip was 100% attack surface and 0% function. The dashboard
  image has deleted npm, npx and corepack since Chunk 30 on exactly this reasoning and a test has
  held it there — the same argument always applied here and nobody made it, because the gate never
  fired. Verified by running the image: `import pip` and `import ensurepip` both raise, no `pip*`
  survives in `/usr/local/bin`, and uvicorn, alembic, pgrep and `python -m aegisnet.cli --help`
  all still work.
- **The runtime stage takes Debian's security patches** (`apt-get upgrade`). A base pinned by
  minor tag ships what Debian had patched when that base was published and nothing later, however
  long it sits. `libpcre2-8-0` was five advisories behind a package already present in the suite
  the build reads from. hadolint's DL3005 forbids this; the waiver is written into
  `.hadolint.yaml` with the reason, which is that the rule defends build reproducibility and F-5
  traded that away when it pinned a tag instead of a digest. If digest pinning lands (#14), the
  waiver should be reconsidered in the same change.

Rebuilt and rescanned at every severity with `--ignore-unfixed`: **0 findings** in both images,
on `arm64` locally and then on `amd64` in CI, which matters because the two architectures have
produced different finding sets before.

The contract, stated once: **the gate blocks on what is urgent, the report shows everything
fixable, and both are limited to images this project builds.** A finding below the gate does not
stop a push; it files an alert, and a rebuild closes it once the fix reaches the distribution.
That is a treadmill only for somebody who never rebuilds.

### `workflow_dispatch`

Added to `security.yml`, and not for convenience. It is the only way to run the wide scan on demand:
without it a history finding could not be re-checked until the following Monday, which is both why
this went unnoticed for two days and why the fix could not have been verified before being pushed.

## Consequences

- The Security tab will not stay at zero by itself, and it is not meant to. It now reports every
  *fixable* finding in the two images this project builds, most of which will never fail the gate.
  The intended lifecycle is: an advisory lands, the alert appears, the next build picks up the
  distribution's patch, and the next analysis closes the alert. What must not happen is somebody
  reading a non-zero tab as noise and reaching for `limit-severities-for-sarif` — the eleven
  findings that motivated all of this were all below the gate, and
  `test_the_report_is_deliberately_wider_than_the_gate` is there to make that a decision rather
  than an edit.
- A finding in `postgres:16-alpine` no longer produces an alert. It is in the job log and in the
  weekly run, and if the Security tab is the only place somebody looks, they will not see it. That
  is the cost, it is deliberate, and R-10 is where it is written down.
- The four allowed strings can be re-committed as literals without the scanner objecting. The tree
  walk is what stops that, and it is a test rather than a comment for that reason.
- `.gitleaks.toml` is read by both the pre-commit hook and the CI job, so a value allowed in one is
  allowed in both. A new fake credential in a test must be built from expressions, as
  [`CONTRIBUTING.md`](../../CONTRIBUTING.md) already said; it must not be added to the allowlist.
- The close-out checklist gained the two checks it lacked: **read the Security tab**, and **look at
  the last scheduled run**, not only the last push.
