# Contributing

AegisNet is developed in the open as a portfolio and learning project. Issues and pull
requests are welcome; the rules below keep the repository honest about what works.

## Ground rules

- **Defensive only.** Nothing that scans, probes, exploits or takes automated action
  against any system will be merged, whatever the framing.
- **No real telemetry in the tree.** Captures and sensor output are ignored by git;
  fixtures use RFC 1918 / RFC 5737 addresses and `example.test` names only.
- **Claims need evidence.** A change that says something works points at the test or the
  `docs/STATUS.md` evidence row that shows it. `STATUS.md`, `CHANGELOG.md` and
  `THREAT_MODEL.md` are updated in the same change as the code, not afterwards.

## Workflow

1. Fork and branch from `main`.
2. Run the checks locally before opening a pull request:

   ```bash
   make backend-install
   make check          # ruff, import contracts, format, mypy, the hermetic suite
   make test-db        # the database suite (needs Docker and a bootstrapped .env)
   ```

3. Keep the change scoped. Behavioural changes come with tests; security-relevant changes
   also update `THREAT_MODEL.md` (which test verifies the mitigation) and, when the
   credential or permission model moves, `SECURITY.md`. A change to a detection rule or a
   labelled case comes with `make gen-fixtures` and `make eval`: one test pins the fixtures
   to their generator, another pins `docs/evaluation.md` §8 to the harness.
4. Architectural decisions get an ADR under `docs/adr/`, numbered after the last one.
5. Open the pull request with the template filled in. CI must be green: the `ci` workflow
   (lint, types, tests, migrations against PostgreSQL, the full Compose stack) and the
   `security` workflow (dependency audits, secret scan).

## Style

- Python 3.12, Ruff formatting, strict mypy on `domain/`. Docstrings explain *why*.
- `domain/` stays pure: no I/O, no ORM, no clock; services take their stores through the
  Protocols in `domain/ports.py`.
- Every operator task is a `make` target added by the commit that makes it work.
- No secret-shaped string literals anywhere, tests included; derive test keys from
  expressions. The `security` workflow's gitleaks step rejects them.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting on this repository, as described in
[`SECURITY.md`](SECURITY.md). Please do not open a public issue for anything exploitable.
