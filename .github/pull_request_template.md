## What and why

<!-- One paragraph: the change and the problem it solves. Link the issue if there is one. -->

## Evidence

<!-- The tests that cover it, and the docs/STATUS.md evidence row(s) if this is chunk work. -->

## Checklist

- [ ] `make check` and, where storage is touched, `make test-db` pass locally
- [ ] Tests cover the behaviour; security-relevant changes update `THREAT_MODEL.md`
- [ ] `docs/STATUS.md` and `CHANGELOG.md` reflect the change
- [ ] No real telemetry, no secret-shaped literal, nothing offensive
