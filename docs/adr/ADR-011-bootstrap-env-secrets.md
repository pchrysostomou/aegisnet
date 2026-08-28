# ADR-011 — `make bootstrap` generates development-only secrets

- Status: accepted
- Date: 2026-08-28
- Milestone: 1 (flag F-1)

## Context

The Milestone 1 acceptance gate was originally "a fresh clone starts with
`docker compose up --build -d`". That is impossible to satisfy honestly while also refusing
to commit secrets: Compose needs `POSTGRES_PASSWORD`, `REDIS_PASSWORD`, and `SECRET_KEY`
to exist. The alternatives were to commit weak default credentials (unacceptable) or to
make the first run fail with a manual copy-and-edit step (a poor first impression, and one
that pushes people toward reusing an example password).

## Decision

The gate becomes:

```
make bootstrap && docker compose up --build -d
```

`infra/scripts/bootstrap_env.py`:

- copies `.env.example` to `.env`, replacing every `__REPLACE_ME__` placeholder with
  `secrets.token_urlsafe(48)`;
- is idempotent — if `.env` already exists it prints a notice and exits 0;
- never overwrites an existing `.env` without the explicit `--force` flag;
- creates the file with mode `0600` where the platform supports it, and warns loudly when
  it cannot;
- never prints a generated secret.

`.env` stays gitignored, and a pre-commit hook plus gitleaks both block it.

Separately, `aegisnet.config.Settings` **refuses to load** when any secret still contains
`REPLACE_ME` and `ENV` is not `test`. So a half-configured deployment fails fast at startup
with an actionable message rather than silently running on a template password.

## Consequences

- Positive: a fresh clone reaches a running stack in two commands, with unique random
  local credentials and no committed secret.
- Positive: the placeholder refusal is a genuine security control, tested in
  `tests/unit/test_config.py`, not just documentation.
- Negative: the gate is two commands rather than one. `make up` wraps them for convenience
  but the documented gate stays explicit so nothing is hidden.
- Negative: these credentials are development-only. They are generated on the host, written
  to a plaintext file, and passed to containers via `env_file`. That is appropriate for a
  local lab and **not** appropriate for a real deployment, which needs a secret manager.
  `SECURITY.md` states this.

## Scope limit

This ADR covers local development credentials only. Production secret management is out of
scope for this project as it is a self-hosted lab, and that limitation is recorded rather
than glossed over.
