# AegisNet — Planning Package Index (M0)

Defensive network threat detection lab. **Planning phase output only — no application code exists yet.**
Last updated: 2026-08-28

## Read in this order

| # | Document | What it answers |
|---|---|---|
| 1 | [docs/PRD.md](docs/PRD.md) | What we are building, for whom, what is explicitly out of scope, and the v1.0 Definition of Done |
| 2 | [ARCHITECTURE.md](ARCHITECTURE.md) | Components, layering rules, the Mermaid data-flow diagram, the Dramatiq decision, ADRs, failure modes |
| 3 | [THREAT_MODEL.md](THREAT_MODEL.md) | Assets, six trust boundaries, STRIDE threats with verification tests, eight accepted residual risks |
| 4 | [docs/repo-structure.md](docs/repo-structure.md) | Monorepo layout and the conventions that keep detectors pure and testable |
| 5 | [docs/data-model.md](docs/data-model.md) | PostgreSQL schema, ER diagram, indexes, retention |
| 6 | [docs/api-milestone-1.md](docs/api-milestone-1.md) | Exact M1 endpoints, limits, error shape, acceptance criteria |
| 7 | [docs/delivery-plan.md](docs/delivery-plan.md) | Six milestones, each with deliverables, risks, acceptance criteria, commands |
| 8 | [docs/evaluation.md](docs/evaluation.md) | Safe local evaluation plan, three-tier corpus, metrics, hard AI safety gates |
| 9 | [docs/STATUS.md](docs/STATUS.md) | Current state, honest and evidence-based |
| 10 | [docs/milestone-1-implementation-prompt.md](docs/milestone-1-implementation-prompt.md) | The prompt that starts implementation |

## Safety charter

AegisNet is **defensive only**. It does not scan, probe, enumerate, exploit, or attack anything. It performs no
automated blocking, containment, firewall changes, or account changes — ever. All demonstrations use isolated
Docker lab traffic the operator owns, or synthetic/public offline datasets. AI output is advisory narrative for
human review and can never change detection state.
