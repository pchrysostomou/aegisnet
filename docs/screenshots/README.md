# Screenshots

Generated, not taken: `cd frontend && pnpm e2e:shots` writes these from the committed
multi-stage scenario (ADR-025) against a running stack, so what they show is data a reviewer
can reproduce rather than a moment from somebody's laptop.

| File | What it shows |
|---|---|
| `incident-queue.png` | The queue: the three cases correlation opened from the scenario, with severity as a number and a word, and the filters |
| `incident-case.png` | `AEG-2026-0001` — four alerts from four rules, the timeline, the status control offering the workflow's legal moves, and the notes |
| `assets.png` | The asset inventory the detectors attribute traffic to |

Everything in them is synthetic: RFC 1918 and RFC 5737 addresses, `.test` hostnames, and
accounts created for the run.
