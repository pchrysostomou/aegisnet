# ADR-020 — The periodiq schedule, the post-ingest sweep and the evaluation harness

- Status: accepted
- Date: 2026-09-05
- Milestone: 2 (Chunk 12); revisits ADR-010 (decision D-10, flag F-11)

## Context

Until this chunk every sweep was asked for: an admin's `POST /detections/sweeps`, `make
run-detectors`, or the CI job. ADR-010 deferred the scheduler until "the first genuinely
periodic workload" existed. Two now do: the detection sweep over the most recent interval
and the nightly baseline recompute (ADR-019), and a third trigger is implied by ingest
itself, since a batch that just stored events is the moment those events should be judged.

At the same time `docs/evaluation.md` §8 still said "empty by design". The labelled cases
(ADR-017) and the benign synthetic corpus (ADR-013) are exact ground truth, so the first
per-detector table can be produced from them without touching a network.

## Decision

### The scheduler is a sixth Compose service running periodiq

`scheduler` runs `periodiq aegisnet.workers.main`: the same image and the same entrypoint
module as the worker, so the actors it schedules are the ones the worker declares. It talks
to Redis only, mounts nothing, publishes nothing, and its healthcheck is process liveness
like the worker's. It only *sends*; the worker runs what it sends. If it is down, nothing
periodic happens and nothing else is affected.

Two periodic actors live in `workers/schedule.py`, both on the `detection` queue:

| Actor | Cron (scheduler clock, UTC in the image) | What it does |
|---|---|---|
| `scheduled_sweep` | `*/SWEEP_CADENCE_MINUTES * * * *` (default every 10 minutes) | sweeps `[end − SWEEP_LOOKBACK_MINUTES, end)` where `end` is now floored to the cadence grid (default a 60-minute lookback) |
| `nightly_baselines` | `0 BASELINE_RECOMPUTE_HOUR * * *` (default 02:00) | recomputes `asset_baselines` over `BASELINE_WINDOW_DAYS` (default 7) |

The cadence must divide 60 so ticks sit on a fixed grid; settings refuse anything else.
Consecutive sweeps overlap on purpose. An event that arrives up to `lookback − cadence`
minutes late still meets a sweep, and the alert dedup key (ADR-018) turns the overlap into
a no-op instead of a duplicate. The broker carries `PeriodiqMiddleware` with
`SCHEDULE_SKIP_DELAY_SECONDS` (default 300): a scheduled message that waited longer than
that is skipped, so a worker that was down for an hour does not replay six stale ticks; the
next tick's lookback covers the gap.

### A completed batch queues its own sweep

When a batch completes with stored events, the side that finished it queues
`run_detectors` over the hour-aligned span of the batch's event times, split into
intervals no longer than a single sweep accepts (24 h). The worker does this after
`import_dataset` and `import_upload`; the API does it inline after a `mode=sync` upload and
records `sweeps_queued` in the `ingest.batch_created` audit entry. `POST_INGEST_SWEEP=false`
turns it off. The span comes from the events themselves (`min`/`max` of `event_time` by
batch id), not from wall-clock timestamps, so a replayed historical corpus is swept where its
events sit.

### `make eval` writes the first metrics table and a test pins it

`aegisnet eval-detectors` (no database, no settings, no secrets, and no path arguments: like a
dataset import it resolves fixed names under a root, here the checkout it finds above its
working directory) runs every labelled case
through its own rule (T1) and every rule over the benign corpus on that rule's grid (T2),
then rewrites the block between `<!-- eval:begin -->` and `<!-- eval:end -->` in
`docs/evaluation.md` §8. The verdicts are strict: a positive case is a true positive only when
the rule alerts on exactly the expected entity, at or above the expected severity, and on
nothing else; a negative case is a false positive on any alert. T2 reports alerts per
10 000 events by distinct dedup key, and marks D-005 as abstaining because the corpus carries
no baselines. `tests/detectors/test_evaluation.py` asserts that the committed block equals
what the harness renders now, so a rule change that moves a number cannot be merged without
bringing the document along. The command exits 1 when any case misses its label, after
writing the report, so a regression shows up in the document rather than hiding.

## What the numbers mean

The first table is all ones and all zeros. That is expected and must not be oversold: the
T1 cases were rendered from the same specifications the rules implement, by the same
author, so they measure conformance to the specification on synthetic data, not detection
quality. T2 is 2 000 quiet synthetic events over ninety-five minutes. The lab corpus (T3,
ADR-009) had not been run when this was written; it has since (ADR-021), and
`docs/evaluation.md` §9 reports what it found — including two defects that made the T1
scores for D-003 and D-004 read better than they deserved. Both were fixed (ADR-022), and the
T1 and T2 tables did not move when they were, which says something about both.

## Consequences

- Positive: the stack detects without an operator asking, on a documented cadence with a
  documented catch-up rule, and every ingested batch is judged promptly.
- Positive: the evaluation document is generated, pinned and honest about its provenance.
- Negative: a sixth container. It is the smallest one, and the compose policy tests hold it
  to the same hardening as the rest.
- Negative: periodiq reads cron lines in the process's local timezone; the image runs UTC and
  the settings say so. A host-run scheduler with another timezone would shift the nightly
  job; the container is the supported way to run it.
- Superseded in part: ADR-010's deferral is over; its reasoning about not shipping decorative
  infrastructure stands and is why the scheduler arrived with the first periodic workload and
  not before.
