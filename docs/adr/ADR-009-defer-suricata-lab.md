# ADR-009 — Defer the isolated Suricata lab to Milestone 2

- Status: accepted; the deferral ended with [ADR-021](ADR-021-isolated-suricata-lab.md)
  (Milestone 2, Chunk 13), which built the lab this record describes and reported what it
  found — including the two divergences from real Suricata output that the "Consequences"
  section below said would be Milestone 2 findings
- Date: 2026-08-28
- Milestone: 1 (decision D-9)

## Context

The original Milestone 1 plan included `infra/lab/`: an isolated Docker network running
Suricata against generated traffic. Milestone 1 is meant to establish the application
foundation and a trustworthy ingestion path. Introducing a live-traffic component at the
same time mixes two risks: ordinary "does the stack build" risk, and the much sharper risk
of running packet-generating tooling on a contributor's machine.

## Decision

`infra/lab/` moves to Milestone 2. Milestone 1 contains **no** live-traffic component, no
packet-generation tooling, no scanning tooling, and no Suricata container.

Milestone 1's demo corpus is instead a committed, registered synthetic Suricata EVE JSON
dataset (decision D-5), which arrives in Chunk 3.

## Consequences

- Positive: the ingestion path can be tested deterministically and reproducibly. Nobody
  needs to generate traffic to run `make demo-ingest`. CI needs no privileged networking.
- Positive: the safety boundary is easier to review. In Milestone 1 the project reads files;
  it does not touch a network interface.
- Negative: Milestone 1 does not demonstrate a real end-to-end Suricata capture. The
  synthetic corpus must therefore be schema-faithful, and any divergence from real Suricata
  output is a Milestone 2 finding rather than a Milestone 1 one.
- Negative: EVE fields that only appear under real load (for example, partially populated
  `flow` records) may not be exercised until Milestone 2.

## Safety note

When the lab does arrive it must remain on an internal Docker network with no route to the
host LAN or the internet, and it must only generate traffic between containers the project
itself owns. Nothing in this project ever scans, probes, or targets a system it does not
create.
