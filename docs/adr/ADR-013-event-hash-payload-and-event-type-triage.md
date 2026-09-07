# ADR-013 — Event hash subset, payload retention, and event-type triage

- Status: accepted
- Date: 2026-09-05
- Milestone: 1, Chunk 3

## Context

ADR-005 fixes *that* ingest is idempotent through a `sha256` over "a canonical subset of
EVE fields", ADR-001 fixes *that* events keep a validated JSONB payload next to promoted
columns, and `docs/data-model.md` lists eight `event_type` labels plus `other`. None of
them says exactly which fields are hashed, what "remainder" means for the payload, or what
happens to a Suricata record whose `event_type` is not in the list. Those choices decide
whether re-ingest is idempotent across versions and whether drill-down can ever need a
join, so they are recorded here.

## Decision

1. **Hash material** (`domain/eve/hashing.py`). The digest is `sha256` over a version
   prefix (`aegisnet-event-hash-v1\n`) and the canonical JSON (sorted keys, no whitespace,
   ASCII) of:
   - `timestamp` in UTC with microseconds and `event_type`, always;
   - `flow_id`, `in_iface`, `src_ip`, `src_port`, `dest_ip`, `dest_port`, `proto`,
     `app_proto`, `tx_id`, `pcap_cnt`, `community_id`, each only when present, taken from
     the *validated* record so equivalent spellings (`+0000` vs `+00:00`, expanded IPv6)
     hash identically;
   - the complete sanitised sub-object for every known type key present (`alert`, `dns`,
     `http`, `flow`, `tls`, `fileinfo`, `anomaly`, `ssh`).

   Keys outside that set do not affect the digest. A change to the subset or to the
   sanitiser bumps the version prefix, so old and new digests never collide or silently
   duplicate; a re-ingest after such a change is a documented re-import, not a surprise.

2. **Payload is the whole sanitised record**, not the record minus promoted fields. The
   promoted columns are bounded copies for indexing; the payload is the single source for
   drill-down and for the AI packet builder's allow-list serialiser, so neither ever needs
   to reassemble a record from two places. Its size is bounded by the line cap (64 KB)
   and by the per-string cap (4096 characters), and every string in it has had C0/C1
   control characters removed.

3. **Event-type triage.** `stats` and `engine` records describe the sensor, not the
   network, and are rejected with `unsupported_event_type`. Every other `event_type` that
   validates is stored: the nine documented labels map to themselves, anything else maps
   to `other` and keeps its original label inside the payload. Rejecting unknown network
   protocols would discard evidence; mapping them keeps the enum small and the data whole.

4. **Timestamps.** A record must carry a UTC offset; a naive timestamp is refused rather
   than guessed (T-1.7). The sanity window is a parameter of the normaliser with generous
   defaults (10 years past, 24 hours future), because lab and public corpora are often
   years old while a future timestamp is almost always a fault or a forgery.

5. **Rejects carry no input.** `Reject.detail` is built from error kinds and field paths;
   `raw_excerpt` is the sanitised first 256 characters of the line and exists for
   debugging only (`ingest_rejects.raw_excerpt` in the data model).

## Consequences

- Positive: idempotency is testable and versioned; `tests/unit/eve/test_hashing.py` pins
  the exact digest construction.
- Positive: the normaliser is pure and clock-free (`now` is a parameter), so every reject
  path and the window logic are unit-tested without I/O.
- Negative: hashing the whole type object means two records that differ only in a
  volatile sub-field (a `flow` byte counter on an alert) are distinct events. That is
  correct for Suricata output, where each line is one observation.
- Negative: storing the full record duplicates the promoted values. Accepted (ADR-001).
