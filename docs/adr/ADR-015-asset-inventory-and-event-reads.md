# ADR-015 — Asset inventory rules and bounded event reads

- Status: accepted
- Date: 2026-09-05
- Milestone: 1, Chunk 5

## Context

`docs/api-milestone-1.md` says overlapping CIDRs *across assets* are rejected with
`409 network_overlap`, while `docs/data-model.md` says resolution picks the most specific
matching CIDR with ties broken by the primary flag and then the oldest asset. Both can be
true only if the tie-break rule is defensive, so the precedence had to be pinned down.
The event read API needs its pagination and window bounds fixed before any route exists,
and the runtime role's grants (ADR-012: no DELETE anywhere) had to accommodate an asset
whose networks are replaced by a `PATCH`.

## Decision

1. **Cross-asset overlaps are refused at write time.** `create`, `update`, `bulk_create`
   and `seed` check the new CIDRs against every network of every *other* active asset
   (`domain.assets.find_overlaps`) and inside the request itself
   (`find_internal_overlaps`); a hit raises `NetworkOverlapError` naming the pair. One
   asset may hold nested networks of its own (a `/24` and a `/32` inside it).
2. **Resolution implements the full precedence anyway**: longest prefix, then
   `is_primary`, then the oldest asset, then the lowest id. It is the SQL store's
   `ORDER BY` and the pure `resolve_ip` in the domain; the database suite inserts
   overlapping rows as the owner to prove the query, because the service will not.
   Deactivated assets never resolve and never block a new asset's networks.
3. **Seeding is an upsert by hostname.** `seed` requires a hostname on every entry,
   creates the new ones atomically and patches the existing ones in place (fields and
   networks). `make seed` runs it on `samples/assets/lab-assets.yml`, which is confined
   to the samples directory exactly like a dataset (T-1.6). Bulk creation is atomic and
   capped at 500 entries.
4. **Revision `0002_asset_network_delete_grant`** grants the runtime role DELETE on
   `asset_networks` only. `audit_log` and `events` stay append-only for that role; the
   grants matrix test names the one exception.
5. **Every list is keyset-paginated and bounded (T-2.6).** Cursors are opaque base64url
   JSON naming the last row seen, validated strictly on the way back; page sizes are 1–200
   (default 50); an event query needs an explicit, timezone-aware window of at most 30
   days; the payload column is read only when a caller asks for it, so a viewer-level
   query never touches it. Rejects of an unknown batch are not enumerable.
6. **The asset filter on events uses the asset's networks**: an event matches when its
   source or destination address is contained in any CIDR of that asset, served by the
   GiST index. Unknown addresses resolve to `{"matched": false}`, never to an error.
7. **HTTP routes still wait for Chunk 6** (ADR-014). The operator CLI gained `seed-assets`,
   `assets`, `asset`, `resolve`, `events`, `event-stats`, `batches` and `rejects`; the
   routes will be thin wrappers over the same services.

## Consequences

- Positive: the inventory cannot become ambiguous, and the resolver is still correct on
  data that predates the check or arrives through a future bulk path.
- Positive: pagination and window bounds are tested once at the service layer
  (`tests/security/test_pagination_bounds.py`) rather than per route.
- Negative: the overlap check reads every active network before a write. At lab scale
  that is a few hundred rows; a large inventory would want the GiST overlap query inside
  the transaction instead.
- Negative: the hermetic coverage gate now excludes the SQL stores and the worker, which
  the database suite and the stack exercise instead; `docs/STATUS.md` records both numbers.
