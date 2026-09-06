# The investigation brief

AegisNet can ask Perplexity to write a narrative about one correlated incident. It is the only
feature that sends anything outside the deployment, and it is **off unless you turn it on**.

The two decisions behind it are
[ADR-029](adr/ADR-029-nothing-leaves-that-was-not-named.md) — what may leave — and
[ADR-030](adr/ADR-030-the-model-is-a-witness-not-an-authority.md) — what may come back.

## What is sent

One JSON evidence packet, built field by field by `domain/redaction`. It is an allow-list:
a field is in it because somebody named it, and anything unclassified is dropped **and
recorded**. In practice what goes out is arithmetic.

```json
{"case_number":"AEG-2026-0001","severity":5,"status":"new","distinct_rule_count":4,
 "subject":"asset-A","subject_class":"private",
 "alerts":[{"rule_id":"D-001","severity":4,"confidence":1.0,"event_count":40,
            "entity":"asset-A","evidence":{"distinct_dest_ports":40,"flows":40,
            "unanswered_flows":40,"threshold_ports":20,"sample_dest_hosts":["int-1"]}}],
 "timeline":["D-001 fired on src_ip asset-A"],"packet_truncated":false}
```

What is **never** sent: raw log lines, packet payloads, real IP addresses or hostnames, asset
names, analyst notes, usernames, or any evidence key nobody has classified. Addresses and names
become stable per-case tokens — `asset-A`, `int-1`, `ext-1`, `domain-1` — carrying which side of
the perimeter they are on and no topology. The mapping stays local.

Because the packet is numbers and tokens rather than prose, an attacker who plants
`ignore previous instructions` in a DNS name achieves nothing: the text never reaches the model.

## What is accepted back

A brief must arrive in the `InvestigationBrief` schema, and is admitted in two steps.

| Step | Refuses | Recorded as |
|---|---|---|
| Shape (`model_validate`) | unknown fields, over-long text, a non-https citation, a citation id pointing at nothing, an action outside the vocabulary | `schema_rejected` |
| Policy (`enforce_safety`) | any passage recommending hacking back, scanning a source, automatic blocking, deleting logs, a takedown, or brute forcing | `safety_rejected` |

Recommendations are an **enum**, not prose: `investigate_host`, `review_with_asset_owner`,
`check_baseline`, `collect_more_evidence`, `correlate_with_other_cases`, `monitor`,
`document_and_close`, `escalate`, `no_action_needed`. All of them are things a person does.

An **external claim with no citation is kept and marked `UNVERIFIED`**, not deleted — a reader
deciding what to trust is better served by seeing it than by a silent removal.

**A brief can never change the case.** There is no field in the schema for a severity, a
status or a verdict, and a test asserts the exact field set.

## Turning it on

```bash
# .env — both are required; either alone does nothing.
BRIEF_ENABLED=true
PERPLEXITY_API_KEY=pplx-...
```

| Setting | Default | What it bounds |
|---|---|---|
| `BRIEF_ENABLED` | `false` | the whole feature |
| `PERPLEXITY_API_KEY` | unset | a `SecretStr`; never logged, never returned by any endpoint |
| `PERPLEXITY_BASE_URL` | `https://api.perplexity.ai` | an allow-list of one host, https only |
| `PERPLEXITY_MODEL` | `sonar` | |
| `PERPLEXITY_TIMEOUT_SECONDS` | `30` | one call |
| `PERPLEXITY_MAX_RETRIES` | `2` | retried only on 429 and 5xx, with jittered backoff |
| `PERPLEXITY_MAX_TOKENS` | `1200` | the answer's size, and its cost |
| `PERPLEXITY_MAX_RESPONSE_BYTES` | `262144` | checked before anything parses it |
| `BRIEF_DAILY_BUDGET` | `50` | calls per UTC day, a hard stop |

There is no setting that disables certificate verification, and there will not be.

## When it fails

Every one of these produces a failed brief and leaves the incident completely usable:

`disabled` · `unconfigured` · `budget_exhausted` · `http_401` and friends · a transport error
(recorded by *type*, because an httpx exception carries the request and the request carries the
key) · `malformed_json` · `malformed_brief` when the model answers in prose ·
`response_too_large` · `schema_rejected` · `safety_rejected`.

## Cost and caching

The packet is content-addressed: an unchanged case is answered from cache and costs nothing.
`temperature` is `0.0`, so the same case does not tell a different story on reload.

## What is not built yet

Chunk 22 ships the client and the schema. Storing briefs (`investigation_briefs`,
`brief_citations`), the `POST /api/v1/incidents/{id}/brief` route, `make brief`, the
deterministic Markdown export and the dashboard panel arrive in Chunks 23 and 24. **No call has
been made from this repository to date** — every test runs against committed fixtures through a
mock transport.
