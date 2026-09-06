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
| `BRIEF_DAILY_BUDGET` | `50` | calls per UTC day across the whole deployment — the counter lives in Redis, so the API, the worker and the CLI spend from one number |
| `BRIEF_USER_DAILY_LIMIT` | `20` | asks per UTC day by one analyst. The budget above is one number for the deployment and therefore not a limit on anybody in particular; this is (T-3.4) |
| `BRIEF_INCIDENT_DAILY_LIMIT` | `10` | asks per UTC day about one case. Spent *before* the per-analyst one, so a loop on a single case cannot cost that analyst every other case they are working |

There is no setting that disables certificate verification, and there will not be.

## Asking for one

```bash
make brief REF=AEG-2026-0001            # from the command line
```
```
POST /api/v1/incidents/{id}/briefs      # analyst; 201 with the brief, or with the failure
GET  /api/v1/incidents/{id}/briefs      # viewer; every version, newest first
GET  /api/v1/incidents/{id}/briefs/{n}  # viewer; one version
```

The routes are in [`docs/api-milestone-5.md`](api-milestone-5.md). Briefs are stored append-only
and versioned: asking again writes v2 rather than replacing v1 (ADR-031).

**With the feature off** — the state of a fresh checkout — the same call answers `201` with the
committed sample in [`samples/briefs/`](../samples/briefs), stored under
`source: offline_fixture`. Nothing leaves the machine, and nothing in the answer pretends a model
wrote it. A *real* failure is never replaced by the sample: `http_503` is recorded as `http_503`.

## When it fails

Every one of these is stored as a brief with `status: failed` and answered `201`, and leaves the
incident completely usable:

`disabled` · `unconfigured` · `budget_exhausted` · `http_401` and friends · a transport error
(recorded by *type*, because an httpx exception carries the request and the request carries the
key) · `malformed_json` · `malformed_brief` when the model answers in prose ·
`response_too_large` · `schema_rejected` · `safety_rejected`.

## Cost and caching

The packet is content-addressed: an unchanged case is answered from cache and costs nothing.
`temperature` is `0.0`, so the same case does not tell a different story on reload.

## Where a brief is read

On the case page in the dashboard, in a panel that shows the summary, the claims, the
recommendations, the sources and the limitations — with every uncited external claim tagged
`UNVERIFIED` and the offline sample labelled as not-a-model. A viewer reads it; only an analyst
is offered the control that asks for one. Model prose goes through the same `SafeMarkdown`
renderer an analyst's note does (ADR-027), and the sources are the one place this app renders a
link: `https` only, `rel="noopener noreferrer nofollow"`, opened in a new tab (ADR-032).

It is also in the exported case document, `GET /api/v1/incidents/{id}/report.md`, marked the
same way.

## What is not built yet

Milestone 5 is complete. **No call has been made from this repository to date** — every test
runs against committed fixtures through a mock transport, and the offline path is what a
checkout without a key exercises. Turning it on takes `BRIEF_ENABLED=true` and a key, and
nothing else in the project changes when you do.
