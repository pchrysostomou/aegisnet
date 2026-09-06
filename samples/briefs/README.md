# The offline brief

`offline-brief.json` is a committed, hand-written `InvestigationBrief` about the multi-stage
scenario in [`samples/scenarios/`](../scenarios). It exists so a reviewer with no Perplexity key
still sees what the feature does, end to end, without anything leaving the deployment.

It is served only when the feature is unconfigured or turned off, and a brief made from it is
stored with `source = offline_fixture` — never `perplexity`. Nothing may present it as
something a model said.

It passes the same admission the real thing does: the schema, the https citation rule and the
safety filter all apply to it, and a test asserts that.
