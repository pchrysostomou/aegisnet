"""The case as a downloadable document (Milestone 5, Chunk 24; ADR-032).

One route. It **writes nothing to the case** and it **is audited** — two different statements,
and the difference is the whole of this module.

*Nothing to the case.* A report that recorded its own export in the timeline would change the
case it claims to render, so the next export would differ from this one. Chunk 23 found
precisely this defect in the evidence packet — a `brief_generated` line entering the next packet
and moving its hash — and `BriefService.BOOKKEEPING` protects the packet, not a document. A
`GET` that appended to the case would also let a viewer, holding only `incidents.read`, mutate
one. `TimelineEntryType.report_exported` therefore stays unwritten, as `brief.requested` and
`brief.egress` in `docs/data-model.md`'s illustrative list stayed unwritten before it.

*And audited anyway.* FR-10.3 names an export an auditable event, and an export is not an
ordinary read: it is the whole case as plain text in a file somebody can forward. The row cannot
move the bytes, because the report renders the case and the audit log is not part of the case.
This is the first read here that writes one, and the objection — that it hands a viewer an
append primitive into a table with no `DELETE` grant — was checked rather than assumed: they
already have one, because `rbac.denied` is written for every refused request. Retention is
Milestone 6's problem, and it is one problem rather than two.

*A viewer may export.* Everything in the document is something the caller can already read
through the JSON API, so gating the format would protect nothing and would only teach an
operator that the export is the sensitive part. One section is the exception and it is handled
rather than hand-waved: the provenance appendix names ingest batches, which is `ingest.read`, so
a viewer's export says the appendix was withheld and why. What is worth saying about the rest —
that the document is the case verbatim and is not redacted — the document says itself, at the
top.
"""

from __future__ import annotations

import re
from typing import Annotated, Final
from uuid import UUID

from fastapi import APIRouter, Depends, Request
from fastapi.responses import PlainTextResponse

from aegisnet.api.deps import (
    AppServices,
    client_ip,
    correlation_id,
    rate_limit,
    require,
    services,
)
from aegisnet.domain.auth import Permission, Principal
from aegisnet.domain.enums import AuditResult

router = APIRouter(prefix="/api/v1/incidents", tags=["incidents"])

MEDIA_TYPE: Final = "text/markdown; charset=utf-8"
CASE_NUMBER: Final = re.compile(r"[A-Z]{3}-\d{4}-\d{4}")
"""The shape `incident_case_seq` produces. The value goes into a response header, which is a
line-oriented format, so it is checked rather than trusted — and the case number is the only
field of the case that could go there at all: a title is written by whoever named the rule."""

FALLBACK_FILENAME: Final = "incident-report.md"


class MarkdownResponse(PlainTextResponse):
    media_type = MEDIA_TYPE


def _filename(case_number: str) -> str:
    # `fullmatch`, not `match`: in Python `$` also matches immediately before a trailing
    # newline, so `AEG-2026-0001\n` would pass a `$`-anchored check and be interpolated into a
    # header. `$` is the one anchor that does not mean end of string.
    return f"{case_number}.md" if CASE_NUMBER.fullmatch(case_number) else FALLBACK_FILENAME


@router.get(
    "/{incident_id}/report.md",
    response_class=MarkdownResponse,
    summary="The whole case as Markdown — the same bytes every time",
    responses={200: {"content": {"text/markdown": {}}, "description": "The case as a document"}},
    dependencies=[Depends(rate_limit("read"))],
)
async def export_report(
    incident_id: UUID,
    request: Request,
    svc: Annotated[AppServices, Depends(services)],
    principal: Annotated[Principal, Depends(require(Permission.incidents_read))],
) -> MarkdownResponse:
    # The appendix names ingest batches, and reading those is `ingest.read` — which a viewer
    # does not hold. Everything else in the document is a re-rendering of what this caller can
    # already fetch as JSON, and the document says plainly when the appendix was withheld.
    case_number, document = await svc.reports.markdown(
        incident_id, provenance=principal.can(Permission.ingest_read)
    )
    await svc.audit.record(
        "report.exported",
        target_type="incident",
        target_id=str(incident_id),
        result=AuditResult.success,
        # What was taken and how much of it, never the document: the report is the case, and
        # the audit log is not a second copy of the case.
        detail={"case_number": case_number, "bytes": len(document.encode("utf-8"))},
        principal=principal,
        actor_ip=client_ip(request),
        correlation_id=correlation_id(),
    )
    return MarkdownResponse(
        document,
        headers={
            # For `curl` and the CLI. The dashboard never reads this: a browser does not talk
            # to this API at all (ADR-026), so the app's own route handler sets its own.
            "Content-Disposition": f'attachment; filename="{_filename(case_number)}"',
            # A case in plain text has no business in a shared cache or a history entry.
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )


__all__ = ["CASE_NUMBER", "MEDIA_TYPE", "MarkdownResponse", "router"]
