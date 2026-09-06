"""SQL implementation of the brief ports (revision 0005; ADR-031).

Append-only, and the grant says so: the runtime role holds SELECT and INSERT on both tables
and nothing else, so there is no code path here that could edit a stored brief even by mistake.

Versions are allocated inside the same transaction that writes the row, from the case's own
maximum. The UNIQUE on ``(incident_id, version)`` is what makes that safe: two requests racing
for "the next one" cannot both get it, and the loser fails rather than overwriting.
"""

from __future__ import annotations

import builtins
from collections.abc import Sequence
from datetime import datetime
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from aegisnet.adapters.db.models import BriefCitation, InvestigationBriefRow
from aegisnet.domain.ports import BriefRecord, CitationRecord, NewBrief


def _citation(row: BriefCitation) -> CitationRecord:
    return CitationRecord(citation_id=row.citation_id, url=row.url, title=row.title)


def _brief(row: InvestigationBriefRow, citations: Sequence[BriefCitation]) -> BriefRecord:
    return BriefRecord(
        id=row.id,
        incident_id=row.incident_id,
        version=row.version,
        status=row.status,
        source=row.source,
        packet_hash=row.packet_hash,
        packet_truncated=row.packet_truncated,
        model=row.model,
        summary=row.summary,
        limitations=row.limitations,
        claims=list(row.claims),
        recommendations=list(row.recommendations),
        has_unverified=row.has_unverified,
        failure_reason=row.failure_reason,
        prompt_tokens=row.prompt_tokens,
        completion_tokens=row.completion_tokens,
        requested_by=row.requested_by,
        created_at=row.created_at,
        citations=tuple(_citation(c) for c in citations),
    )


class SqlBriefStore:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._sessions = session_factory

    async def create(self, brief: NewBrief, now: datetime) -> BriefRecord:
        async with self._sessions() as session, session.begin():
            highest = (
                await session.execute(
                    select(func.max(InvestigationBriefRow.version)).where(
                        InvestigationBriefRow.incident_id == brief.incident_id
                    )
                )
            ).scalar()
            row = InvestigationBriefRow(
                incident_id=brief.incident_id,
                version=(highest or 0) + 1,
                status=brief.status,
                source=brief.source,
                packet_hash=brief.packet_hash,
                packet_truncated=brief.packet_truncated,
                model=brief.model,
                summary=brief.summary,
                limitations=brief.limitations,
                claims=list(brief.claims),
                recommendations=list(brief.recommendations),
                has_unverified=brief.has_unverified,
                failure_reason=brief.failure_reason,
                prompt_tokens=brief.prompt_tokens,
                completion_tokens=brief.completion_tokens,
                requested_by=brief.requested_by,
                created_at=now,
            )
            session.add(row)
            await session.flush()
            for citation in brief.citations:
                session.add(
                    BriefCitation(
                        brief_id=row.id,
                        citation_id=citation.citation_id,
                        url=citation.url,
                        title=citation.title,
                        created_at=now,
                    )
                )
            await session.flush()
            stored = await self._citations(session, row.id)
            await session.refresh(row)
            return _brief(row, stored)

    async def list(self, incident_id: UUID) -> tuple[BriefRecord, ...]:
        async with self._sessions() as session:
            rows = builtins.list(
                (
                    await session.execute(
                        select(InvestigationBriefRow)
                        .where(InvestigationBriefRow.incident_id == incident_id)
                        .order_by(InvestigationBriefRow.version.desc())
                    )
                )
                .scalars()
                .all()
            )
            return tuple([_brief(row, await self._citations(session, row.id)) for row in rows])

    async def get(self, incident_id: UUID, version: int) -> BriefRecord | None:
        async with self._sessions() as session:
            row = (
                await session.execute(
                    select(InvestigationBriefRow).where(
                        InvestigationBriefRow.incident_id == incident_id,
                        InvestigationBriefRow.version == version,
                    )
                )
            ).scalar_one_or_none()
            if row is None:
                return None
            return _brief(row, await self._citations(session, row.id))

    async def latest(self, incident_id: UUID) -> BriefRecord | None:
        async with self._sessions() as session:
            row = (
                await session.execute(
                    select(InvestigationBriefRow)
                    .where(InvestigationBriefRow.incident_id == incident_id)
                    .order_by(InvestigationBriefRow.version.desc())
                    .limit(1)
                )
            ).scalar_one_or_none()
            if row is None:
                return None
            return _brief(row, await self._citations(session, row.id))

    async def _citations(self, session: AsyncSession, brief_id: UUID) -> Sequence[BriefCitation]:
        return builtins.list(
            (
                await session.execute(
                    select(BriefCitation)
                    .where(BriefCitation.brief_id == brief_id)
                    .order_by(BriefCitation.citation_id)
                )
            )
            .scalars()
            .all()
        )


__all__ = ["SqlBriefStore"]
