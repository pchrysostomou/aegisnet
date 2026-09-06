"""The two brief tables against PostgreSQL 16 (revision 0005; ADR-031).

What is worth testing here is what the database enforces rather than what Python remembers: the
UNIQUE that makes version allocation safe under a race, the two check constraints that keep a
brief's status honest about whether it has anything to say, the https rule on a citation, and —
the point of the whole design — that the runtime role cannot edit or delete a stored brief.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, IntegrityError, ProgrammingError
from sqlalchemy.ext.asyncio import AsyncEngine

from aegisnet.adapters.db.brief_store import SqlBriefStore
from aegisnet.adapters.db.incident_store import SqlIncidentStore
from aegisnet.adapters.db.session import make_session_factory
from aegisnet.domain.enums import BriefSource, BriefStatus
from aegisnet.domain.ports import CitationRecord, NewBrief, NewIncident

pytestmark = [pytest.mark.db, pytest.mark.integration]

NOW = datetime(2026, 9, 6, 12, 0, tzinfo=UTC)
KEY = "src_ip=10.10.0.42"


@pytest.fixture(autouse=True)
async def clean_tables(migrator_engine: AsyncEngine) -> AsyncIterator[None]:
    async with migrator_engine.begin() as connection:
        for table in ("brief_citations", "investigation_briefs", "incidents"):
            await connection.execute(text(f"DELETE FROM {table}"))  # noqa: S608 - fixed names
    yield


@pytest.fixture
def sessions(app_engine: AsyncEngine):  # type: ignore[no-untyped-def]
    return make_session_factory(app_engine)


@pytest.fixture
def store(sessions) -> SqlBriefStore:  # type: ignore[no-untyped-def]
    return SqlBriefStore(sessions)


async def _case(sessions) -> uuid4.__class__:  # type: ignore[no-untyped-def,valid-type]
    incidents = SqlIncidentStore(sessions)
    record = await incidents.open_case(
        NewIncident(
            correlation_key=KEY,
            title="D-004 on 10.10.0.42",
            severity=4,
            severity_rationale={"result": 4},
            window_start=NOW,
            window_end=NOW,
            distinct_rule_count=1,
            alert_ids=(),
        ),
        [],
        now=NOW,
    )
    return record.id


def complete(incident_id, **overrides) -> NewBrief:  # type: ignore[no-untyped-def]
    values = {
        "incident_id": incident_id,
        "status": BriefStatus.complete,
        "source": BriefSource.perplexity,
        "packet_hash": "a" * 64,
        "packet_truncated": False,
        "model": "sonar",
        "summary": "asset-A did four things.",
        "limitations": "No process context.",
        "claims": [{"text": "c", "kind": "observed", "citations": [], "verified": True}],
        "recommendations": [{"action": "investigate_host", "detail": "look"}],
        "citations": (CitationRecord(citation_id=1, url="https://example.test/a", title="A"),),
    }
    values.update(overrides)
    return NewBrief(**values)  # type: ignore[arg-type]


async def test_a_brief_round_trips_with_its_citations(store, sessions) -> None:  # type: ignore[no-untyped-def]
    incident_id = await _case(sessions)
    record = await store.create(complete(incident_id), NOW)

    assert record.version == 1
    assert record.status is BriefStatus.complete
    assert record.source is BriefSource.perplexity
    assert [c.url for c in record.citations] == ["https://example.test/a"]

    read = await store.get(incident_id, 1)
    assert read is not None
    assert read.summary == "asset-A did four things."
    assert read.claims[0]["verified"] is True
    assert read.recommendations[0]["action"] == "investigate_host"


async def test_versions_are_allocated_per_case_and_never_reused(store, sessions) -> None:  # type: ignore[no-untyped-def]
    first_case = await _case(sessions)
    second_case = await _case(sessions)

    assert (await store.create(complete(first_case), NOW)).version == 1
    assert (await store.create(complete(first_case), NOW)).version == 2
    assert (await store.create(complete(second_case), NOW)).version == 1, "per case, not global"

    listed = await store.list(first_case)
    assert [b.version for b in listed] == [2, 1], "newest first"
    latest = await store.latest(first_case)
    assert latest is not None and latest.version == 2


async def test_two_requests_racing_for_a_version_cannot_both_get_it(store, sessions) -> None:  # type: ignore[no-untyped-def]
    """The UNIQUE is what makes the read-then-write safe: the loser fails rather than
    overwriting the winner's brief."""
    incident_id = await _case(sessions)
    outcomes = await asyncio.gather(
        store.create(complete(incident_id), NOW),
        store.create(complete(incident_id), NOW),
        return_exceptions=True,
    )
    written = [o for o in outcomes if not isinstance(o, BaseException)]
    failed = [o for o in outcomes if isinstance(o, BaseException)]
    # Either both serialised cleanly into 1 and 2, or one lost — never two rows at one version.
    assert len(written) + len(failed) == 2
    stored = await store.list(incident_id)
    assert len({b.version for b in stored}) == len(stored)


async def test_a_failed_brief_records_why_and_has_nothing_to_say(store, sessions) -> None:  # type: ignore[no-untyped-def]
    incident_id = await _case(sessions)
    record = await store.create(
        NewBrief(
            incident_id=incident_id,
            status=BriefStatus.failed,
            source=BriefSource.perplexity,
            packet_hash="b" * 64,
            packet_truncated=True,
            failure_reason="http_503",
        ),
        NOW,
    )
    assert record.status is BriefStatus.failed
    assert record.failure_reason == "http_503"
    assert record.summary is None
    assert record.packet_truncated is True


async def test_the_database_refuses_a_brief_that_lies_about_its_status(store, sessions) -> None:  # type: ignore[no-untyped-def]
    """`ck_investigation_briefs_summary_matches_status` and its twin. A complete brief with
    nothing to say, or a failed one with no reason, are not states worth being able to store."""
    incident_id = await _case(sessions)
    with pytest.raises((IntegrityError, DBAPIError)):
        await store.create(complete(incident_id, summary=None), NOW)
    with pytest.raises((IntegrityError, DBAPIError)):
        await store.create(
            complete(incident_id, status=BriefStatus.failed, failure_reason=None), NOW
        )


async def test_the_database_refuses_a_citation_that_is_not_https(store, sessions) -> None:  # type: ignore[no-untyped-def]
    """The domain refuses it first; the database says it too, because a citation is a link
    somebody will click."""
    incident_id = await _case(sessions)
    with pytest.raises((IntegrityError, DBAPIError)):
        await store.create(
            complete(
                incident_id,
                citations=(CitationRecord(citation_id=1, url="http://example.test", title="A"),),
            ),
            NOW,
        )


async def test_the_runtime_role_cannot_edit_or_delete_a_stored_brief(
    store, sessions, app_engine: AsyncEngine
) -> None:  # type: ignore[no-untyped-def]
    """The property the whole design rests on. A brief is a record of what a model said and of
    exactly what was sent to get it; one that can be edited afterwards is evidence of nothing."""
    incident_id = await _case(sessions)
    await store.create(complete(incident_id), NOW)

    async with app_engine.connect() as connection:
        for statement in (
            "UPDATE investigation_briefs SET summary = 'edited'",
            "DELETE FROM investigation_briefs",
            "UPDATE brief_citations SET url = 'https://elsewhere.test'",
            "DELETE FROM brief_citations",
        ):
            nested = await connection.begin_nested()
            with pytest.raises(ProgrammingError) as refused:
                await connection.execute(text(statement))
            if nested.is_active:
                await nested.rollback()
            assert "permission denied" in str(refused.value), statement
