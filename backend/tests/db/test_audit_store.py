"""The SQL audit store: append, list newest first, filters and cursors, full round trip."""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from uuid import uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from aegisnet.adapters.db.audit_store import SqlAuditStore
from aegisnet.adapters.db.auth_store import SqlUserStore
from aegisnet.adapters.db.session import make_session_factory
from aegisnet.domain.enums import AuditResult, UserRole
from aegisnet.domain.ports import AuditEntry, AuditFilter

pytestmark = [pytest.mark.db, pytest.mark.integration]

T0 = datetime(2026, 9, 5, 12, 0, tzinfo=UTC)


@pytest.fixture(autouse=True)
async def clean_tables(migrator_engine: AsyncEngine) -> AsyncIterator[None]:
    async with migrator_engine.begin() as connection:
        await connection.execute(text("DELETE FROM audit_log"))
        await connection.execute(text("DELETE FROM users"))
    yield


def _ids(page_items: tuple[object, ...]) -> list[str | None]:
    return [row.entry.target_id for row in page_items]  # type: ignore[attr-defined]


async def test_entries_append_and_page_newest_first_with_filters(app_engine: AsyncEngine) -> None:
    sessions = make_session_factory(app_engine)
    store = SqlAuditStore(sessions)
    user = await SqlUserStore(sessions).create(
        "ana@example.test", "Ana", "$argon2id$x", UserRole.analyst, T0
    )
    entries = [
        AuditEntry(
            occurred_at=T0 + timedelta(seconds=index),
            action=f"a{index % 2}",
            target_type="t",
            target_id=str(index),
            result=AuditResult.denied if index == 2 else AuditResult.success,
            detail={"index": index, "nested": {"ok": True}},
            actor_user_id=user.id if index < 2 else None,
            actor_ip=ip_address("10.0.0.7") if index == 0 else None,
            correlation_id=uuid4(),
        )
        for index in range(4)
    ]
    for entry in entries:
        await store.write(entry)

    page = await store.list(AuditFilter(limit=3))
    assert _ids(page.items) == ["3", "2", "1"] and page.next_cursor
    assert [row.id for row in page.items] == sorted((row.id for row in page.items), reverse=True)
    rest = await store.list(AuditFilter(limit=3, cursor=page.next_cursor))
    assert _ids(rest.items) == ["0"] and rest.next_cursor is None
    assert rest.items[0].entry == entries[0]  # full round trip: ip, detail, correlation id

    assert _ids((await store.list(AuditFilter(action="a1"))).items) == ["3", "1"]
    assert _ids((await store.list(AuditFilter(result=AuditResult.denied))).items) == ["2"]
    assert _ids((await store.list(AuditFilter(actor_user_id=user.id))).items) == ["1", "0"]
    window = AuditFilter(time_from=T0 + timedelta(seconds=1), time_to=T0 + timedelta(seconds=2))
    assert _ids((await store.list(window)).items) == ["2", "1"]
    assert (await store.list(AuditFilter(action="none"))).items == ()
