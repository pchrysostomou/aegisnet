"""AuditService: bounded, credential-free detail; actor attribution; read-side validation."""

from __future__ import annotations

from ipaddress import ip_address
from uuid import uuid4

import pytest

from aegisnet.domain.auth import principal_for_service_token, principal_for_user
from aegisnet.domain.enums import AuditResult, ServiceTokenRole, UserRole
from aegisnet.domain.pagination import InvalidCursorError
from aegisnet.domain.ports import AuditFilter
from aegisnet.services.audit_service import (
    MAX_DETAIL_CHARS,
    MAX_DETAIL_KEYS,
    AuditReadService,
    AuditService,
    bounded_detail,
)
from tests.fakes import Clock, FakeAuditStore

pytestmark = pytest.mark.unit


def test_credential_like_keys_never_reach_the_trail() -> None:
    detail = bounded_detail(
        {
            "password": "x",
            "Passwd": "x",
            "secret": "x",
            "api_key": "x",
            "API-KEY": "x",
            "token": "x",
            "refresh_token": "x",
            "Authorization": "x",
            "cookie": "x",
            "credential": "x",
            "reason": "ok",
            "nested": {"password": "x", "hostname": "h"},
        }
    )
    assert detail == {"reason": "ok", "nested": {"hostname": "h"}}


def test_values_are_scalars_cleaned_and_capped() -> None:
    detail = bounded_detail(
        {
            "n": 3,
            "f": 1.5,
            "b": True,
            "none": None,
            "long": "x" * (MAX_DETAIL_CHARS + 50),
            "ctrl": "a\x00b\x1bc",
            "list": [f"item{i}\x07" for i in range(25)],
            "obj": ip_address("10.0.0.1"),
            "k\x00ey": 1,
            "deep": {"level1": {"level2": {"level3": "v"}}},
        }
    )
    assert detail["n"] == 3 and detail["f"] == 1.5 and detail["b"] is True
    assert detail["none"] is None
    assert len(detail["long"]) <= MAX_DETAIL_CHARS + 1
    assert "\x00" not in detail["ctrl"] and "\x1b" not in detail["ctrl"]
    assert len(detail["list"]) == 20 and all("\x07" not in item for item in detail["list"])
    assert detail["obj"] == "10.0.0.1"
    assert all("\x00" not in key for key in detail)
    assert isinstance(detail["deep"]["level1"], str)  # nesting is bounded to one level


def test_at_most_max_keys_are_kept_in_order() -> None:
    detail = bounded_detail({f"k{i}": i for i in range(MAX_DETAIL_KEYS + 10)})
    assert list(detail) == [f"k{i}" for i in range(MAX_DETAIL_KEYS)]
    assert bounded_detail(None) == {}


async def test_record_attributes_the_actor_and_writes_one_entry() -> None:
    clock, store = Clock(), FakeAuditStore()
    service = AuditService(store, clock=clock)
    user = principal_for_user(uuid4(), UserRole.admin, "root@example.test")
    token = principal_for_service_token(uuid4(), ServiceTokenRole.ingest_service)
    correlation = uuid4()
    entry = await service.record(
        "asset.created",
        target_type="asset",
        target_id="a1",
        detail={"hostname": "h", "password": "no"},
        principal=user,
        actor_ip=ip_address("10.0.0.9"),
        correlation_id=correlation,
    )
    assert entry.actor_user_id == user.id and entry.actor_token_id is None
    assert entry.occurred_at == clock.now and entry.result is AuditResult.success
    assert entry.detail == {"hostname": "h"} and entry.correlation_id == correlation
    assert str(entry.actor_ip) == "10.0.0.9"
    by_token = await service.record(
        "ingest.batch_created",
        target_type="ingest_batch",
        principal=token,
        result=AuditResult.denied,
    )
    assert by_token.actor_token_id == token.id and by_token.actor_user_id is None
    assert by_token.result is AuditResult.denied and by_token.detail == {}
    explicit = await service.record("auth.login_failed", target_type="user", actor_user_id=user.id)
    assert explicit.actor_user_id == user.id
    assert store.entries == [entry, by_token, explicit]


async def test_action_and_target_are_cleaned_and_capped() -> None:
    service = AuditService(FakeAuditStore(), clock=Clock())
    entry = await service.record("x" * 100 + "\x00", target_type="t\x1b", target_id="i" * 200)
    assert len(entry.action) <= 65 and "\x00" not in entry.action
    assert "\x1b" not in entry.target_type
    assert entry.target_id is not None and len(entry.target_id) <= 129


async def test_the_read_side_validates_limits_and_cursors_before_the_store() -> None:
    store = FakeAuditStore()
    service = AuditService(store, clock=Clock())
    reader = AuditReadService(store)
    for index in range(3):
        await service.record(f"a{index}", target_type="t")
    page = await reader.list(AuditFilter(limit=2))
    assert [r.entry.action for r in page.items] == ["a2", "a1"] and page.next_cursor
    rest = await reader.list(AuditFilter(limit=2, cursor=page.next_cursor))
    assert [r.entry.action for r in rest.items] == ["a0"] and rest.next_cursor is None
    with pytest.raises(ValueError, match="limit"):
        await reader.list(AuditFilter(limit=0))
    with pytest.raises(ValueError, match="limit"):
        await reader.list(AuditFilter(limit=201))
    with pytest.raises(InvalidCursorError):
        await reader.list(AuditFilter(cursor="nope"))
