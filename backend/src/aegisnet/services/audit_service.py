"""Audit trail writer (FR-10.3, T-2.5).

One call per auditable action. ``detail`` is bounded and sanitised here so no caller
can put a secret, a raw log line, or a control character into the append-only table:
values are stringified, control characters stripped, each value capped, and keys that
look like credentials are dropped outright.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import Any, Final
from uuid import UUID

from aegisnet.domain.assets import IPAddress
from aegisnet.domain.auth import Principal, PrincipalKind
from aegisnet.domain.enums import AuditResult
from aegisnet.domain.eve.sanitize import clean_text
from aegisnet.domain.pagination import check_limit, decode_int
from aegisnet.domain.ports import AuditEntry, AuditFilter, AuditReadStore, AuditRow, AuditSink, Page

MAX_DETAIL_KEYS: Final = 32
MAX_DETAIL_CHARS: Final = 512
_SENSITIVE_KEY: Final = re.compile(
    r"(pass(word)?|secret|token|api[_-]?key|authorization|cookie|credential)", re.IGNORECASE
)


def utc_now() -> datetime:
    return datetime.now(tz=UTC)


def bounded_detail(detail: Mapping[str, Any] | None, *, depth: int = 1) -> dict[str, Any]:
    """Only scalars, only non-sensitive keys, every string cleaned and capped.

    One level of nested mapping is kept (a before/after pair, say) under the same rules;
    anything deeper is stringified so the shape stays bounded.
    """
    cleaned: dict[str, Any] = {}
    for key, value in (detail or {}).items():
        if len(cleaned) >= MAX_DETAIL_KEYS or _SENSITIVE_KEY.search(str(key)):
            continue
        safe_key = clean_text(str(key), 64)
        if value is None or isinstance(value, bool | int | float):
            cleaned[safe_key] = value
        elif isinstance(value, Mapping) and depth > 0:
            cleaned[safe_key] = bounded_detail(value, depth=depth - 1)
        elif isinstance(value, list | tuple):
            cleaned[safe_key] = [clean_text(str(item), 128) for item in value[:20]]
        else:
            cleaned[safe_key] = clean_text(str(value), MAX_DETAIL_CHARS)
    return cleaned


class AuditService:
    def __init__(self, sink: AuditSink, *, clock: Callable[[], datetime] = utc_now) -> None:
        self._sink = sink
        self._clock = clock

    async def record(
        self,
        action: str,
        *,
        target_type: str,
        target_id: str | None = None,
        result: AuditResult = AuditResult.success,
        detail: Mapping[str, Any] | None = None,
        principal: Principal | None = None,
        actor_user_id: UUID | None = None,
        actor_ip: IPAddress | None = None,
        correlation_id: UUID | None = None,
    ) -> AuditEntry:
        user_id = actor_user_id
        token_id: UUID | None = None
        if principal is not None:
            if principal.kind is PrincipalKind.user:
                user_id = principal.id
            else:
                token_id = principal.id
        entry = AuditEntry(
            occurred_at=self._clock(),
            action=clean_text(action, 64),
            target_type=clean_text(target_type, 64),
            target_id=None if target_id is None else clean_text(str(target_id), 128),
            result=result,
            detail=bounded_detail(detail),
            actor_user_id=user_id,
            actor_token_id=token_id,
            actor_ip=actor_ip,
            correlation_id=correlation_id,
        )
        await self._sink.write(entry)
        return entry


class AuditReadService:
    def __init__(self, store: AuditReadStore) -> None:
        self._store = store

    async def list(self, query: AuditFilter) -> Page[AuditRow]:
        check_limit(query.limit)
        if query.cursor is not None:
            decode_int(query.cursor)
        return await self._store.list(query)
