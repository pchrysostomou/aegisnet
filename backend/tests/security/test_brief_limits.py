"""Asking for a brief is limited per analyst and per case (Milestone 6, Chunk 28; T-3.4).

`BRIEF_DAILY_BUDGET` has existed since Chunk 23 and is a real cap, but it is one number for the
whole deployment, so it is not a limit on anybody in particular: one analyst could spend the
day, and a loop on one case could spend it in a minute. `THREAT_MODEL.md` said per-user and
per-incident limits existed. They did not, and the §6 coverage matrix is what said so out loud.

Nothing here reaches the network. The feature is off and the wiring has no key, so every ask is
served the committed offline sample — which is the point: an ask that costs no money still
writes an append-only brief row and a timeline line, and a loop that writes rows nobody can
delete is the same denial of service as a loop that spends.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient

from aegisnet.config import Settings
from aegisnet.domain.enums import AlertStatus, EntityType, TimelineEntryType, UserRole
from aegisnet.domain.ports import AlertRecord, NewIncident, NewTimelineEntry
from tests.conftest import PASSWORD, TEST_SECRET_KEY, make_settings
from tests.fakes import FakeWiring

pytestmark = [pytest.mark.security, pytest.mark.integration]

INCIDENTS = "/api/v1/incidents"
T0 = datetime(2026, 9, 5, 9, 0, tzinfo=UTC)

# Small enough to exhaust in a test, and still in the shipped relation: the case's share is
# narrower than the analyst's, which is narrower than the deployment's day.
CASE_LIMIT = 3
USER_LIMIT = 5


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    """Overrides only the two numbers under test; everything else is the shipped default."""
    return make_settings(
        cookie_secure=False,
        spool_dir=tmp_path / "spool",
        secret_key=TEST_SECRET_KEY,
        brief_incident_daily_limit=CASE_LIMIT,
        brief_user_daily_limit=USER_LIMIT,
    )


async def _case(wiring: FakeWiring, host: str) -> UUID:
    """A case with one alert, built the way `test_brief_routes.py` builds one."""
    alert = AlertRecord(
        id=uuid4(),
        rule_id="D-004",
        rule_version=1,
        dedup_key=f"D-004:src_ip={host}:x",
        severity=4,
        confidence=0.9,
        severity_rationale={"result": 4},
        entity_type=EntityType.src_ip,
        entity_value=host,
        first_seen=T0,
        last_seen=T0 + timedelta(minutes=14),
        evidence={"connections": 14, "jitter": 0.016, "destination": "203.0.113.55"},
        event_count=14,
        status=AlertStatus.correlated,
        created_at=T0,
    )
    wiring.alert_store.rows[alert.id] = alert
    incident = await wiring.incident_store.open_case(
        NewIncident(
            correlation_key=f"src_ip={host}",
            title=f"D-004 on {host}",
            severity=4,
            severity_rationale={"result": 4},
            window_start=T0,
            window_end=T0 + timedelta(minutes=14),
            distinct_rule_count=1,
            alert_ids=(alert.id,),
        ),
        [
            NewTimelineEntry(
                occurred_at=T0,
                entry_type=TimelineEntryType.alert_fired,
                summary=f"D-004 fired on src_ip {host}",
                alert_id=alert.id,
            )
        ],
        now=T0 + timedelta(minutes=20),
    )
    return incident.id


def _ask(client: TestClient, headers: dict[str, str], case: UUID):
    return client.post(f"{INCIDENTS}/{case}/briefs", headers=headers)


async def test_one_case_can_only_be_asked_about_so_many_times_in_a_day(
    client: TestClient, wiring: FakeWiring, analyst_headers: dict[str, str]
) -> None:
    case = await _case(wiring, "10.10.0.42")

    for attempt in range(CASE_LIMIT):
        assert _ask(client, analyst_headers, case).status_code == 201, f"ask {attempt}"

    refused = _ask(client, analyst_headers, case)
    assert refused.status_code == 429
    body = refused.json()["error"]
    assert body["code"] == "rate_limited"
    assert body["correlation_id"], "a refusal is still traceable"
    assert refused.headers["Retry-After"], "a 429 nobody can act on is not a refusal"

    listed = client.get(f"{INCIDENTS}/{case}/briefs", headers=analyst_headers).json()
    assert len(listed) == CASE_LIMIT, "the refused ask stored nothing"


async def test_a_loop_on_one_case_does_not_cost_an_analyst_their_other_cases(
    client: TestClient, wiring: FakeWiring, analyst_headers: dict[str, str]
) -> None:
    """Why the case limit is spent before the analyst's, and not after.

    `hit` increments whether or not it allows. Checking the analyst first would mean a stuck
    tab on one case spends that analyst's whole day and locks them out of every other case —
    turning a cost problem into an availability problem for the person doing the work.
    """
    loud = await _case(wiring, "10.10.0.42")
    other = await _case(wiring, "10.10.0.77")

    for _ in range(CASE_LIMIT):
        assert _ask(client, analyst_headers, loud).status_code == 201
    for _ in range(4):
        assert _ask(client, analyst_headers, loud).status_code == 429

    assert _ask(client, analyst_headers, other).status_code == 201, (
        "a loop on one case spent the analyst's whole day"
    )


async def test_one_analysts_day_is_their_own_and_does_not_spend_anybody_elses(
    client: TestClient, wiring: FakeWiring, analyst_headers: dict[str, str]
) -> None:
    """The per-user cap binds across cases, and it binds on the user rather than the deployment.

    Five distinct cases, one analyst: the sixth ask is refused by the *user* limit even though
    that case has been asked about once. A second analyst is unaffected.
    """
    cases = [await _case(wiring, f"10.10.0.{n}") for n in range(10, 10 + USER_LIMIT + 1)]

    for case in cases[:USER_LIMIT]:
        assert _ask(client, analyst_headers, case).status_code == 201

    spent = _ask(client, analyst_headers, cases[USER_LIMIT])
    assert spent.status_code == 429, "the analyst's day was not bounded"

    await wiring.add_user("second-analyst@example.test", UserRole.analyst, PASSWORD)
    second = await wiring.login_headers("second-analyst@example.test", PASSWORD)
    fresh = _ask(client, second, cases[USER_LIMIT])
    assert fresh.status_code == 201, "one analyst's loop spent another analyst's day"


async def test_a_refused_ask_writes_no_brief_no_timeline_line_and_asks_nothing(
    client: TestClient, wiring: FakeWiring, analyst_headers: dict[str, str]
) -> None:
    case = await _case(wiring, "10.10.0.42")
    for _ in range(CASE_LIMIT):
        _ask(client, analyst_headers, case)

    before = client.get(f"{INCIDENTS}/{case}", headers=analyst_headers).json()
    generated_before = [
        entry for entry in wiring.audit_store.entries if entry.action == "brief.generated"
    ]

    assert _ask(client, analyst_headers, case).status_code == 429

    after = client.get(f"{INCIDENTS}/{case}", headers=analyst_headers).json()
    assert after["timeline"] == before["timeline"], "a refusal changed the case's story"
    generated_after = [
        entry for entry in wiring.audit_store.entries if entry.action == "brief.generated"
    ]
    assert generated_after == generated_before, "a refusal was audited as a generation"


@pytest.mark.parametrize("failing", ["brief_incident", "brief_user"])
async def test_each_brief_limit_fails_closed_when_the_limiter_is_down(
    client: TestClient, wiring: FakeWiring, analyst_headers: dict[str, str], failing: str
) -> None:
    """Reads fail open so a Redis outage does not lock an analyst out of their queue. These fail
    closed, with login and ingest: the cap they sit under is a spending cap *and* an exposure
    cap, and an unreachable counter is not a reason to send more to a third party than the
    deployment agreed to.

    One limit is broken at a time on purpose. Breaking both proves only that *something* fails
    closed — with the case limit checked first, a version where it quietly failed open would
    still be caught by the user limit behind it, and nothing would say so.
    """
    case = await _case(wiring, "10.10.0.42")
    working = wiring.limiter.hit

    async def hit(name: str, subject: str, **kwargs: object):
        if name == failing:
            from redis.exceptions import ConnectionError as RedisConnectionError

            raise RedisConnectionError("redis is down")
        return await working(name, subject, **kwargs)  # type: ignore[arg-type]

    wiring.limiter.hit = hit  # type: ignore[method-assign]

    refused = _ask(client, analyst_headers, case)

    assert refused.status_code == 429, f"{failing} did not fail closed"
    assert refused.json()["error"]["code"] == "rate_limited"
    assert refused.headers["Retry-After"] == "30"
    assert client.get(f"{INCIDENTS}/{case}/briefs", headers=analyst_headers).json() == []


def test_the_shipped_limits_are_each_narrower_than_the_deployment_budget() -> None:
    """Asserted as a relation rather than as three literals, because the relation is the claim:
    no single analyst and no single case can spend the deployment's day."""
    shipped = make_settings(secret_key=TEST_SECRET_KEY)
    assert shipped.brief_incident_daily_limit < shipped.brief_user_daily_limit
    assert shipped.brief_user_daily_limit < shipped.brief_daily_budget
