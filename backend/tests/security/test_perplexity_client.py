"""The inbound half of the boundary, and the client that carries it (TB-3, TB-4; ADR-030).

Every fixture here is a committed response in `tests/fixtures/briefs/`: one good, and one for
each way a model can hand back something that must not be stored as written. No test makes a
network request — the transport is a mock, which is the only way to assert what *would* have
been sent.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from redis.exceptions import RedisError

from aegisnet.adapters.perplexity import (
    SYSTEM_PROMPT,
    BriefUnavailableError,
    InMemoryDailyBudget,
    PerplexityClient,
    packet_hash,
)
from aegisnet.config import Settings
from aegisnet.logging import SecretScrubber
from tests.conftest import make_settings

pytestmark = pytest.mark.security

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "briefs"
KEY = "pplx-" + "canary" + "0123456789abcdefghijklmnop"
PACKET = json.dumps({"case_number": "AEG-2026-0001", "subject": "asset-A"}, sort_keys=True)


def fixture(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES / f"{name}.json").read_text())


def settings(**overrides: object) -> Settings:
    values: dict[str, object] = {"brief_enabled": True, "perplexity_api_key": KEY}
    values.update(overrides)
    return make_settings(**values)


def transport_returning(
    *responses: httpx.Response, record: list[httpx.Request] | None = None
) -> httpx.MockTransport:
    queue = list(responses)

    def handler(request: httpx.Request) -> httpx.Response:
        if record is not None:
            record.append(request)
        return queue.pop(0) if len(queue) > 1 else queue[0]

    return httpx.MockTransport(handler)


def ok(document: dict[str, Any]) -> httpx.Response:
    return httpx.Response(200, json=document)


def client(
    *responses: httpx.Response, record: list[httpx.Request] | None = None, **overrides: object
):  # type: ignore[no-untyped-def]
    return PerplexityClient(
        settings(**overrides),
        transport=transport_returning(*responses, record=record),
        sleep=_no_sleep,
    )


async def _no_sleep(_seconds: float) -> None:
    return None


# ---------------------------------------------------------------- off by default


async def test_the_feature_is_off_unless_somebody_turns_it_on() -> None:
    """The only feature that sends anything outside the deployment defaults to not."""
    assert make_settings().brief_enabled is False
    assert make_settings().perplexity_api_key is None

    silent = PerplexityClient(make_settings(), transport=transport_returning(ok(fixture("good"))))
    assert silent.available is False
    with pytest.raises(BriefUnavailableError) as refused:
        await silent.brief(PACKET)
    assert refused.value.reason == "disabled"


async def test_an_enabled_feature_with_no_key_refuses_rather_than_improvises() -> None:
    half = PerplexityClient(
        make_settings(brief_enabled=True), transport=transport_returning(ok(fixture("good")))
    )
    with pytest.raises(BriefUnavailableError) as refused:
        await half.brief(PACKET)
    assert refused.value.reason == "unconfigured"


# ---------------------------------------------------------------- T-3.6, T-3.1


async def test_only_the_packet_is_sent_and_it_is_announced_as_data() -> None:
    sent: list[httpx.Request] = []
    await client(ok(fixture("good")), record=sent).brief(PACKET)
    (request,) = sent
    body = json.loads(request.content)

    assert str(request.url) == "https://api.perplexity.ai/chat/completions"
    assert request.url.scheme == "https"
    # Exactly two messages: our system prompt, and the packet wrapped in a delimiter that says
    # what it is. Nothing else about the case travels.
    assert [m["role"] for m in body["messages"]] == ["system", "user"]
    assert body["messages"][0]["content"] == SYSTEM_PROMPT
    assert body["messages"][1]["content"] == f"<evidence-packet>\n{PACKET}\n</evidence-packet>"
    assert body["max_tokens"] == settings().perplexity_max_tokens
    assert body["temperature"] == 0.0


def test_the_base_url_cannot_be_pointed_somewhere_else_or_downgraded() -> None:
    for hostile in (
        "http://api.perplexity.ai",
        "https://evil.test",
        "https://api.perplexity.ai.evil.test",
    ):
        with pytest.raises(ValueError, match="perplexity_base_url"):
            make_settings(perplexity_base_url=hostile)


def test_there_is_no_setting_that_turns_certificate_verification_off() -> None:
    """T-3.6 is enforced by absence: a flag that exists is a flag somebody sets."""
    source = (
        Path(__file__).resolve().parents[2] / "src/aegisnet/adapters/perplexity/client.py"
    ).read_text()
    assert "verify=" not in source
    assert "verify_ssl" not in source
    assert "SSL_VERIFY" not in source


# ---------------------------------------------------------------- T-3.3


async def test_the_key_travels_in_a_header_and_nowhere_else() -> None:
    sent: list[httpx.Request] = []
    await client(ok(fixture("good")), record=sent).brief(PACKET)
    (request,) = sent
    assert request.headers["Authorization"] == f"Bearer {KEY}"
    assert KEY not in request.content.decode()
    assert KEY not in str(request.url)


async def test_no_log_record_can_carry_the_key(caplog: pytest.LogCaptureFixture) -> None:
    """The client redacts, and the scrubber would catch it anyway. Both are asserted, because
    the second is what protects against the first being wrong one day (T-3.3)."""
    caplog.set_level(logging.DEBUG)
    failing = client(httpx.Response(500), httpx.Response(500), httpx.Response(500))
    with pytest.raises(BriefUnavailableError):
        await failing.brief(PACKET)

    emitted = "\n".join(f"{record.getMessage()} {record.__dict__}" for record in caplog.records)
    assert KEY not in emitted

    # And the scrubber, given the same settings, would replace it if it ever did appear.
    scrubber = SecretScrubber(settings().secret_values())
    assert KEY not in scrubber.scrub_text(f"a line that leaked {KEY} somehow")


async def test_a_transport_failure_reports_its_type_not_its_exception(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """An httpx error carries the request, and the request carries the Authorization header."""
    caplog.set_level(logging.DEBUG)

    def explode(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    broken = PerplexityClient(settings(), transport=httpx.MockTransport(explode), sleep=_no_sleep)
    with pytest.raises(BriefUnavailableError) as refused:
        await broken.brief(PACKET)
    assert refused.value.reason == "ConnectError"
    assert KEY not in "\n".join(f"{r.getMessage()} {r.__dict__}" for r in caplog.records)


# ---------------------------------------------------------------- T-3.4


async def test_an_unchanged_case_is_answered_from_cache_and_costs_nothing() -> None:
    sent: list[httpx.Request] = []
    cached = client(ok(fixture("good")), record=sent)
    first = await cached.brief(PACKET)
    second = await cached.brief(PACKET)
    assert first.cached is False
    assert second.cached is True
    assert len(sent) == 1, "the second ask did not reach the network"
    assert first.packet_hash == second.packet_hash == packet_hash(PACKET)


async def test_the_daily_budget_is_a_hard_stop() -> None:
    sent: list[httpx.Request] = []
    spender = PerplexityClient(
        settings(brief_daily_budget=2),
        transport=transport_returning(ok(fixture("good")), record=sent),
        sleep=_no_sleep,
    )
    await spender.brief(json.dumps({"case": 1}))
    await spender.brief(json.dumps({"case": 2}))
    with pytest.raises(BriefUnavailableError) as refused:
        await spender.brief(json.dumps({"case": 3}))
    assert refused.value.reason == "budget_exhausted"
    assert len(sent) == 2


async def test_a_budget_that_cannot_be_counted_is_a_stored_failure_and_not_a_crash() -> None:
    """The budget lives in Redis, and Redis can be down.

    `brief()` promises in its own docstring to raise `BriefUnavailableError` "for every reason",
    and `brief_service` catches exactly that to turn a failure into a *stored* brief with a
    reason — the whole point of ADR-031, where a failure is a row rather than an error. A
    `RedisError` from `take()` was the one path that escaped it, and would have surfaced as an
    unhandled 500 with no record that anybody had asked.

    Also asserted: nothing is sent. Counting the ask is what bounds the egress, so a budget that
    cannot be counted must stop the request, not wave it through.
    """

    class UncountableBudget:
        async def take(self) -> None:
            raise RedisError("connection refused")

        async def used(self) -> int:  # pragma: no cover - never reached
            return 0

    sent: list[httpx.Request] = []
    unreachable = PerplexityClient(
        settings(),
        transport=transport_returning(ok(fixture("good")), record=sent),
        sleep=_no_sleep,
        budget=UncountableBudget(),  # type: ignore[arg-type]
    )
    with pytest.raises(BriefUnavailableError) as refused:
        await unreachable.brief(json.dumps({"case": 1}))
    assert refused.value.reason == "budget_unavailable"
    assert sent == [], "the request went out without being counted"


async def test_the_budget_resets_on_a_new_day_and_not_before() -> None:
    now = datetime(2026, 9, 6, 23, 30, tzinfo=UTC)
    budget = InMemoryDailyBudget(2, clock=lambda: now)
    await budget.take()
    await budget.take()
    with pytest.raises(BriefUnavailableError):
        await budget.take()
    now += timedelta(hours=1)
    await budget.take()
    assert budget.used == 1


async def test_the_shared_budget_is_one_cap_for_every_process_that_spends_it() -> None:
    """The reason it moved to Redis (ADR-031): the API, the worker and the CLI each build their
    own client, so a counter in one of them caps that one and lets the other two spend again."""
    import fakeredis

    from aegisnet.adapters.perplexity import RedisDailyBudget

    now = datetime(2026, 9, 6, 23, 30, tzinfo=UTC)
    shared = fakeredis.FakeAsyncRedis()
    api = RedisDailyBudget(shared, 2, clock=lambda: now)
    cli = RedisDailyBudget(shared, 2, clock=lambda: now)
    try:
        await api.take()
        await cli.take()
        with pytest.raises(BriefUnavailableError) as refused:
            await api.take()
        assert refused.value.reason == "budget_exhausted"
        assert await cli.used() == 3, "a refused attempt still counts as one that tried"

        tomorrow = now + timedelta(hours=1)
        fresh = RedisDailyBudget(shared, 2, clock=lambda: tomorrow)
        await fresh.take()
        assert await fresh.used() == 1, "a new UTC day is a new key"
        assert await shared.ttl(f"aegisnet:brief:budget:{now.date().isoformat()}") > 0
    finally:
        await shared.aclose()


# ---------------------------------------------------------------- failure modes


@pytest.mark.parametrize("status", [429, 500, 502, 503, 504])
async def test_a_retryable_status_is_retried_then_gives_up_gracefully(status: int) -> None:
    sent: list[httpx.Request] = []
    flaky = client(httpx.Response(status), record=sent)
    with pytest.raises(BriefUnavailableError) as refused:
        await flaky.brief(PACKET)
    assert refused.value.reason == f"http_{status}"
    assert len(sent) == settings().perplexity_max_retries + 1


async def test_a_retry_succeeds_when_the_second_attempt_answers() -> None:
    sent: list[httpx.Request] = []
    recovering = client(httpx.Response(503), ok(fixture("good")), record=sent)
    result = await recovering.brief(PACKET)
    assert result.brief.summary.startswith("Host asset-A scanned")
    assert len(sent) == 2


@pytest.mark.parametrize("status", [400, 401, 403, 404])
async def test_a_refusal_that_will_not_change_is_not_retried(status: int) -> None:
    sent: list[httpx.Request] = []
    refusing = client(httpx.Response(status), record=sent)
    with pytest.raises(BriefUnavailableError):
        await refusing.brief(PACKET)
    assert len(sent) == 1, "retrying a 401 only wastes a request"


async def test_a_response_that_is_not_json_fails_gracefully() -> None:
    with pytest.raises(BriefUnavailableError) as refused:
        await client(httpx.Response(200, content=b"<html>502</html>")).brief(PACKET)
    assert refused.value.reason == "malformed_json"


async def test_an_enormous_response_is_not_parsed(caplog: pytest.LogCaptureFixture) -> None:
    """T-4.5: the cap is checked against the bytes before anything tries to read them."""
    huge = httpx.Response(200, content=b'{"choices":[]}' + b" " * 5000)
    tight = PerplexityClient(
        settings(perplexity_max_response_bytes=2048),
        transport=transport_returning(huge),
        sleep=_no_sleep,
    )
    with pytest.raises(BriefUnavailableError) as refused:
        await tight.brief(PACKET)
    assert refused.value.reason == "response_too_large"


async def test_a_model_that_answers_in_prose_is_refused() -> None:
    with pytest.raises(BriefUnavailableError) as refused:
        await client(ok(fixture("not-json"))).brief(PACKET)
    assert refused.value.reason == "malformed_brief"


async def test_every_failure_names_a_reason_worth_storing() -> None:
    """Chunk 23 records these on a failed brief, so each has to be a short stable string."""
    reasons = set()
    for response in (
        httpx.Response(401),
        httpx.Response(200, content=b"nope"),
        ok(fixture("not-json")),
    ):
        try:
            await client(response).brief(PACKET)
        except BriefUnavailableError as error:
            reasons.add(error.reason)
    assert reasons == {"http_401", "malformed_json", "malformed_brief"}
    assert all(reason.replace("_", "").isalnum() for reason in reasons)


# ---------------------------------------------------------------- TB-4 through the client


async def test_a_brief_recommending_an_attack_is_reported_as_safety_rejected() -> None:
    """The M5 acceptance criterion, and the reason safety is a separate step from validation:
    pydantic turns any ValueError raised inside a validator into a ValidationError, which would
    have made "the model told us to attack something" indistinguishable from "a field was too
    long". Those need different records and different conversations."""
    with pytest.raises(BriefUnavailableError) as refused:
        await client(ok(fixture("unsafe"))).brief(PACKET)
    assert refused.value.reason == "safety_rejected"


async def test_a_brief_whose_shape_is_wrong_is_reported_separately() -> None:
    for name in ("dangling-citation", "insecure-citation"):
        with pytest.raises(BriefUnavailableError) as refused:
            await client(ok(fixture(name))).brief(PACKET)
        assert refused.value.reason == "schema_rejected", name


async def test_an_uncited_claim_is_stored_and_flagged_rather_than_refused() -> None:
    """Unlike the two above, this one is admitted. A reader deciding what to trust is better
    served by seeing the claim marked UNVERIFIED than by a silent deletion (T-4.2)."""
    result = await client(ok(fixture("uncited"))).brief(PACKET)
    assert result.brief.has_unverified is True
    assert "APT-99" in result.brief.unverified[0].text


async def test_a_good_brief_comes_back_whole_with_its_usage() -> None:
    result = await client(ok(fixture("good"))).brief(PACKET)
    assert result.brief.has_unverified is False
    assert result.model == "sonar"
    assert (result.prompt_tokens, result.completion_tokens) == (812, 340)
    assert result.cached is False
