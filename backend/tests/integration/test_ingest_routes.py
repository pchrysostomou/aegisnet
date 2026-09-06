"""Ingest over HTTP: sync and async uploads, the spool, caps, limits, imports, batch reads."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import httpx
import pytest
from fastapi.testclient import TestClient

from aegisnet.config import Settings
from aegisnet.domain.enums import IngestMethod
from aegisnet.main import create_app
from tests.conftest import REPO_ROOT, TEST_SECRET_KEY, make_settings
from tests.fakes import FakeWiring

pytestmark = pytest.mark.integration

EVE = "/api/v1/ingest/eve"
IMPORT = "/api/v1/ingest/import"
BATCHES = "/api/v1/ingest/batches"
FIXTURES = REPO_ROOT / "backend" / "tests" / "fixtures" / "eve"
LINES = (FIXTURES / "benign.ndjson").read_text().splitlines()
BODY = ("\n".join(LINES[:3]) + "\n").encode()
DATASET = "synthetic-benign-baseline-01"


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return make_settings(
        cookie_secure=False,
        spool_dir=tmp_path / "spool",
        secret_key=TEST_SECRET_KEY,
        samples_dir=REPO_ROOT / "samples",
        ingest_max_body_bytes=4096,
        ingest_sync_max_lines=5,
        rate_limit_ingest_per_min=5,
        rate_limit_ingest_bytes_per_hour=4096,
    )


def _post(
    client: TestClient, headers: dict[str, str], body: bytes, **params: str
) -> httpx.Response:
    return client.post(
        EVE,
        params={"source_label": "sensor-a", **params},
        content=body,
        headers={**headers, "content-type": "application/x-ndjson"},
    )


def _spooled(wiring: FakeWiring) -> list[Path]:
    directory = wiring.settings.spool_dir
    return sorted(directory.iterdir()) if directory.exists() else []


def test_sync_ingest_stores_the_lines_cleans_the_spool_and_audits(
    client: TestClient, wiring: FakeWiring, service_headers: dict[str, str]
) -> None:
    response = _post(client, service_headers, BODY, mode="sync")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "complete"
    assert body["counts"] == {"received": 3, "stored": 3, "duplicate": 0, "rejected": 0}
    assert body["source_label"] == "sensor-a" and body["dataset_id"] is None
    assert _spooled(wiring) == [] and wiring.enqueued == []
    entry = wiring.audit_store.entries[-1]
    assert entry.action == "ingest.batch_created" and entry.target_id == body["batch_id"]
    assert entry.actor_token_id is not None and entry.actor_user_id is None
    assert entry.detail["mode"] == "sync" and entry.detail["stored"] == 3
    assert entry.detail["method"] == IngestMethod.api_ndjson.value
    assert entry.detail["sweeps_queued"] == 0  # the fake read store knows no span for it


def test_sync_ingest_queues_a_sweep_over_the_batch_span(
    client: TestClient, wiring: FakeWiring, service_headers: dict[str, str]
) -> None:
    """ADR-020: a completed batch is swept over the hour blocks its events fall in."""
    wiring.event_store.default_span = (
        datetime(2026, 9, 1, 10, 0, 4, tzinfo=UTC),
        datetime(2026, 9, 1, 11, 35, tzinfo=UTC),
    )
    response = _post(client, service_headers, BODY, mode="sync")
    assert response.status_code == 200, response.text
    assert wiring.sweeps == [
        (datetime(2026, 9, 1, 10, tzinfo=UTC), datetime(2026, 9, 1, 12, tzinfo=UTC))
    ]
    assert wiring.audit_store.entries[-1].detail["sweeps_queued"] == 1


async def test_the_post_ingest_sweep_can_be_switched_off(tmp_path: Path) -> None:
    settings = make_settings(
        cookie_secure=False,
        spool_dir=tmp_path / "spool",
        secret_key=TEST_SECRET_KEY,
        post_ingest_sweep=False,
    )
    wiring = FakeWiring(settings, settings.spool_dir)
    wiring.event_store.default_span = (
        datetime(2026, 9, 1, 10, tzinfo=UTC),
        datetime(2026, 9, 1, 10, 5, tzinfo=UTC),
    )
    headers = await wiring.service_token_headers()
    with TestClient(create_app(settings, services_factory=wiring.factory())) as client:  # type: ignore[arg-type]
        response = _post(client, headers, BODY, mode="sync")
    assert response.status_code == 200, response.text
    assert wiring.sweeps == []
    assert wiring.audit_store.entries[-1].detail["sweeps_queued"] == 0


def test_async_ingest_spools_the_body_and_hands_the_name_to_the_worker(
    client: TestClient, wiring: FakeWiring, admin_headers: dict[str, str]
) -> None:
    response = _post(client, admin_headers, BODY)
    assert response.status_code == 202, response.text
    accepted = response.json()
    batch_id = UUID(accepted["batch_id"])
    assert accepted["status"] == "received" and accepted["bytes_received"] == len(BODY)
    assert accepted["poll_url"] == f"{BATCHES}/{batch_id}"
    [(actor, queued_id, spool_name, label)] = wiring.enqueued
    assert actor == "import_upload" and queued_id == batch_id and label == "sensor-a"
    assert wiring.spool.open(spool_name).read_bytes() == BODY
    poll = client.get(accepted["poll_url"], headers=admin_headers)
    assert poll.status_code == 200 and poll.json()["status"] == "received"
    entry = wiring.audit_store.entries[-1]
    assert entry.actor_user_id is not None and entry.detail["mode"] == "async"
    assert entry.detail["bytes"] == len(BODY)


def test_multipart_uploads_take_the_file_part(
    client: TestClient, wiring: FakeWiring, service_headers: dict[str, str]
) -> None:
    response = client.post(
        EVE,
        params={"source_label": "sensor-a", "mode": "sync"},
        files={"file": ("eve.ndjson", BODY, "application/x-ndjson")},
        headers=service_headers,
    )
    assert response.status_code == 200, response.text
    assert response.json()["counts"]["stored"] == 3
    assert wiring.audit_store.entries[-1].detail["method"] == IngestMethod.api_file.value
    wrong_part = client.post(
        EVE,
        params={"source_label": "sensor-a"},
        files={"upload": ("eve.ndjson", BODY)},
        headers=service_headers,
    )
    assert wrong_part.status_code == 422
    assert _spooled(wiring) == []


def test_bodies_past_the_cap_are_refused_and_never_spooled(
    client: TestClient, wiring: FakeWiring, service_headers: dict[str, str]
) -> None:
    too_big = b"\n" * (wiring.settings.ingest_max_body_bytes + 1)
    declared = _post(client, service_headers, too_big)
    assert declared.status_code == 413
    assert declared.json()["error"]["code"] == "payload_too_large"

    def chunks() -> Iterator[bytes]:  # no content-length: the spool's cap is the backstop
        yield too_big[:2048]
        yield too_big[2048:]

    streamed = client.post(
        EVE,
        params={"source_label": "sensor-a"},
        content=chunks(),
        headers={**service_headers, "content-type": "application/x-ndjson"},
    )
    assert streamed.status_code == 413
    assert _spooled(wiring) == [] and wiring.enqueued == []
    refusals = [e for e in wiring.audit_store.entries if e.action == "ingest.refused"]
    assert [e.detail["reason"] for e in refusals] == ["body_too_large", "body_too_large"]
    assert refusals[0].detail["declared"] == len(too_big) and refusals[0].actor_token_id


def test_sync_mode_is_capped_by_lines(
    client: TestClient, wiring: FakeWiring, service_headers: dict[str, str]
) -> None:
    cap = wiring.settings.ingest_sync_max_lines
    many = ("\n".join(LINES[:1] * (cap + 1)) + "\n").encode()
    assert len(many) <= wiring.settings.ingest_max_body_bytes
    response = _post(client, service_headers, many, mode="sync")
    assert response.status_code == 413, response.text
    assert _spooled(wiring) == []
    assert wiring.audit_store.entries[-1].detail == {"reason": "sync_lines_exceeded", "cap": cap}
    wiring.clock.advance(timedelta(hours=1))  # the refused body still counted against bytes
    assert _post(client, service_headers, many).status_code == 202  # async takes it


@pytest.mark.parametrize(
    "params",
    [
        {},
        {"source_label": "bad label!"},
        {"source_label": "x" * 65},
        {"source_label": "ok", "mode": "later"},
    ],
)
def test_query_parameters_are_validated(
    client: TestClient, service_headers: dict[str, str], params: dict[str, str]
) -> None:
    response = client.post(EVE, params=params, content=BODY, headers=service_headers)
    assert response.status_code == 422


def test_ingest_is_rate_limited_by_request_count(
    client: TestClient, wiring: FakeWiring, service_headers: dict[str, str]
) -> None:
    limit = wiring.settings.rate_limit_ingest_per_min
    for _ in range(limit):
        assert _post(client, service_headers, b"\n", mode="sync").status_code == 200
    blocked = _post(client, service_headers, b"\n", mode="sync")
    assert blocked.status_code == 429 and int(blocked.headers["retry-after"]) >= 1
    assert wiring.audit_actions().count("ingest.batch_created") == limit
    wiring.clock.advance(timedelta(minutes=1))
    assert _post(client, service_headers, b"\n", mode="sync").status_code == 200


def test_ingest_fails_closed_when_the_limiter_is_unreachable(
    client: TestClient, wiring: FakeWiring, service_headers: dict[str, str]
) -> None:
    """A Redis outage must not turn metered ingest into unmetered ingest.

    `THREAT_MODEL.md` T-2.6 has claimed since Chunk 6 that this file proves it. It did not:
    `wiring.limiter.broken` appeared only in `test_auth_routes.py`, for login and for the
    fail-*open* read path, so both `fail_open=False` arguments in `api/v1/ingest.py` could have
    been flipped to `True` with the whole suite still green. That is the one direction of this
    setting that matters — reads fail open so an analyst is not locked out by a cache outage,
    and ingest fails closed because an unmetered write path is how a lab becomes a disk-filling
    exercise.

    Both entrypoints are checked, because they take the limiter separately: the synchronous
    body and the spooled upload.
    """
    wiring.limiter.broken = True

    refused = _post(client, service_headers, b"\n", mode="sync")
    assert refused.status_code == 429, "a sync upload was accepted while the limiter was down"
    assert refused.json()["error"]["code"] == "rate_limited"
    assert refused.json()["error"]["correlation_id"]

    spooled = _post(client, service_headers, b"\n" * 20)
    assert spooled.status_code == 429, "a spooled upload was accepted while the limiter was down"

    assert "ingest.batch_created" not in wiring.audit_actions(), "a refused upload created a batch"

    wiring.limiter.broken = False
    assert _post(client, service_headers, b"\n", mode="sync").status_code == 200


def test_ingest_is_rate_limited_by_bytes_per_hour_and_discards_the_spool(
    client: TestClient, wiring: FakeWiring, service_headers: dict[str, str]
) -> None:
    filler = b"\n" * 1500  # blank lines: cheap to ingest, expensive against the byte budget
    assert _post(client, service_headers, filler).status_code == 202
    assert _post(client, service_headers, filler).status_code == 202
    blocked = _post(client, service_headers, filler)
    assert blocked.status_code == 429
    assert len(_spooled(wiring)) == 2 and len(wiring.enqueued) == 2
    wiring.clock.advance(timedelta(hours=1))
    assert _post(client, service_headers, filler).status_code == 202


def test_users_without_ingest_write_are_refused(
    client: TestClient, analyst_headers: dict[str, str], viewer_headers: dict[str, str]
) -> None:
    for headers in (analyst_headers, viewer_headers):
        assert _post(client, headers, BODY).status_code == 403


def test_import_enqueues_a_registered_dataset_only(
    client: TestClient,
    wiring: FakeWiring,
    admin_headers: dict[str, str],
    service_headers: dict[str, str],
) -> None:
    response = client.post(
        IMPORT, json={"dataset_id": DATASET, "source_label": "lab"}, headers=admin_headers
    )
    assert response.status_code == 202, response.text
    batch_id = UUID(response.json()["batch_id"])
    assert response.json()["bytes_received"] > 0
    assert wiring.enqueued == [("import_dataset", batch_id, DATASET, "lab")]
    assert wiring.audit_store.entries[-1].action == "ingest.import_requested"
    unknown = client.post(
        IMPORT, json={"dataset_id": "nope", "source_label": "lab"}, headers=admin_headers
    )
    assert unknown.status_code == 404
    assert unknown.json()["error"]["code"] == "not_found"
    traversal = client.post(
        IMPORT, json={"dataset_id": "../registry", "source_label": "lab"}, headers=admin_headers
    )
    assert traversal.status_code == 422
    refused = wiring.audit_store.entries[-1]
    assert refused.action == "ingest.refused" and refused.actor_user_id is not None
    assert refused.detail == {"reason": "invalid_field", "fields": ["dataset_id"]}
    assert "registry" not in repr(refused)  # the offending value is never recorded
    unauthenticated = client.post(IMPORT, json={"dataset_id": "../x", "source_label": "lab"})
    assert unauthenticated.status_code == 401
    assert wiring.audit_store.entries[-1] is refused  # no principal, nothing to attribute
    bad_label = client.post(
        IMPORT, json={"dataset_id": DATASET, "source_label": "bad label!"}, headers=admin_headers
    )
    assert bad_label.status_code == 422 and wiring.audit_store.entries[-1] is refused
    forbidden = client.post(
        IMPORT, json={"dataset_id": DATASET, "source_label": "lab"}, headers=service_headers
    )
    assert forbidden.status_code == 403
    assert len(wiring.enqueued) == 1


def test_batches_and_rejects_are_readable_by_analysts(
    client: TestClient,
    wiring: FakeWiring,
    service_headers: dict[str, str],
    analyst_headers: dict[str, str],
) -> None:
    mixed = b"not json at all\n" + BODY
    response = _post(client, service_headers, mixed, mode="sync")
    assert response.status_code == 200, response.text
    summary = response.json()
    assert summary["counts"]["rejected"] == 1 and summary["counts"]["stored"] == 3
    batch_id = summary["batch_id"]
    listed = client.get(BATCHES, headers=analyst_headers)
    assert listed.status_code == 200
    assert [b["batch_id"] for b in listed.json()["items"]] == [batch_id]
    one = client.get(f"{BATCHES}/{batch_id}", headers=analyst_headers)
    assert one.status_code == 200 and one.json()["counts"] == summary["counts"]
    rejects = client.get(f"{BATCHES}/{batch_id}/rejects", headers=analyst_headers)
    assert rejects.status_code == 200
    [reject] = rejects.json()["items"]
    assert reject["line_number"] == 1 and reject["reason_code"]
    assert client.get(f"{BATCHES}/{uuid4()}", headers=analyst_headers).status_code == 404
    assert client.get(BATCHES, headers=service_headers).status_code == 403
    assert client.get(BATCHES, params={"limit": 0}, headers=analyst_headers).status_code == 422
    assert client.get(BATCHES, params={"cursor": "x"}, headers=analyst_headers).status_code == 422


BOUNDARY = "aegisnetboundary"
_UPLOAD_BODIES = {
    "ndjson": ("application/x-ndjson", b'{"timestamp":"2026-09-01T10:00:00.000000+0000"'),
    "multipart": (
        f"multipart/form-data; boundary={BOUNDARY}",
        f'--{BOUNDARY}\r\nContent-Disposition: form-data; name="file"; '
        f'filename="a.ndjson"\r\n\r\n'.encode(),
    ),
}


@pytest.mark.asyncio
@pytest.mark.parametrize("shape", sorted(_UPLOAD_BODIES))
async def test_a_body_that_stops_arriving_is_refused_when_the_deadline_passes(
    tmp_path: Path, shape: str
) -> None:
    """T-1.4: every other ingest limit bounds a size, and a size cap is never reached by a body
    that simply stops. This one bounds time.

    It cannot flake. The body yields its first chunk and then waits on an event nothing ever
    sets, so the request has exactly one way to end — the deadline — and a loaded runner delays
    the refusal without changing it. There is no race between the work and the clock because
    the work can never win. The outer `asyncio.timeout` turns a regression from a hung CI job
    into a fast failure.

    Driven through `ASGITransport` rather than `TestClient`: the latter reads the body
    synchronously inside `receive()`, so a stalling generator would block the event loop
    instead of yielding it and nothing would ever fire.
    """
    content_type, first_chunk = _UPLOAD_BODIES[shape]
    settings = make_settings(
        cookie_secure=False,
        spool_dir=tmp_path / "spool",
        secret_key=TEST_SECRET_KEY,
        ingest_upload_timeout_seconds=0.05,
    )
    wiring = FakeWiring(settings, settings.spool_dir)
    headers = await wiring.service_token_headers()
    app = create_app(settings, services_factory=wiring.factory())  # type: ignore[arg-type]

    forever = asyncio.Event()

    async def stalls() -> AsyncIterator[bytes]:
        yield first_chunk
        await forever.wait()  # never set: the deadline is the only way out
        yield b"never sent"

    transport = httpx.ASGITransport(app=app)
    # `TestClient` runs the lifespan for us; driving the app directly means entering it here,
    # which is what puts the wiring on `app.state`.
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=transport, base_url="http://ingest.test") as client,
    ):
        async with asyncio.timeout(5):
            response = await client.post(
                EVE,
                params={"source_label": "sensor-a"},
                content=stalls(),
                headers={
                    **headers,
                    "content-type": content_type,
                    # Multipart is refused without one, and a declared length under the byte
                    # cap proves the refusal is the clock rather than the size.
                    "content-length": str(len(first_chunk) + 9),
                },
            )

    assert response.status_code == 408, response.text
    body = response.json()["error"]
    assert body["code"] == "request_timeout"
    assert body["correlation_id"], "a refusal is still traceable"

    assert _spooled(wiring) == [], "a partial upload was left behind"
    assert wiring.enqueued == [] and wiring.ingest_store.batches == {}, "no batch was opened"

    refusals = [e for e in wiring.audit_store.entries if e.action == "ingest.refused"]
    assert [e.detail["reason"] for e in refusals] == ["upload_timeout"]
    assert refusals[0].detail["seconds"] == 0.05
    assert refusals[0].actor_token_id, "the refusal names who was uploading"
