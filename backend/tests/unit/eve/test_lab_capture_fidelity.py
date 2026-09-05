"""What real Suricata output does that the synthetic corpus does not (ADR-021, ADR-009).

ADR-009 deferred the lab with a promise: "any divergence from real Suricata output is a
Milestone 2 finding". These tests are that finding, written as executable statements over
the committed lab capture (`samples/lab/lab-capture-01.ndjson`, real Suricata 8.0.6 output
from `infra/lab/`).

Two of them recorded defects when this file was written in Chunk 13: D-004 could not see a
real beacon and D-003 could not read real DNS at all. Chunk 14 fixed both (ADR-022), and the
same tests now hold the fixes down — the facts about Suricata's output are unchanged, so what
flipped is the consequence, which is exactly what a regression test for a fix should assert.
"""

from __future__ import annotations

import json
import statistics
from datetime import UTC, datetime, timedelta
from itertools import pairwise
from pathlib import Path

import pytest

from aegisnet.adapters.files.labelled import row_from_normalized
from aegisnet.domain.detectors import EventWindow, get_detector
from aegisnet.domain.detectors.beaconing import BeaconingParams
from aegisnet.domain.enums import EventType
from aegisnet.domain.eve.normalizer import normalize_lines
from aegisnet.domain.models import NormalizedEvent
from aegisnet.domain.ports import EventRow
from tests.conftest import REPO_ROOT

pytestmark = pytest.mark.unit

CAPTURE = REPO_ROOT / "samples" / "lab" / "lab-capture-01.ndjson"
SYNTHETIC = REPO_ROOT / "samples" / "synthetic" / "benign-baseline-01.ndjson"
BEACON_PORT = 9443
# Fixed so normalisation's freshness check does not depend on the day the suite runs.
CLOCK = datetime(2026, 9, 6, 12, 0, tzinfo=UTC)


def _raw(path: Path) -> list[dict]:
    return [
        json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()
    ]


def _rows(path: Path) -> list[EventRow]:
    lines = path.read_text(encoding="utf-8").splitlines()
    return [
        row_from_normalized(outcome)
        for _, outcome in normalize_lines(lines, now=CLOCK)
        if isinstance(outcome, NormalizedEvent)
    ]


def _moment(text: str) -> datetime:
    return datetime.fromisoformat(text.replace("+0000", "+00:00").replace("Z", "+00:00"))


def _window(rows: list[EventRow]) -> EventWindow:
    """The hour the capture falls in, which is the grid a sweep would use."""
    ordered = sorted(rows, key=lambda r: (r.event_time, r.id.int))
    start = ordered[0].event_time.replace(minute=0, second=0, microsecond=0)
    return EventWindow(start, start + timedelta(hours=1), tuple(ordered))


def _jitter(moments: list[datetime]) -> float:
    """Standard deviation over mean of the gaps, which is what D-004 measures."""
    gaps = [(b - a).total_seconds() for a, b in pairwise(moments)]
    mean = statistics.fmean(gaps)
    return statistics.pstdev(gaps) / mean


# ---------------------------------------------------------------- what works


def test_every_record_of_a_real_capture_survives_the_ingest_path() -> None:
    """The headline result: real Suricata output needs no special handling to be ingested."""
    lines = CAPTURE.read_text(encoding="utf-8").splitlines()
    outcomes = list(normalize_lines(lines, now=CLOCK))
    rejected = [(number, o) for number, o in outcomes if not isinstance(o, NormalizedEvent)]
    assert rejected == [], f"real capture rejected at {[n for n, _ in rejected]}"
    assert len(outcomes) == len([line for line in lines if line.strip()])


def test_the_capture_carries_the_event_types_the_lab_generates() -> None:
    """The four the six scenarios aim at, plus whatever else a real sensor decided to say —
    this capture also carries one `anomaly`, which no scenario asked for and which is the
    kind of record the synthetic corpus can only guess at."""
    kinds = {row.event_type for row in _rows(CAPTURE)}
    assert {EventType.alert, EventType.dns, EventType.flow, EventType.http} <= kinds
    assert kinds <= set(EventType), "every type the capture carries is one the domain knows"


def test_the_scan_and_the_auth_burst_are_found_in_the_real_capture() -> None:
    """D-001 and D-002 on real traffic, without a database or a container in sight."""
    window = _window(_rows(CAPTURE))
    fired = {
        rule: [result.entity.value for result in get_detector(rule).run(window)]
        for rule in ("D-001", "D-002")
    }
    assert fired["D-001"] == ["203.0.113.20"], "the generator is the scanner"
    assert fired["D-002"] == ["203.0.113.10"], "the target answered the failures"


# ---------------------------------------------------------------- what does not


def test_a_flow_is_read_at_its_start_not_at_its_emission() -> None:
    """L-F1, fixed (ADR-022). The fact about Suricata is unchanged — a flow record is stamped
    when the flow manager emits it, and those emissions are irregular — but the normaliser now
    files the event under `flow.start`, so D-004 sees the beacon that is really there."""
    beacon = sorted(
        (
            r
            for r in _raw(CAPTURE)
            if r["event_type"] == "flow" and r.get("dest_port") == BEACON_PORT
        ),
        key=lambda r: r["timestamp"],
    )
    assert len(beacon) >= BeaconingParams().min_connections

    emitted = [_moment(r["timestamp"]) for r in beacon]
    started = sorted(_moment(r["flow"]["start"]) for r in beacon)
    true_jitter = _jitter(started)
    seen_jitter = _jitter(emitted)

    limit = BeaconingParams().max_jitter
    assert true_jitter < limit, "the beacon really is regular"
    assert seen_jitter > limit, "and the record timestamps really are not"

    # What the normaliser files the event under is now the first of those, not the second.
    normalised = sorted(
        r.event_time
        for r in _rows(CAPTURE)
        if r.dest_port == BEACON_PORT and r.event_type is EventType.flow
    )
    assert _jitter(normalised) == pytest.approx(true_jitter, abs=1e-6)

    # And this is the consequence: the rule finds the beacon.
    [found] = get_detector("D-004").run(_window(_rows(CAPTURE)))
    assert found.entity.value == "203.0.113.20"


def test_a_real_dns_request_carries_an_rcode_and_is_still_read_as_a_question() -> None:
    """L-F2, fixed (ADR-022). Suricata 8 logs EVE DNS v3, where request and response records
    both carry `rcode`; direction now comes from the record's own `type`, so the query names
    are tallied against the host that asked and D-003 can see the shape the lab generated."""
    requests = [
        r for r in _raw(CAPTURE) if r["event_type"] == "dns" and r["dns"]["type"] == "request"
    ]
    assert requests, "the capture contains DNS requests"
    assert all("rcode" in r["dns"] for r in requests)
    assert all(r["dns"]["version"] == 3 for r in requests)

    # The corpus now carries both shapes, so T1 and T2 exercise the path this defect was on
    # rather than leaving it to the real capture alone (Chunk 14).
    synthetic = [r for r in _raw(SYNTHETIC) if r.get("event_type") == "dns"]
    shapes = {(r["dns"]["version"], r["dns"]["type"]) for r in synthetic}
    assert shapes == {(3, "request"), (3, "response"), (2, "query"), (2, "answer")}
    v2_queries = [r for r in synthetic if r["dns"]["type"] == "query"]
    v3_requests = [r for r in synthetic if r["dns"]["type"] == "request"]
    assert v2_queries and not any("rcode" in r["dns"] for r in v2_queries), "v2: only answers"
    assert v3_requests and all("rcode" in r["dns"] for r in v3_requests), "v3: both halves"

    # The consequence, on the capture the lab actually took.
    rows = _rows(CAPTURE)
    dns = [r for r in rows if r.event_type is EventType.dns]
    questions = [r for r in dns if r.dns_rcode is None]
    replies = [r for r in dns if r.dns_rcode is not None]
    assert len(questions) == len(replies) == len(dns) // 2, "half of them are questions"
    long_labels = {
        r.dns_query
        for r in questions
        if r.dns_query and any(len(label) >= 40 for label in r.dns_query.split("."))
    }
    assert len(long_labels) >= 20, "the lab generated an unmistakable tunnel shape"
    [found] = get_detector("D-003").run(_window(rows))
    assert found.entity.value == "203.0.113.20", "attributed to the host that asked"


def test_alert_records_carry_their_flow_and_app_layer_metadata() -> None:
    """Finding L-F3: an alert has `flow` and `http` blocks only when the sensor's eve-log
    sets `metadata: yes`. The lab's first run had it off and produced alerts thinner than the
    synthetic corpus's; the configuration now says yes, and this keeps it that way."""
    alerts = [r for r in _raw(CAPTURE) if r["event_type"] == "alert"]
    assert alerts
    assert all("flow" in r for r in alerts), "flow counters reach the alert"
    http_alerts = [r for r in alerts if r.get("app_proto") == "http"]
    assert http_alerts and all("http" in r for r in http_alerts)


def test_real_records_carry_keys_the_generator_does_not_and_the_normaliser_ignores_both() -> None:
    """Live capture and offline generation label their records differently. Neither set of
    extra keys reaches the normalised event, which is why ingest is unaffected."""
    live = {key for record in _raw(CAPTURE) for key in record}
    generated = {key for record in _raw(SYNTHETIC) for key in record}
    assert {"pkt_src", "direction"} <= live, "live capture records where a packet came from"
    assert "pcap_cnt" in generated - live, "an offline-pcap artefact live capture never emits"
    assert len(_rows(CAPTURE)) == len(_raw(CAPTURE)), "and every record still normalises"
