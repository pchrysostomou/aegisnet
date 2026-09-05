"""What real Suricata output does that the synthetic corpus does not (ADR-021, ADR-009).

ADR-009 deferred the lab with a promise: "any divergence from real Suricata output is a
Milestone 2 finding". These tests are that finding, written as executable statements over
the committed lab capture (`samples/lab/lab-capture-01.ndjson`, real Suricata 8.0.6 output
from `infra/lab/`).

Three of them describe things the project gets **wrong** today. They are written to pass
against the current behaviour on purpose: they pin the divergence so it cannot drift
unnoticed, and they hand the fix a fixture to work against. Each one names the defect it
records; `docs/evaluation.md` §9 explains what the fix is and why it was not made here.
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


def test_flow_records_are_stamped_when_they_are_emitted_not_when_they_happened() -> None:
    """Defect L-F1 (docs/evaluation.md §9): a flow event's `timestamp` is the flow manager's
    emission time. The lab's beacon checks in every five seconds to the millisecond, and the
    record timestamps say otherwise, so D-004 cannot see a real beacon at all."""
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
    assert seen_jitter > limit, "but the timestamps the detector reads are not"
    # And this is the consequence: the rule stays silent on a textbook beacon.
    assert get_detector("D-004").run(_window(_rows(CAPTURE))) == []


def test_a_real_dns_request_carries_an_rcode_and_the_synthetic_corpus_does_not() -> None:
    """Defect L-F2 (docs/evaluation.md §9): Suricata 8 logs EVE DNS v3, where request and
    response records both carry `rcode`. D-003 reads "has an rcode" as "is an answer", so on
    real output every record looks like an answer: no query name is ever tallied and the
    client attribution flips from the asker to the resolver."""
    requests = [
        r for r in _raw(CAPTURE) if r["event_type"] == "dns" and r["dns"]["type"] == "request"
    ]
    assert requests, "the capture contains DNS requests"
    assert all("rcode" in r["dns"] for r in requests)
    assert all(r["dns"]["version"] == 3 for r in requests)

    synthetic = [r for r in _raw(SYNTHETIC) if r.get("event_type") == "dns"]
    queries = [r for r in synthetic if r["dns"]["type"] == "query"]
    assert queries and not any("rcode" in r["dns"] for r in queries)
    assert all(r["dns"]["version"] == 2 for r in synthetic), "the generator writes the v2 shape"

    # The consequence, on the capture the lab actually took.
    rows = _rows(CAPTURE)
    dns = [r for r in rows if r.event_type is EventType.dns]
    assert dns and all(r.dns_rcode is not None for r in dns), "every record looks like an answer"
    long_labels = {
        r.dns_query
        for r in dns
        if r.dns_query and any(len(label) >= 40 for label in r.dns_query.split("."))
    }
    assert len(long_labels) >= 20, "the lab did generate an unmistakable tunnel shape"
    assert get_detector("D-003").run(_window(rows)) == [], "and D-003 still says nothing"


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
