"""``make eval`` part two: score correlation on the committed multi-stage scenario (ADR-025).

The scenario is one host doing four things in an hour and a second host doing an unrelated
one at the same time. Every rule runs over it on its own grid, exactly as a sweep would slice
it, the results become alerts, `domain/correlation.group` groups them, and
`domain/correlation_eval` scores that grouping against the ground truth committed beside the
data. The numbers land in `docs/evaluation.md` §8 between the ``correlation`` markers, and a
test pins the committed block to what this produces.

Two things are worth being explicit about, because they bound what the numbers mean.

**The baseline is derived here, not read from a database.** D-005 compares an hour against an
asset's history, and a rule that abstains cannot be scored. The history hours in the scenario
are summarised with the same pure function the baseline job uses, so this harness sees the
baseline `make demo-scenario` would have written — but it is a reconstruction, and the
end-to-end demo is what proves the database path agrees.

**Severity is the rule's base severity.** The sweep raises severity by the asset's criticality
(ADR-018); there is no asset inventory in a pure run. That affects the escalation arithmetic
only through `max(member severities)`, and the property being measured — that three or more
distinct rules escalate a case — does not depend on where the members started.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from ipaddress import ip_network
from pathlib import Path
from typing import Any
from uuid import NAMESPACE_URL, UUID, uuid5

from aegisnet.adapters.files.labelled import load_corpus
from aegisnet.domain.correlation import AlertFacts, Proposal, group
from aegisnet.domain.correlation_eval import GroupingMetrics, markdown_table, score
from aegisnet.domain.detectors import Detector, EventWindow, default_detectors, summarize
from aegisnet.domain.detectors.addresses import is_internal
from aegisnet.domain.detectors.model import Baseline, DetectionResult
from aegisnet.domain.enums import BaselineMetric, EventType
from aegisnet.domain.ports import EventRow
from aegisnet.services.detection_service import grid_buckets

BEGIN = "<!-- correlation:begin -->"
END = "<!-- correlation:end -->"
_BLOCK = re.compile(re.escape(BEGIN) + r".*?" + re.escape(END), re.DOTALL)

SCENARIO_FILE = Path("samples/scenarios/multi-stage-01.ndjson")
MANIFEST_FILE = Path("samples/scenarios/multi-stage-01.manifest.json")
RESULTS_DOC = Path("docs/evaluation.md")
LAYOUT = (SCENARIO_FILE, MANIFEST_FILE, RESULTS_DOC)

BASELINE_WINDOW_DAYS = 7


class ScenarioEvalError(ValueError):
    pass


def repository_root(start: Path) -> Path:
    """The nearest directory at or above ``start`` that holds the whole layout."""
    for candidate in (start, *start.parents):
        if all((candidate / relative).exists() for relative in LAYOUT):
            return candidate
    raise ScenarioEvalError(
        "not inside a repository checkout: "
        + ", ".join(str(relative) for relative in LAYOUT)
        + " were not all found at or above the working directory"
    )


@dataclass(frozen=True, slots=True)
class ScenarioReport:
    metrics: GroupingMetrics
    proposals: tuple[Proposal, ...]
    truth: Mapping[UUID, str]
    """Which scenario each alert belongs to, as declared by the ground truth."""
    rules_fired: tuple[str, ...]
    alerts_produced: int
    events: int
    rejected: int
    sha256: str
    scenario_names: tuple[str, ...]
    window_start: datetime
    window_end: datetime

    @property
    def severities(self) -> tuple[int, ...]:
        return tuple(proposal.severity().value for proposal in self.proposals)

    @property
    def escalated(self) -> tuple[bool, ...]:
        return tuple(proposal.severity().escalated for proposal in self.proposals)


def _aware(raw: str) -> datetime:
    moment = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    if moment.tzinfo is None:
        raise ScenarioEvalError(f"{raw} is not timezone-aware")
    return moment


def baselines_from_history(
    events: Sequence[EventRow], *, address: str, before: datetime
) -> dict[str, Baseline]:
    """The baseline the recompute job would have written for this address.

    Same arithmetic, same source data, same filters: flow events only, with a destination, to a
    non-internal address, from inside the asset's networks, over the complete hours of the
    seven days before the scenario's window (ADR-019). Any divergence from
    `adapters/db/event_read_store.hourly_outbound_bytes` would mean the published §8 numbers
    described a baseline D-005 was never compared against.
    """
    # The job floors its end to the hour, because the current hour is still being written.
    end = before.replace(minute=0, second=0, microsecond=0)
    start = end - timedelta(days=BASELINE_WINDOW_DAYS)
    hours: dict[datetime, int] = {}
    for event in events:
        # Every clause the SQL applies, in the same order (`event_read_store`), because a
        # reconstruction that counted different events would publish numbers describing a
        # baseline D-005 was never compared against.
        if event.event_type is not EventType.flow:
            continue
        if not (start <= event.event_time < end):
            continue
        if event.bytes_toserver is None or event.dest_ip is None:
            continue
        if event.src_ip is None or event.src_ip not in ip_network(address):
            continue
        if is_internal(str(event.dest_ip)):
            continue
        hour = event.event_time.replace(minute=0, second=0, microsecond=0)
        hours[hour] = hours.get(hour, 0) + event.bytes_toserver
    if not hours:
        return {}
    totals = [total for _hour, total in sorted(hours.items())]
    summary = summarize(totals)
    return {
        address: Baseline(
            metric=BaselineMetric.outbound_bytes_per_hour,
            window_days=BASELINE_WINDOW_DAYS,
            mean=summary.mean,
            stddev=summary.stddev,
            p95=summary.p95,
            sample_count=summary.sample_count,
        )
    }


def _alert_id(result: DetectionResult) -> UUID:
    """A stable id for an alert this harness never stored. Derived from the dedup key, which
    is what the database would have made unique anyway."""
    return uuid5(NAMESPACE_URL, f"aegisnet:scenario:{result.dedup_key}")


def facts_of(result: DetectionResult, *, severity: int) -> AlertFacts:
    return AlertFacts(
        id=_alert_id(result),
        rule_id=result.rule_id,
        severity=severity,
        entity_type=result.entity.type,
        entity_value=result.entity.value,
        first_seen=result.first_seen,
        last_seen=result.last_seen,
    )


def detect(
    events: Sequence[EventRow],
    detectors: Sequence[Detector],
    *,
    start: datetime,
    end: datetime,
    baselines: dict[str, Baseline],
) -> list[AlertFacts]:
    """Every rule over the window on its own grid, as a sweep would slice it."""
    facts: list[AlertFacts] = []
    for detector in detectors:
        for bucket_start, bucket_end in grid_buckets(start, end, detector.spec.window_seconds):
            window = EventWindow(
                bucket_start,
                bucket_end,
                tuple(e for e in events if bucket_start <= e.event_time < bucket_end),
                baselines,
            )
            facts += [
                facts_of(result, severity=detector.spec.base_severity)
                for result in detector.run(window)
            ]
    return sorted(facts, key=lambda fact: (fact.first_seen, fact.id.int))


def expected_alert_id(scenario_id: str, rule_id: str) -> UUID:
    """The id of an alert a scenario said it would produce.

    Stable and independent of whether it appeared, so a rule that stops firing shows up as a
    pair the grouping failed to make rather than vanishing from the arithmetic entirely.
    """
    return uuid5(NAMESPACE_URL, f"aegisnet:scenario:expected:{scenario_id}:{rule_id}")


def label(facts: Sequence[AlertFacts], truth_doc: dict[str, Any]) -> dict[UUID, str]:
    """Which scenario each alert belongs to, read from the ground truth rather than derived
    from the grouping key.

    This is the whole reason the numbers mean anything. Two of the scenarios share an entity
    and differ only in when they happened; a truth taken from the entity would call them one
    story, and grouping precision and case contamination could then never be anything but
    perfect whatever correlation did.
    """
    windows = [
        (doc["id"], doc["entity"], _aware(doc["window"]["from"]), _aware(doc["window"]["to"]))
        for doc in truth_doc["scenarios"]
    ]
    truth: dict[UUID, str] = {}
    for fact in facts:
        owner = next(
            (
                scenario_id
                for scenario_id, entity, start, end in windows
                if fact.key == entity and start <= fact.first_seen < end
            ),
            None,
        )
        if owner is None:
            raise ScenarioEvalError(
                f"no scenario claims {fact.rule_id} on {fact.key} at {fact.first_seen.isoformat()}"
            )
        truth[fact.id] = owner
    # Everything the scenarios said would fire, whether it did or not.
    for doc in truth_doc["scenarios"]:
        for rule_id in doc["expected_rules"]:
            produced = any(
                truth.get(fact.id) == doc["id"] and fact.rule_id == rule_id for fact in facts
            )
            if not produced:
                truth[expected_alert_id(doc["id"], rule_id)] = doc["id"]
    return truth


def run_scenario(
    scenario: Path, manifest_path: Path, *, detectors: Sequence[Detector] | None = None
) -> ScenarioReport:
    if not scenario.is_file():
        raise ScenarioEvalError(f"scenario not found: {scenario}")
    manifest = json.loads(manifest_path.read_text())
    truth_doc = manifest["ground_truth"]
    window = manifest["sweep_window"]
    start, end = _aware(window["from"]), _aware(window["to"])

    events, rejected = load_corpus(scenario)
    if rejected:
        raise ScenarioEvalError(f"{rejected} scenario lines were rejected; the data is the spec")

    baselines = baselines_from_history(
        events, address=manifest["history"]["asset"], before=_aware(manifest["baseline_until"])
    )
    facts = detect(
        events,
        default_detectors() if detectors is None else detectors,
        start=start,
        end=end,
        baselines=baselines,
    )

    truth = label(facts, truth_doc)

    proposals = group(facts)
    metrics = score(proposals, truth, incidents_expected=truth_doc["expected_incidents"])
    return ScenarioReport(
        metrics=metrics,
        proposals=tuple(proposals),
        truth=truth,
        rules_fired=tuple(sorted({fact.rule_id for fact in facts})),
        alerts_produced=len(facts),
        events=len(events),
        rejected=rejected,
        sha256=hashlib.sha256(scenario.read_bytes()).hexdigest(),
        scenario_names=tuple(s["id"] for s in truth_doc["scenarios"]),
        window_start=start,
        window_end=end,
    )


def render(report: ScenarioReport) -> str:
    """The block between the correlation markers: provenance, the table, what was produced."""
    lines = [
        f"Generated by `make eval` from `{SCENARIO_FILE.name}` "
        f"({report.events} events, {report.rejected} rejected, sha256 "
        f"`{report.sha256[:12]}`) over "
        f"{report.window_start.isoformat().replace('+00:00', 'Z')} to "
        f"{report.window_end.isoformat().replace('+00:00', 'Z')}, "
        f"covering {len(report.scenario_names)} scenarios: "
        + ", ".join(f"`{name}`" for name in report.scenario_names)
        + ".",
        "",
        markdown_table(report.metrics),
        "",
        f"{report.alerts_produced} alerts from {len(report.rules_fired)} rules "
        f"({', '.join(report.rules_fired)}) became {report.metrics.incidents_produced} incidents; "
        f"{report.metrics.alerts} alerts were scored, counting any a scenario expected and no "
        "rule produced:",
        "",
        "| Case | Entity | Rules | Alerts | Severity |",
        "|---|---|---|---|---|",
    ]
    for index, proposal in enumerate(report.proposals, start=1):
        severity = proposal.severity()
        escalated = " (escalated)" if severity.escalated else ""
        lines.append(
            f"| {index} | `{proposal.key}` | {', '.join(proposal.rule_ids)} | "
            f"{len(proposal.alerts)} | {severity.value}{escalated} |"
        )
    lines += [
        "",
        "Severity here is each rule's base severity. The stored formula (ADR-018) also moves it "
        "by the asset's criticality and by how far past its threshold the rule went, and a pure "
        "run has neither an inventory nor a stored alert; both cases come out at 5 here, by "
        "different arithmetic. The escalation the table shows is correlation's own, for three "
        "or more distinct rules on one entity.",
    ]
    return "\n".join(lines)


def replace_results(document: str, block: str) -> str:
    if BEGIN not in document or END not in document:
        raise ScenarioEvalError("the correlation markers are missing from the document")
    return _BLOCK.sub(lambda _: f"{BEGIN}\n{block}\n{END}", document, count=1)


__all__ = [
    "BEGIN",
    "END",
    "MANIFEST_FILE",
    "RESULTS_DOC",
    "SCENARIO_FILE",
    "ScenarioEvalError",
    "ScenarioReport",
    "baselines_from_history",
    "render",
    "replace_results",
    "repository_root",
    "run_scenario",
]
