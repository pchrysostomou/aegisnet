"""The committed multi-stage scenario is the Milestone 3 acceptance criterion, as data.

`docs/delivery-plan.md` M3 asks for a scripted scenario — scan, then auth failures, then
beaconing, then a large upload from one asset — that produces **exactly one incident with four
alerts from four distinct rules and an escalated severity**. These tests assert that sentence
against the bytes in `samples/scenarios/`, so the claim cannot drift from the data, and pin
the §8 block so a change to either has to bring the document with it.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from aegisnet.adapters.files.registry import load_registry
from aegisnet.services.scenario_service import (
    BEGIN,
    END,
    MANIFEST_FILE,
    RESULTS_DOC,
    SCENARIO_FILE,
    render,
    run_scenario,
)
from tests.conftest import REPO_ROOT

pytestmark = pytest.mark.unit

DATASET_ID = "demo-scenario-multi-stage-01"
SCENARIO = REPO_ROOT / SCENARIO_FILE
MANIFEST = REPO_ROOT / MANIFEST_FILE


@pytest.fixture(scope="module")
def report():  # type: ignore[no-untyped-def]
    return run_scenario(SCENARIO, MANIFEST)


def test_the_scenario_produces_one_escalated_case_of_four_rules(report) -> None:  # type: ignore[no-untyped-def]
    """The acceptance criterion itself."""
    compromise = next(p for p in report.proposals if p.entity_value == "10.10.0.42")
    assert compromise.rule_ids == ("D-001", "D-002", "D-004", "D-005")
    assert compromise.distinct_rule_count == 4
    assert len(compromise.alerts) == 4
    severity = compromise.severity()
    assert severity.escalated is True
    assert severity.value == min(5, severity.member_max + 1)


def test_the_two_unrelated_stories_get_their_own_cases(report) -> None:  # type: ignore[no-untyped-def]
    """Contamination is only meaningfully zero if something could have contaminated it.

    One of the three scenarios is the *same host* six hours later. It shares the compromise's
    entity key and must still be its own case, which is what gives the precision and
    contamination figures something to be wrong about.
    """
    assert report.metrics.incidents_produced == 3
    bystander = next(p for p in report.proposals if p.entity_value == "10.10.0.77")
    assert bystander.rule_ids == ("D-001",)
    assert bystander.severity().escalated is False
    same_host = [p for p in report.proposals if p.entity_value == "10.10.0.42"]
    assert len(same_host) == 2, "one entity, two stories, two cases"
    assert sorted(len(p.alerts) for p in same_host) == [1, 4]


def test_every_correlation_target_in_the_evaluation_plan_is_met(report) -> None:  # type: ignore[no-untyped-def]
    metrics = report.metrics
    assert metrics.precision == 1.0 and metrics.recall == 1.0
    assert abs(metrics.fragmentation - 1.0) <= 0.2, "docs/evaluation.md §4 target"
    assert metrics.contamination == 0.0
    assert metrics.contaminated_incidents == 0


def test_the_scenario_is_clean_input_and_all_four_rules_speak(report) -> None:  # type: ignore[no-untyped-def]
    assert report.rejected == 0, "the data is the spec; a rejected line is a broken fixture"
    assert report.rules_fired == ("D-001", "D-002", "D-004", "D-005")
    assert report.events == 303
    assert report.alerts_produced == 6


def test_the_metrics_can_actually_fail(report) -> None:  # type: ignore[no-untyped-def]
    """The measurement earns its place only if a worse grouping scores worse.

    Ground truth is declared by scenario window, never read off the entity key, so widening
    correlation's join gap until the morning compromise swallows the afternoon scan on the same
    host must cost precision and must show up as contamination. A harness whose truth came from
    the key being scored would report 1.00 and 0.00 here, which is the trap this guards.
    """
    from datetime import timedelta

    from aegisnet.domain.correlation import group
    from aegisnet.domain.correlation_eval import score

    facts = [alert for proposal in report.proposals for alert in proposal.alerts]
    truth = {alert.id: report.truth[alert.id] for alert in facts}
    merged = score(group(facts, gap=timedelta(hours=24)), truth, incidents_expected=3)

    assert merged.incidents_produced == 2, "the two same-entity stories were folded into one"
    assert merged.precision < 1.0, "pairs that do not belong together were put together"
    assert merged.contamination > 0.0, "a case now holds alerts from two scenarios"
    assert merged.recall == 1.0, "over-merging never loses a pair that belonged"
    # And the shipped policy does not do that.
    assert report.metrics.precision == 1.0 and report.metrics.contamination == 0.0


def test_d005_had_a_real_baseline_rather_than_abstaining() -> None:
    """The rule that abstains without history is the one this scenario had to feed. If the
    history stopped producing a baseline, D-005 would fall silent and the four-rule claim
    would quietly become three."""
    from aegisnet.adapters.files.labelled import load_corpus
    from aegisnet.services.scenario_service import _aware, baselines_from_history

    manifest = json.loads(MANIFEST.read_text())
    events, _ = load_corpus(SCENARIO)
    baselines = baselines_from_history(
        events,
        address=manifest["history"]["asset"],
        before=_aware(manifest["baseline_until"]),
    )
    (baseline,) = baselines.values()
    assert baseline.sample_count >= 24, "D-005's min_samples"
    assert baseline.mean > 0 and baseline.stddev > 0
    # The spike has to clear the absolute floor, not just the asset's own history: a scenario
    # whose "large upload" only beat a tiny mean would be testing the arithmetic, not the rule.
    assert baseline.mean < 50 * 1024 * 1024


def test_the_registry_entry_matches_the_committed_file() -> None:
    entry = load_registry(REPO_ROOT / "samples").get(DATASET_ID)
    assert entry is not None, f"{DATASET_ID} is not registered"
    assert entry.path == "scenarios/multi-stage-01.ndjson"
    assert entry.sha256 == hashlib.sha256(SCENARIO.read_bytes()).hexdigest()


def test_the_manifest_describes_the_file_beside_it() -> None:
    manifest = json.loads(MANIFEST.read_text())
    lines = SCENARIO.read_text().splitlines()
    assert manifest["events"] == len(lines)
    assert manifest["sha256"] == hashlib.sha256(SCENARIO.read_bytes()).hexdigest()
    assert manifest["ground_truth"]["expected_incidents"] == 3
    assert [s["id"] for s in manifest["ground_truth"]["scenarios"]] == [
        "multi-stage-compromise",
        "unrelated-scan",
        "later-unrelated-scan",
    ]
    # Two scenarios share an entity and are separated only by time; that is deliberate.
    entities = [s["entity"] for s in manifest["ground_truth"]["scenarios"]]
    assert len(set(entities)) < len(entities)


def test_the_committed_results_block_is_what_the_harness_produces(report) -> None:  # type: ignore[no-untyped-def]
    """`make eval` writes this block. If a rule, the scenario or the grouping policy changes,
    the document has to change in the same commit."""
    document = (REPO_ROOT / RESULTS_DOC).read_text(encoding="utf-8")
    start = document.index(BEGIN) + len(BEGIN)
    committed = document[start : document.index(END)].strip()
    assert committed == render(report).strip()


def test_the_scenario_never_leaves_the_documentation_address_ranges() -> None:
    """docs/evaluation.md §1: nothing routable, ever."""
    import ipaddress

    allowed = [
        ipaddress.ip_network(cidr)
        for cidr in ("10.0.0.0/8", "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
    ]
    for raw in SCENARIO.read_text().splitlines():
        record = json.loads(raw)
        for key in ("src_ip", "dest_ip"):
            address = ipaddress.ip_address(record[key])
            assert any(address in network for network in allowed), f"{address} is routable"


def test_the_generator_is_deterministic(tmp_path: Path) -> None:
    """Regenerating from the same seed must reproduce the committed bytes; that is what makes
    the sha256 in the registry a fact rather than a snapshot."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "gen_demo_scenario", REPO_ROOT / "tools" / "gen_demo_scenario.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    _count, digest = module.write_all(tmp_path / "s.ndjson", tmp_path / "s.manifest.json")
    assert digest == hashlib.sha256(SCENARIO.read_bytes()).hexdigest()
    assert (tmp_path / "s.ndjson").read_bytes() == SCENARIO.read_bytes()
