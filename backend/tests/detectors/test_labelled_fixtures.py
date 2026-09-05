"""Every labelled T1 fixture (docs/evaluation.md §3) runs through its detector: positives
must fire on the labelled entity at or above the labelled severity, negatives must stay
silent, and the committed fixtures must match their generator byte for byte."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

from aegisnet.domain.detectors import get_detector, score
from tests.conftest import REPO_ROOT
from tests.detectors.conftest import LABELLED, labelled_case_dirs, load_case

pytestmark = pytest.mark.unit

CASE_DIRS = labelled_case_dirs()


def _run(directory: Path) -> tuple[dict, list]:
    case = load_case(directory)
    detector = get_detector(str(case.labels["rule_id"]))
    return case.labels, detector.run(case.window)


@pytest.mark.parametrize("directory", CASE_DIRS, ids=lambda p: f"{p.parent.name}/{p.name}")
def test_labelled_case(directory: Path) -> None:
    labels, results = _run(directory)
    if labels["expected"] == "no_detection":
        assert results == [], f"{labels['case_id']} must not alert: {results}"
        return
    assert labels["expected"] == "detection"
    entity = labels["expected_entity"]
    matching = [
        r
        for r in results
        if r.entity.type.value == entity["type"] and r.entity.value == entity["value"]
    ]
    assert (
        len(matching) == 1
    ), f"{labels['case_id']}: expected one result for {entity}, got {results}"
    others = [r for r in results if r not in matching]
    assert others == [], f"{labels['case_id']}: unexpected extra results {others}"
    [result] = matching
    severity = score(get_detector(labels["rule_id"]).spec.base_severity, result.signal_strength)
    assert severity.value >= int(labels["expected_min_severity"])


def test_every_shipped_rule_has_at_least_three_positive_and_three_negative_cases() -> None:
    by_rule: dict[str, dict[str, int]] = {}
    for directory in CASE_DIRS:
        rule = directory.parent.parent.name[:5]  # "D-001-port-scan" -> "D-001"
        by_rule.setdefault(rule, {"positive": 0, "negative": 0})[directory.parent.name] += 1
    assert by_rule == {
        "D-001": {"positive": 3, "negative": 4},
        "D-002": {"positive": 3, "negative": 4},
        "D-003": {"positive": 3, "negative": 3},
        "D-004": {"positive": 3, "negative": 4},
        "D-005": {"positive": 3, "negative": 4},
    }


def test_the_committed_fixtures_match_their_generator(tmp_path: Path) -> None:
    spec = importlib.util.spec_from_file_location(
        "gen_labelled_fixtures", REPO_ROOT / "tools" / "gen_labelled_fixtures.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses resolve string annotations via sys.modules
    spec.loader.exec_module(module)
    module.write_all(tmp_path)
    regenerated = sorted(p.relative_to(tmp_path) for p in tmp_path.rglob("*") if p.is_file())
    committed = sorted(p.relative_to(LABELLED) for p in LABELLED.rglob("*") if p.is_file())
    assert regenerated == committed
    for relative in committed:
        assert (tmp_path / relative).read_bytes() == (LABELLED / relative).read_bytes(), relative


def test_every_fixture_flow_starts_before_it_is_emitted() -> None:
    """The invariant the fixtures encode since ADR-022: a flow record carries the conversation
    in `flow.start` and is stamped when Suricata would have emitted it. Without this, D-004's
    cases pass for the wrong reason — which is exactly what happened until the lab ran."""
    seen = 0
    for directory in CASE_DIRS:
        for line in (directory / "events.ndjson").read_text(encoding="utf-8").splitlines():
            record = json.loads(line)
            if record["event_type"] != "flow":
                continue
            seen += 1
            start = record["flow"]["start"].replace("+0000", "+00:00")
            emitted = record["timestamp"].replace("+0000", "+00:00")
            assert start <= emitted, f"{directory.name}: a flow emitted before it began"
    assert seen > 100, "the cases are mostly flows; this would be vacuous otherwise"
