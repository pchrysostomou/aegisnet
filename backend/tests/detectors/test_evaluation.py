"""``make eval`` (ADR-020): the verdict rules, the metrics arithmetic, the document block,
and the pin that keeps docs/evaluation.md §8 equal to what the harness produces."""

from __future__ import annotations

import json
import shutil
from datetime import UTC, datetime
from pathlib import Path

import pytest

from aegisnet.cli import main
from aegisnet.domain.detectors import DetectionResult, Entity, EventWindow, get_detector
from aegisnet.domain.detectors.evaluation import (
    BenignRun,
    CaseOutcome,
    Expectation,
    RuleMetrics,
    judge,
    markdown_table,
    summarize,
)
from aegisnet.domain.enums import EntityType
from aegisnet.services.evaluation_service import (
    BEGIN,
    CASES_DIR,
    CORPUS_FILE,
    END,
    RESULTS_DOC,
    EvaluationError,
    evaluate_benign,
    generator_seed,
    recorded_commit,
    render,
    replace_results,
    repository_root,
    run_evaluation,
)
from tests.conftest import REPO_ROOT
from tests.detectors.conftest import LABELLED, flow_row

pytestmark = pytest.mark.unit

CORPUS = REPO_ROOT / "samples" / "synthetic" / "benign-baseline-01.ndjson"
DOC = REPO_ROOT / "docs" / "evaluation.md"
BUCKET = datetime(2026, 9, 1, 10, tzinfo=UTC)
SCANNER = Entity(EntityType.src_ip, "10.10.0.99")
OTHER = Entity(EntityType.src_ip, "10.10.0.5")


def _result(entity: Entity, signal: float = 1.0) -> DetectionResult:
    return DetectionResult(
        rule_id="D-001",
        rule_version=1,
        entity=entity,
        window_bucket=BUCKET,
        first_seen=BUCKET,
        last_seen=BUCKET,
        signal_strength=signal,
        confidence=0.9,
        event_count=40,
        evidence={"ports": 40},
        samples=(),
    )


POSITIVE = Expectation("D-001", "pos", "positive", SCANNER, 3)
NEGATIVE = Expectation("D-001", "neg", "negative", None, None)


def test_a_positive_case_is_a_true_positive_only_for_exactly_the_expected_alert() -> None:
    assert judge(POSITIVE, [_result(SCANNER)], base_severity=3).verdict == "TP"
    assert judge(POSITIVE, [], base_severity=3).reason == "no alert"
    wrong = judge(POSITIVE, [_result(OTHER)], base_severity=3)
    assert wrong.verdict == "FN" and "0 alert(s) on the expected entity" in wrong.reason
    extra = judge(POSITIVE, [_result(SCANNER), _result(OTHER)], base_severity=3)
    assert extra.verdict == "FN" and "other entities" in extra.reason
    weak = judge(POSITIVE, [_result(SCANNER, signal=0.0)], base_severity=1)
    assert weak.verdict == "FN" and weak.reason.startswith("severity ")


def test_a_negative_case_is_a_false_positive_on_any_alert() -> None:
    assert judge(NEGATIVE, [], base_severity=3).verdict == "TN"
    noisy = judge(NEGATIVE, [_result(OTHER)], base_severity=3)
    assert noisy.verdict == "FP" and noisy.fired == 1
    with pytest.raises(ValueError, match="names its entity"):
        judge(Expectation("D-001", "x", "positive", None, None), [], base_severity=3)


def test_metrics_arithmetic_and_undefined_ratios() -> None:
    outcomes = [
        CaseOutcome(POSITIVE, 1, True, ""),
        CaseOutcome(POSITIVE, 0, False, "no alert"),
        CaseOutcome(NEGATIVE, 0, True, ""),
        CaseOutcome(Expectation("D-002", "n", "negative", None, None), 2, False, "alerted"),
    ]
    benign = [BenignRun("D-001", 2000, 1, 12), BenignRun("D-003", 2000, 0, 3, "abstains")]
    metrics = summarize(outcomes, benign)
    assert [m.rule_id for m in metrics] == ["D-001", "D-002", "D-003"]
    one, two, three = metrics
    assert (one.tp, one.fp, one.fn, one.tn, one.cases) == (1, 0, 1, 1, 3)
    assert one.precision == 1.0 and one.recall == 0.5 and one.f1 == pytest.approx(2 / 3)
    assert one.alerts_per_10k == 5.0
    assert (two.fp, two.precision, two.recall, two.f1, two.alerts_per_10k) == (
        1,
        0.0,
        None,
        None,
        None,
    )
    assert three.cases == 0 and three.benign_note == "abstains"
    table = markdown_table(metrics, corpus="T1/T2")
    assert "| D-001 | T1/T2 | 3 | 1 | 0 | 1 | 1 | 1.00 | 0.50 | 0.67 | 5.0 |" in table
    assert "| D-002 | T1/T2 | 1 | 0 | 1 | 0 | 0 | 0.00 | n/a | n/a | n/a |" in table
    assert "0.0 (abstains)" in table
    assert RuleMetrics("D-009", 0, 0, 0, 0, 0, 0).benign_events == 0


def test_benign_scoring_runs_every_rule_on_its_own_grid() -> None:
    rows = [
        flow_row(BUCKET.replace(minute=m), "10.10.0.1", "203.0.113.9", 443) for m in (1, 31, 59)
    ]
    detectors = {r: get_detector(r) for r in ("D-001", "D-004")}
    runs = evaluate_benign(rows, detectors)
    assert [(r.rule_id, r.events, r.alerts, r.buckets) for r in runs] == [
        ("D-001", 3, 0, 6),
        ("D-004", 3, 0, 1),
    ]
    assert [r.rule_id for r in evaluate_benign([], detectors)] == ["D-001", "D-004"]


def test_replace_results_rewrites_only_the_marked_block() -> None:
    document = f"# title\n\n{BEGIN}\nold\n{END}\n\ntail\n"
    assert replace_results(document, "new") == f"# title\n\n{BEGIN}\nnew\n{END}\n\ntail\n"
    with pytest.raises(EvaluationError, match="markers"):
        replace_results("no markers here", "x")


def test_the_committed_cases_all_meet_their_labels_and_the_document_is_current() -> None:
    """The pin: docs/evaluation.md §8 must equal what the harness renders now. If this
    fails after a rule change, run ``make eval`` and commit the document.

    The commit is read back out of the document rather than resolved from git, so the pin
    holds the *numbers* without needing a history — CI checks out one commit deep, and a test
    that skipped there would pin nothing. Whether that commit is the right one is
    `test_the_published_commit_is_the_one_the_corpus_was_last_changed_in`.
    """
    report = run_evaluation(LABELLED, CORPUS)
    assert report.failures == ()
    assert len(report.outcomes) == 34 and report.corpus_events == 2000
    assert {m.rule_id for m in report.metrics} == {"D-001", "D-002", "D-003", "D-004", "D-005"}
    assert all(m.precision == m.recall == 1.0 for m in report.metrics)
    document = DOC.read_text(encoding="utf-8")
    block = render(report, corpus_commit=recorded_commit(document))
    assert replace_results(document, block) == document, "run `make eval`"


def test_the_published_provenance_is_complete_and_not_invented() -> None:
    """§6 asks a published number to carry the command, the corpus sha256, the rule versions
    and the seed. Three of those were there from Chunk 12; this asserts all four, because a
    reproducibility requirement nothing checks is a paragraph, not a requirement."""
    document = DOC.read_text(encoding="utf-8")
    report = run_evaluation(LABELLED, CORPUS)

    assert report.corpus_seed == 20260905, "the seed comes from the manifest beside the corpus"
    assert report.rule_versions == tuple((f"D-00{n}", 1) for n in range(1, 6))
    assert generator_seed(CORPUS.with_name("nothing-here.ndjson")) is None

    published = render(report, corpus_commit=recorded_commit(document))
    assert "make eval" in published, "the command"
    assert f"`{report.corpus_sha256[:12]}`" in published, "the corpus hash"
    assert "generator seed `20260905`" in published, "the seed"
    assert "D-005 v1" in published, "the rule versions"

    with pytest.raises(EvaluationError, match="forty hex"):
        render(report, corpus_commit="not-a-commit")
    with pytest.raises(EvaluationError, match="publishes no corpus commit"):
        recorded_commit("a document with no provenance line")


def test_run_evaluation_refuses_missing_inputs(tmp_path: Path) -> None:
    with pytest.raises(EvaluationError, match="no labelled cases"):
        run_evaluation(tmp_path, CORPUS)
    with pytest.raises(EvaluationError, match="corpus not found"):
        run_evaluation(LABELLED, tmp_path / "missing.ndjson")


def _checkout(tmp_path: Path) -> Path:
    """A miniature repository layout: the real cases and corpus, a tiny results document."""
    shutil.copytree(LABELLED, tmp_path / CASES_DIR)
    (tmp_path / CORPUS_FILE).parent.mkdir(parents=True)
    shutil.copyfile(CORPUS, tmp_path / CORPUS_FILE)
    # The manifest travels with the corpus, because the seed the provenance line publishes
    # comes out of it and a checkout missing it is not the layout the command expects.
    manifest = CORPUS.with_name(f"{CORPUS.stem}.manifest.json")
    shutil.copyfile(manifest, (tmp_path / CORPUS_FILE).with_name(manifest.name))
    (tmp_path / RESULTS_DOC).parent.mkdir(parents=True)
    (tmp_path / RESULTS_DOC).write_text(f"intro\n{BEGIN}\nstale\n{END}\n", encoding="utf-8")
    return tmp_path


def test_repository_root_is_found_above_the_working_directory(tmp_path: Path) -> None:
    root = _checkout(tmp_path)
    assert repository_root(root / "backend" / "src") == root
    assert repository_root(root) == root
    with pytest.raises(EvaluationError, match="not inside a repository checkout"):
        repository_root(Path("/"))


FAKE_COMMIT = "0" * 39 + "1"


def test_the_cli_takes_no_paths_writes_the_block_and_needs_no_settings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    for name in ("SECRET_KEY", "POSTGRES_APP_PASSWORD", "REDIS_PASSWORD", "ENV"):
        monkeypatch.delenv(name, raising=False)
    root = _checkout(tmp_path)
    # The miniature checkout is not a git repository, and this test is about the command's
    # paths and its writer. What git actually answers is `tests/unit/test_provenance.py`.
    monkeypatch.setattr("aegisnet.cli.corpus_commit", lambda _root, _paths: FAKE_COMMIT)
    monkeypatch.chdir(root / "backend")
    assert main(["eval-detectors"]) == 0
    written = (root / RESULTS_DOC).read_text(encoding="utf-8")
    assert "stale" not in written and "| D-005 |" in written and written.startswith("intro\n")
    assert "Every labelled case met its label." in capsys.readouterr().out
    # --no-write leaves the document alone; --json reports the same numbers as data.
    (root / RESULTS_DOC).write_text("untouched", encoding="utf-8")
    assert main(["eval-detectors", "--no-write", "--json"]) == 0
    assert (root / RESULTS_DOC).read_text(encoding="utf-8") == "untouched"
    payload = json.loads(capsys.readouterr().out)
    assert payload["failures"] == [] and payload["corpus"]["events"] == 2000
    assert payload["corpus"]["commit"] == FAKE_COMMIT and payload["corpus"]["seed"] == 20260905
    assert payload["rule_versions"] == {f"D-00{n}": 1 for n in range(1, 6)}
    assert {m["rule_id"] for m in payload["metrics"]} == {
        "D-001",
        "D-002",
        "D-003",
        "D-004",
        "D-005",
    }


def test_the_cli_refuses_to_publish_a_number_it_cannot_place_in_history(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A checkout with the right layout but no git history cannot answer "which commit are
    these bytes from", so the command stops instead of publishing a table with no provenance.
    The document it would have written is left exactly as it was."""
    root = _checkout(tmp_path)
    monkeypatch.chdir(root / "backend")
    assert main(["eval-detectors"]) == 1
    assert "git" in capsys.readouterr().err
    assert (root / RESULTS_DOC).read_text(encoding="utf-8").count("stale") == 1


def test_the_cli_refuses_to_run_outside_a_checkout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    assert main(["eval-detectors"]) == 1
    assert "not inside a repository checkout" in capsys.readouterr().err
    window = EventWindow(BUCKET, BUCKET.replace(minute=10), ())
    assert get_detector("D-001").run(window) == []
