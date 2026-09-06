"""``make eval``: run every labelled case through its rule (T1) and every rule over the
benign corpus (T2), then write the numbers into docs/evaluation.md §8 between the
``eval:begin`` / ``eval:end`` markers (ADR-020). A test pins the committed block to what
this produces, so a rule change that moves a number has to bring the document with it.
"""

from __future__ import annotations

import bisect
import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from aegisnet.adapters.files.labelled import LabelledCase, case_dirs, load_case, load_corpus
from aegisnet.domain.detectors import Detector, EventWindow, default_detectors
from aegisnet.domain.detectors.evaluation import (
    BenignRun,
    CaseOutcome,
    RuleMetrics,
    judge,
    markdown_table,
    summarize,
)
from aegisnet.domain.ports import EventRow
from aegisnet.services.detection_service import grid_buckets

BEGIN = "<!-- eval:begin -->"
END = "<!-- eval:end -->"
_BLOCK = re.compile(re.escape(BEGIN) + r".*?" + re.escape(END), re.DOTALL)

# Where the harness reads and writes, relative to the repository root. The command takes
# no paths: like a dataset import, it resolves fixed names under a root it finds itself.
CASES_DIR = Path("backend/tests/fixtures/labelled")
CORPUS_FILE = Path("samples/synthetic/benign-baseline-01.ndjson")
RESULTS_DOC = Path("docs/evaluation.md")
LAYOUT = (CASES_DIR, CORPUS_FILE, RESULTS_DOC)


class EvaluationError(ValueError):
    pass


_COMMIT = re.compile(r"[0-9a-f]{40}")
_RECORDED_COMMIT = re.compile(r"Corpus commit `([0-9a-f]{40})`")


def recorded_commit(document: str) -> str:
    """The commit `docs/evaluation.md` already publishes.

    The pin in `tests/detectors/test_evaluation.py` reads it back and renders with it, so the
    test stays hermetic — it holds the *numbers* to the harness without needing a git history,
    which a shallow CI checkout does not have. Whether that commit is the right one is a
    separate question, asked by a separate test that skips when git cannot answer it.
    """
    found = _RECORDED_COMMIT.search(document)
    if found is None:
        raise EvaluationError("the document publishes no corpus commit; run `make eval`")
    return found.group(1)


def repository_root(start: Path) -> Path:
    """The nearest directory at or above ``start`` that holds the whole layout."""
    for candidate in (start, *start.parents):
        if all((candidate / relative).exists() for relative in LAYOUT):
            return candidate
    raise EvaluationError(
        "not inside a repository checkout: "
        + ", ".join(str(relative) for relative in LAYOUT)
        + " were not all found at or above the working directory"
    )


@dataclass(frozen=True, slots=True)
class Report:
    outcomes: tuple[CaseOutcome, ...]
    benign: tuple[BenignRun, ...]
    metrics: tuple[RuleMetrics, ...]
    cases_root: str
    corpus_name: str
    corpus_sha256: str
    corpus_events: int
    corpus_rejected: int
    corpus_seed: int | None
    rule_versions: tuple[tuple[str, int], ...]

    @property
    def failures(self) -> tuple[CaseOutcome, ...]:
        return tuple(o for o in self.outcomes if o.verdict in ("FN", "FP"))


def _by_rule(detectors: Sequence[Detector]) -> dict[str, Detector]:
    return {d.spec.rule_id: d for d in detectors}


def evaluate_cases(
    cases: Sequence[LabelledCase], detectors: Mapping[str, Detector]
) -> tuple[CaseOutcome, ...]:
    out: list[CaseOutcome] = []
    for case in cases:
        detector = detectors.get(case.rule_id)
        if detector is None:
            raise EvaluationError(f"{case.case_id}: no detector for {case.rule_id}")
        results = detector.run(case.window)
        out.append(judge(case.expectation(), results, base_severity=detector.spec.base_severity))
    return tuple(out)


def evaluate_benign(
    events: Sequence[EventRow], detectors: Mapping[str, Detector]
) -> tuple[BenignRun, ...]:
    """Every rule over the corpus on its own grid, the way a sweep would slice it; alerts
    are counted by distinct dedup key, which is what a sweep would have stored."""
    if not events:
        return tuple(BenignRun(rule_id, 0, 0, 0) for rule_id in sorted(detectors))
    times = [row.event_time for row in events]
    first, last = times[0], times[-1] + timedelta(microseconds=1)
    out: list[BenignRun] = []
    for rule_id in sorted(detectors):
        detector = detectors[rule_id]
        keys: set[str] = set()
        buckets = grid_buckets(first, last, detector.spec.window_seconds)
        for start, end in buckets:
            window = EventWindow(start, end, _slice(events, times, start, end))
            keys.update(result.dedup_key for result in detector.run(window))
        note = "abstains: no baselines in T2" if "min_samples" in detector.spec.params else ""
        out.append(BenignRun(rule_id, len(events), len(keys), len(buckets), note))
    return tuple(out)


def _slice(
    events: Sequence[EventRow], times: Sequence[datetime], start: datetime, end: datetime
) -> tuple[EventRow, ...]:
    lo = bisect.bisect_left(times, start)
    hi = bisect.bisect_left(times, end)
    return tuple(events[lo:hi])


def run_evaluation(
    cases_root: Path, corpus: Path, *, detectors: Sequence[Detector] | None = None
) -> Report:
    directories = case_dirs(cases_root)
    if not directories:
        raise EvaluationError(f"no labelled cases under {cases_root}")
    if not corpus.is_file():
        raise EvaluationError(f"corpus not found: {corpus}")
    registry = _by_rule(default_detectors() if detectors is None else detectors)
    cases = [load_case(directory) for directory in directories]
    outcomes = evaluate_cases(cases, registry)
    events, rejected = load_corpus(corpus)
    benign = evaluate_benign(events, registry)
    digest = hashlib.sha256(corpus.read_bytes()).hexdigest()
    return Report(
        outcomes,
        benign,
        summarize(outcomes, benign),
        cases_root.name,
        corpus.name,
        digest,
        len(events),
        rejected,
        generator_seed(corpus),
        tuple(sorted((rule_id, d.spec.version) for rule_id, d in registry.items())),
    )


def generator_seed(corpus: Path) -> int | None:
    """The seed the corpus was generated from, out of the manifest beside it.

    `docs/evaluation.md` §6 asks every published number to carry the seed, because a corpus is
    reproducible only if somebody can regenerate it. A missing or unreadable manifest is not a
    failure — a corpus can be a real capture, which has no seed — so this answers `None` and
    the provenance line says so rather than inventing a number.
    """
    manifest = corpus.with_name(f"{corpus.stem}.manifest.json")
    try:
        loaded = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    seed = loaded.get("seed") if isinstance(loaded, dict) else None
    return seed if isinstance(seed, int) and not isinstance(seed, bool) else None


def render(report: Report, *, corpus_commit: str) -> str:
    """The block that goes between the markers: provenance lines, table, failures.

    `corpus_commit` is passed in rather than resolved here so that rendering stays pure — the
    same report and the same commit produce the same bytes, on a machine with no git at all.
    The command that writes the document is what asks git; see `cmd_eval`.
    """
    if not _COMMIT.fullmatch(corpus_commit):
        raise EvaluationError(f"a corpus commit is forty hex characters, not {corpus_commit!r}")
    positives = sum(1 for o in report.outcomes if o.expectation.kind == "positive")
    negatives = len(report.outcomes) - positives
    seed = f"`{report.corpus_seed}`" if report.corpus_seed is not None else "none (not generated)"
    versions = ", ".join(f"{rule} v{version}" for rule, version in report.rule_versions)
    lines = [
        f"Generated by `make eval` from {len(report.outcomes)} labelled cases "
        f"({positives} positive, {negatives} negative) under `{report.cases_root}/` (T1) "
        f"and `{report.corpus_name}` (T2, {report.corpus_events} events, "
        f"{report.corpus_rejected} rejected, sha256 `{report.corpus_sha256[:12]}`).",
        "",
        f"Corpus commit `{corpus_commit}` · generator seed {seed} · rule versions {versions}. "
        "The commit is the one that last changed the labelled cases or the corpus, so these "
        "bytes can be fetched rather than trusted.",
        "",
        markdown_table(report.metrics, corpus="T1 labelled / T2 synthetic"),
    ]
    if report.failures:
        lines += ["", "Cases that did not meet their label:"]
        lines += [f"- `{o.expectation.case_id}` ({o.verdict}): {o.reason}" for o in report.failures]
    else:
        lines += ["", "Every labelled case met its label."]
    return "\n".join(lines)


def replace_results(document: str, block: str) -> str:
    """``document`` with the marked block replaced; the markers stay in place."""
    if BEGIN not in document or END not in document:
        raise EvaluationError("the results markers are missing from the document")
    return _BLOCK.sub(lambda _: f"{BEGIN}\n{block}\n{END}", document, count=1)
