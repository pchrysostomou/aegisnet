"""`THREAT_MODEL.md` §6 is checked, not merely written (Milestone 6, Chunk 27).

A coverage matrix is the one security artefact whose whole value is that it is current. Written
by hand and read once, it is worse than nothing: it says a mitigation is verified by a test that
was renamed three chunks ago, and the next reader believes it.

So the matrix is data and this is its parser. It fails on:

* a threat in §3 with no row in §6, or a row for a threat that no longer exists;
* a pytest node id naming a file or a function that is not there;
* a vitest or Playwright title that no `it(...)` or `test(...)` call carries;
* a CI job that the workflow does not define;
* a residual-risk id that §4 does not define;
* a status whose evidence does not match it — a `test` row with no test, an `accepted` row with
  one, a `partial` row that does not say what is missing.

What it deliberately does **not** assert is that the named tests pass. That is the suites' job,
and asserting it here would mean running pytest inside pytest for a weaker guarantee than the
run this test is already part of. What breaks a matrix in practice is not a test that starts
failing — CI catches that on the same push — it is a test that quietly stops existing under the
name the document uses. That is what this catches.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path

import pytest
import yaml

from tests.conftest import REPO_ROOT

pytestmark = pytest.mark.security

MODEL = REPO_ROOT / "THREAT_MODEL.md"
BEGIN = "<!-- coverage:begin -->"
END = "<!-- coverage:end -->"

STATUSES = frozenset({"test", "partial", "accepted"})
NOTHING = "—"  # an em dash, the document's own way of saying "no entry"

_THREAT_ROW = re.compile(r"^\| (T-\d+\.\d+) \|", re.MULTILINE)
_RISK_ROW = re.compile(r"^\| (R-\d+) \|", re.MULTILINE)
_RISK_MENTION = re.compile(r"\bR-\d+\b")
_BACKTICKED = re.compile(r"`([^`]+)`")

_PYTEST_REF = re.compile(r"^(backend/tests/[\w/]+\.py)((?:::\w+)+)$")
_TS_REF = re.compile(r'^(frontend/[\w\-./\[\]]+\.tsx?)::"(.+)"$')
_CI_REF = re.compile(r"^(\.github/workflows/[\w-]+\.yml)::([\w-]+)$")


@dataclass(frozen=True, slots=True)
class Row:
    threat: str
    status: str
    references: tuple[str, ...]
    gap: str


def _matrix_block(document: str) -> str:
    start, end = document.find(BEGIN), document.find(END)
    assert start != -1 and end > start, "the coverage markers are missing from THREAT_MODEL.md"
    return document[start + len(BEGIN) : end]


def _cells(line: str) -> list[str]:
    """A row's cells. No cell in this table contains a pipe, and the checker below would
    reject a reference broken across two cells anyway, so a plain split is enough."""
    return [cell.strip() for cell in line.strip().strip("|").split("|")]


def _parse_rows(document: str) -> tuple[Row, ...]:
    rows: list[Row] = []
    for line in _matrix_block(document).splitlines():
        if not line.startswith("| T-"):
            continue
        cells = _cells(line)
        assert len(cells) == 4, f"{cells[0]}: expected four columns, got {len(cells)}"
        threat, status, references, gap = cells
        rows.append(Row(threat, status, tuple(_BACKTICKED.findall(references)), gap))
    return tuple(rows)


@pytest.fixture(scope="module")
def document() -> str:
    return MODEL.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def rows(document: str) -> tuple[Row, ...]:
    parsed = _parse_rows(document)
    assert parsed, "no coverage rows were parsed; the table's shape has changed"
    return parsed


def test_every_threat_has_exactly_one_row_and_every_row_a_threat(
    document: str, rows: tuple[Row, ...]
) -> None:
    """The bijection is the whole point. A threat added to §3 without a row here is a
    mitigation nobody has said anything about; a row without a threat is a claim about
    something that is no longer in the model."""
    declared = _THREAT_ROW.findall(document[: document.find(BEGIN)])
    assert declared, "§3 declares no threats; the parser has drifted"
    assert len(declared) == len(set(declared)), f"§3 declares a threat twice: {declared}"
    threats = set(declared)
    covered = [row.threat for row in rows]

    assert len(covered) == len(set(covered)), "a threat is covered twice"
    assert set(covered) == threats, (
        f"uncovered threats: {sorted(threats - set(covered))}; "
        f"rows for no threat: {sorted(set(covered) - threats)}"
    )


def test_every_status_is_one_the_document_defines(rows: tuple[Row, ...]) -> None:
    for row in rows:
        assert row.status in STATUSES, f"{row.threat}: unknown status {row.status!r}"


def _promise_broken(row: Row) -> str | None:
    """A status is a promise about the other two columns. This is the promise, in one place.

    `test` is the only status that may leave the gap column empty, and `accepted` is the only
    one that may leave the references column empty. `partial` has to do both — name what holds
    and say what does not — because a `partial` with nothing written in it is indistinguishable
    from a row somebody could not be bothered to finish.
    """
    if row.status == "accepted":
        if row.references:
            return "accepted, but names tests"
        if not _RISK_MENTION.search(row.gap):
            return "accepted without a residual risk"
        return None

    if not row.references:
        return f"{row.status}, but names no test"
    if row.status == "partial":
        if not row.gap or row.gap == NOTHING:
            return "partial without saying what is missing"
        return None
    if row.gap != NOTHING and not _RISK_MENTION.search(row.gap):
        return f"a verified row's last column is {NOTHING!r} or a residual risk, not {row.gap!r}"
    return None


def test_the_evidence_matches_the_status_it_claims(rows: tuple[Row, ...]) -> None:
    broken = {row.threat: problem for row in rows if (problem := _promise_broken(row))}
    assert not broken, broken


@pytest.mark.parametrize(
    ("status", "references", "gap", "problem"),
    [
        ("test", ("a",), NOTHING, None),
        ("test", ("a",), "R-3", None),
        ("test", (), NOTHING, "test, but names no test"),
        ("test", ("a",), "we never got round to it", "a verified row's last column"),
        ("partial", ("a",), "no timeout is set", None),
        ("partial", ("a",), NOTHING, "partial without saying what is missing"),
        ("partial", (), "no timeout is set", "partial, but names no test"),
        ("accepted", (), "R-5", None),
        ("accepted", ("a",), "R-5", "accepted, but names tests"),
        ("accepted", (), "out of scope", "accepted without a residual risk"),
    ],
)
def test_the_status_rules_accept_and_refuse_the_shapes_they_are_meant_to(
    status: str, references: tuple[str, ...], gap: str, problem: str | None
) -> None:
    """The document currently uses two of the three statuses, so `accepted` would otherwise be a
    rule nobody has ever seen fire. Held to a table instead, and the failure messages are part
    of the check — a row rejected for the wrong reason tells the next reader the wrong thing."""
    result = _promise_broken(Row("T-0.0", status, references, gap))
    if problem is None:
        assert result is None, result
    else:
        assert result is not None and result.startswith(problem), result


def test_every_residual_risk_named_is_one_the_model_accepts(
    document: str, rows: tuple[Row, ...]
) -> None:
    accepted = set(_RISK_ROW.findall(document))
    assert accepted, "§4 defines no residual risks; the parser has drifted"
    for row in rows:
        for named in _RISK_MENTION.findall(row.gap):
            assert named in accepted, f"{row.threat} names {named}, which §4 does not define"


def _python_test_exists(path: Path, names: tuple[str, ...]) -> bool:
    """``names`` is a node id's tail — a function, or a class then a function. Resolved
    against the file's syntax tree rather than by importing it: the matrix has to be
    checkable without the imports of every module it names being satisfiable."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    body: list[ast.stmt] = tree.body
    for name in names[:-1]:
        found = next(
            (n for n in body if isinstance(n, ast.ClassDef) and n.name == name),
            None,
        )
        if found is None:
            return False
        body = found.body
    leaf = names[-1]
    return any(
        isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.name == leaf
        for node in body
    )


def _ts_test_exists(path: Path, title: str) -> bool:
    """vitest and Playwright both spell a case ``it("title", …)`` or ``test("title", …)``.
    The title is matched literally, so a reworded test breaks the row that cites it — which
    is the intended failure, not an inconvenience."""
    source = path.read_text(encoding="utf-8")
    return re.search(rf'\b(?:it|test)\(\s*"{re.escape(title)}"', source) is not None


def _ci_job_exists(path: Path, job: str) -> bool:
    workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
    return job in (workflow.get("jobs") or {})


def test_every_named_test_and_job_resolves(rows: tuple[Row, ...]) -> None:
    """The check the whole file exists for: a reference that no longer points at anything.

    Three shapes are understood and a fourth is an error rather than something to skip over,
    because a reference the checker cannot read is a reference nobody is checking.
    """
    unresolved: list[str] = []
    for row in rows:
        for reference in row.references:
            if match := _PYTEST_REF.match(reference):
                path = REPO_ROOT / match.group(1)
                names = tuple(match.group(2).lstrip(":").split("::"))
                ok = path.is_file() and _python_test_exists(path, names)
            elif match := _TS_REF.match(reference):
                path = REPO_ROOT / match.group(1)
                ok = path.is_file() and _ts_test_exists(path, match.group(2))
            elif match := _CI_REF.match(reference):
                path = REPO_ROOT / match.group(1)
                ok = path.is_file() and _ci_job_exists(path, match.group(2))
            else:
                raise AssertionError(
                    f"{row.threat}: {reference!r} is not a node id, a quoted test title or a "
                    "workflow job. The matrix only holds up if every reference is checkable."
                )
            if not ok:
                unresolved.append(f"{row.threat}: {reference}")
    assert not unresolved, "references that no longer resolve:\n  " + "\n  ".join(unresolved)


def test_the_prose_above_the_table_counts_the_partial_rows_correctly(
    document: str, rows: tuple[Row, ...]
) -> None:
    """The paragraph before the table says how many rows are unfinished, because that number
    is what a reader takes away. It is asserted so it cannot be the stale part of a document
    whose entire purpose is not being stale."""
    words = ("Zero", "One", "Two", "Three", "Four", "Five", "Six", "Seven", "Eight", "Nine")
    partial = sum(1 for row in rows if row.status == "partial")
    # "Zero rows are `partial` today" is not a sentence anybody writes. The point of this test
    # is that the number above the table is true, not that it is phrased in one fixed way, so
    # at zero it accepts the sentence a person would actually write.
    claim = (
        "**No row is `partial`.**" if partial == 0 else f"{words[partial]} rows are `partial` today"
    )
    assert claim in document, f"the summary above the table should read {claim!r}"
