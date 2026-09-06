"""Where a published number's bytes live (Milestone 6, Chunk 27).

`docs/evaluation.md` §8 names the commit its corpus was measured at. That claim is only worth
making if it is the *right* commit, so these build small real repositories and ask.

The last test is the one that matters to a reader: it takes the sha the committed document
publishes and checks it against this checkout. It skips — loudly, with a reason — where git
cannot answer, which is any shallow clone (CI checks out one commit deep) and any export with
no history at all. A skip there is honest; asserting would only mean the test never ran.
"""

from __future__ import annotations

import subprocess  # building a real repository is the point of this file
from pathlib import Path

import pytest

from aegisnet.adapters.files.provenance import ProvenanceError, corpus_commit
from aegisnet.services.evaluation_service import CASES_DIR, CORPUS_FILE, recorded_commit
from tests.conftest import REPO_ROOT

pytestmark = pytest.mark.unit

DOC = REPO_ROOT / "docs" / "evaluation.md"


def _git(root: Path, *arguments: str) -> str:
    finished = subprocess.run(  # noqa: S603 - fixed argv, no shell, test-owned paths
        ["git", "-C", str(root), *arguments],  # noqa: S607 - git from PATH, as everywhere else
        capture_output=True,
        text=True,
        check=True,
    )
    return finished.stdout.strip()


@pytest.fixture
def repository(tmp_path: Path) -> Path:
    """A checkout with two commits: the corpus, then something that is not the corpus."""
    _git(tmp_path, "init", "--quiet", "--initial-branch=main")
    _git(tmp_path, "config", "user.email", "tests@example.test")
    _git(tmp_path, "config", "user.name", "tests")
    _git(tmp_path, "config", "commit.gpgsign", "false")

    (tmp_path / "corpus.ndjson").write_text('{"a": 1}\n', encoding="utf-8")
    _git(tmp_path, "add", "corpus.ndjson")
    _git(tmp_path, "commit", "--quiet", "-m", "the corpus")

    (tmp_path / "unrelated.txt").write_text("later\n", encoding="utf-8")
    _git(tmp_path, "add", "unrelated.txt")
    _git(tmp_path, "commit", "--quiet", "-m", "something else entirely")
    return tmp_path


def test_the_commit_is_the_last_one_that_changed_the_corpus_not_the_newest(
    repository: Path,
) -> None:
    """HEAD would have been easier and would have made §8 stale on the next unrelated push,
    which is how a provenance line becomes something everybody scrolls past."""
    head = _git(repository, "rev-parse", "HEAD")
    corpus = _git(repository, "rev-parse", "HEAD~1")

    resolved = corpus_commit(repository, (repository / "corpus.ndjson",))

    assert resolved == corpus
    assert resolved != head, "an unrelated commit moved the corpus's provenance"


def test_a_second_change_moves_it_forward(repository: Path) -> None:
    (repository / "corpus.ndjson").write_text('{"a": 2}\n', encoding="utf-8")
    _git(repository, "add", "corpus.ndjson")
    _git(repository, "commit", "--quiet", "-m", "regenerated")

    assert corpus_commit(repository, (repository / "corpus.ndjson",)) == _git(
        repository, "rev-parse", "HEAD"
    )


def test_uncommitted_bytes_have_no_commit_and_are_refused(repository: Path) -> None:
    """The failure this exists to prevent: regenerate a corpus, run `make eval`, and publish a
    table measured from bytes that are not at the commit the table names."""
    (repository / "corpus.ndjson").write_text('{"a": 3}\n', encoding="utf-8")

    with pytest.raises(ProvenanceError, match="uncommitted"):
        corpus_commit(repository, (repository / "corpus.ndjson",))


def test_a_change_to_something_else_does_not_make_the_corpus_dirty(repository: Path) -> None:
    """The dirty check is scoped to the paths asked about, so ordinary work in progress
    elsewhere in the tree does not stop the command."""
    (repository / "unrelated.txt").write_text("edited while working\n", encoding="utf-8")

    assert corpus_commit(repository, (repository / "corpus.ndjson",))


def test_a_path_outside_the_checkout_is_refused(repository: Path, tmp_path: Path) -> None:
    """`git log -- <path outside>` answers about the whole history rather than failing, so
    the wrong answer is turned into an error here."""
    outside = tmp_path.parent / "elsewhere.ndjson"
    with pytest.raises(ProvenanceError, match="not inside"):
        corpus_commit(repository, (outside,))


def test_a_directory_that_is_not_a_checkout_is_refused(tmp_path: Path) -> None:
    with pytest.raises(ProvenanceError, match="not a git repository"):
        corpus_commit(tmp_path, (tmp_path / "corpus.ndjson",))


def test_a_path_git_has_never_seen_is_refused(repository: Path) -> None:
    """An untracked file is not dirty and has no commit; without this it would resolve to
    whatever the other paths last touched."""
    with pytest.raises(ProvenanceError, match="no commit was found"):
        corpus_commit(repository, (repository / "never-added.ndjson",))


def test_a_shallow_clone_is_refused_rather_than_answered_wrongly(
    repository: Path, tmp_path_factory: pytest.TempPathFactory
) -> None:
    """The defect CI found on this chunk's first push, kept.

    A truncated history does not make `git log -1 -- <paths>` come back empty. The files exist
    at the graft point, so git names the boundary commit as the one that introduced them — and
    the check that was meant to skip instead compared the real commit against that. CI checks
    out one commit deep, so this is the ordinary case rather than an exotic one, and a
    confident wrong answer is worse than no answer.
    """
    shallow = tmp_path_factory.mktemp("shallow") / "clone"
    _git(
        repository,
        "clone",
        "--quiet",
        "--depth",
        "1",
        f"file://{repository}",
        str(shallow),
    )
    assert (shallow / "corpus.ndjson").is_file(), "the file is there; the history is not"
    # Left to itself, git would name the graft point — the commit that has nothing to do with
    # when the corpus was written.
    assert _git(shallow, "log", "-1", "--format=%H", "--", "corpus.ndjson") == _git(
        shallow, "rev-parse", "HEAD"
    )

    with pytest.raises(ProvenanceError, match="shallow clone"):
        corpus_commit(shallow, (shallow / "corpus.ndjson",))


def test_no_paths_is_refused(repository: Path) -> None:
    with pytest.raises(ProvenanceError, match="no corpus paths"):
        corpus_commit(repository, ())


def test_the_published_commit_is_the_one_the_corpus_was_last_changed_in() -> None:
    """The claim §8 actually makes, checked against this checkout.

    The pin in `tests/detectors/test_evaluation.py` reads the sha back out of the document and
    renders with it, which holds every number but would happily hold a made-up commit too.
    This is the other half.
    """
    published = recorded_commit(DOC.read_text(encoding="utf-8"))
    try:
        actual = corpus_commit(REPO_ROOT, (REPO_ROOT / CASES_DIR, REPO_ROOT / CORPUS_FILE))
    except ProvenanceError as error:
        pytest.skip(f"git cannot place the corpus in history here: {error}")

    assert published == actual, (
        f"docs/evaluation.md publishes {published[:12]} and the corpus was last changed in "
        f"{actual[:12]}; run `make eval`"
    )
