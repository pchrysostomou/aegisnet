"""Where the bytes a published number was measured from can be found (Milestone 6, Chunk 27).

`docs/evaluation.md` §6 asks every published number to carry four things: the command, the
corpus sha256, the detector rule versions and the generator seed. Three of those the harness
already knew. The fourth question a reader actually asks — *where do I get this corpus?* — the
content hash cannot answer, so this resolves the commit that last changed the inputs.

**This is the only module under `src/` that starts a process**, and
`tests/security/test_runtime_dependencies.py` pins it to that: the exception is one call site,
with fixed arguments and no value derived from an event, a request or a setting. T-1.2 forbids
a shell reached by attacker-influenced data, not `git log`; the pin is what keeps the two from
being confused later.

It refuses rather than improvises. If the paths carry uncommitted changes there is no honest
commit to name — the bytes measured are not the bytes at any commit — and `make eval` stops
with a message saying to commit the corpus first. A published number with a wrong provenance
line is worse than one that was never published.
"""

from __future__ import annotations

import re
import subprocess  # the one call site; see the module docstring and the pin that holds it there
from collections.abc import Sequence
from pathlib import Path

_SHA = re.compile(r"^[0-9a-f]{40}$")
_TIMEOUT_SECONDS = 15


class ProvenanceError(RuntimeError):
    """The commit behind the corpus could not be established."""


def _git(root: Path, *arguments: str) -> str:
    """`git` with a fixed argv, no shell, and no value that came from outside this module."""
    try:
        finished = subprocess.run(  # noqa: S603 - fixed argv, no shell, no untrusted input
            ["git", "-C", str(root), *arguments],  # noqa: S607 - git is resolved from PATH
            capture_output=True,
            text=True,
            timeout=_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise ProvenanceError(f"git could not be run: {type(error).__name__}") from error
    if finished.returncode != 0:
        detail = finished.stderr.strip().splitlines()
        raise ProvenanceError(f"git {arguments[0]} failed: {detail[0] if detail else 'no output'}")
    return finished.stdout


def _relative(root: Path, paths: Sequence[Path]) -> list[str]:
    """Every path as a repository-relative string, or a refusal. A path outside the checkout
    would silently widen `git log` to the whole history, which is the wrong answer rather than
    an error, so it is made an error here."""
    out: list[str] = []
    for path in paths:
        try:
            out.append(str(path.resolve().relative_to(root.resolve())))
        except ValueError as error:
            raise ProvenanceError(f"{path} is not inside {root}") from error
    return out


def corpus_commit(root: Path, paths: Sequence[Path]) -> str:
    """The commit that last changed any of `paths`, as forty hex characters.

    Deliberately not `HEAD`: the corpus does not change on every commit, so pinning HEAD would
    make §8 stale on the next push and teach everybody to ignore it. The last commit to touch
    the inputs stays put until the inputs do.
    """
    if not paths:
        raise ProvenanceError("no corpus paths were given")
    relative = _relative(root, paths)

    dirty = _git(root, "status", "--porcelain", "--", *relative).strip()
    if dirty:
        changed = ", ".join(line[3:] for line in dirty.splitlines()[:4])
        raise ProvenanceError(
            f"the corpus has uncommitted changes ({changed}); commit them before publishing a "
            "number measured from them"
        )

    sha = _git(root, "log", "-1", "--format=%H", "--", *relative).strip()
    if not _SHA.fullmatch(sha):
        raise ProvenanceError(
            "no commit was found for the corpus; a shallow clone or an export does not carry "
            "the history a provenance line needs"
        )
    return sha


__all__ = ["ProvenanceError", "corpus_commit"]
