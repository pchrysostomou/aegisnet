"""Every third-party module the application imports is a runtime dependency.

The runtime image installs `[project.dependencies]` and not the dev group, so a module that
only the tests happened to pull in works everywhere except in production. That is exactly how
this test came to exist: `httpx` was a dev dependency, the Perplexity client imported it from
Chunk 22, and nothing in the *runtime* import graph reached that client until Chunk 23 wired
the brief service into the app. Every check passed — ruff, mypy, the whole suite, the database
suite — and the api container then failed to start on the runner with
`ModuleNotFoundError: No module named 'httpx'`.

The check is deliberately blunt: walk `src/`, collect every top-level module imported that is
neither this package nor part of the standard library, and require each one to be declared.
"""

from __future__ import annotations

import ast
import sys
import tomllib
from pathlib import Path

import pytest

from tests.conftest import REPO_ROOT

pytestmark = pytest.mark.security

SRC = REPO_ROOT / "backend" / "src" / "aegisnet"
PYPROJECT = REPO_ROOT / "backend" / "pyproject.toml"

# Distributions whose import name differs from the name on the dependency line.
IMPORT_TO_DISTRIBUTION = {
    "jwt": "pyjwt",
    "yaml": "pyyaml",
    "argon2": "argon2-cffi",
    "multipart": "python-multipart",
}

# Imported by code that only ever runs under Alembic, which installs its own entry point.
EXEMPT = frozenset({"alembic"})


def _declared() -> set[str]:
    data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    names = set()
    for line in data["project"]["dependencies"]:
        # "sqlalchemy[asyncio]>=2.0.35,<2.1" -> "sqlalchemy"
        name = line.split("[")[0].split(">")[0].split("<")[0].split("=")[0].split(";")[0]
        names.add(name.strip().lower().replace("_", "-"))
    return names


def _imported() -> dict[str, set[Path]]:
    found: dict[str, set[Path]] = {}
    for path in sorted(SRC.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                roots = [alias.name.split(".")[0] for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                # A relative import (level > 0) is this package by definition.
                roots = [node.module.split(".")[0]] if node.module and not node.level else []
            else:
                continue
            for root in roots:
                if root in ("aegisnet", "__future__") or root in sys.stdlib_module_names:
                    continue
                found.setdefault(root, set()).add(path.relative_to(SRC))
    return found


def test_every_third_party_import_in_src_is_a_runtime_dependency() -> None:
    declared = _declared()
    undeclared = {
        module: sorted(str(p) for p in files)
        for module, files in _imported().items()
        if module not in EXEMPT
        and IMPORT_TO_DISTRIBUTION.get(module, module).lower().replace("_", "-") not in declared
    }
    assert not undeclared, (
        "these modules are imported by the application but are not runtime dependencies, "
        f"so the runtime image will not have them: {undeclared}"
    )


def test_the_alias_table_describes_real_dependencies() -> None:
    """A stale alias would quietly excuse a missing dependency."""
    declared = _declared()
    stale = {i: d for i, d in IMPORT_TO_DISTRIBUTION.items() if d not in declared}
    assert not stale, stale


# The one module allowed to start a process, and the reason it is allowed to. T-1.2 bans a
# shell reached by attacker-influenced data; `git log` with a fixed argv is not that. Keeping
# the exception in one named place is what stops the distinction being lost later.
MAY_START_A_PROCESS = frozenset({Path("adapters/files/provenance.py")})
PROCESS_MODULES = frozenset({"subprocess", "pty", "multiprocessing"})
OS_RUNNERS = frozenset({"system", "popen", "spawnl", "spawnv", "execv", "execvp", "execl"})


def _process_starters(tree: ast.AST) -> list[str]:
    """Every way this codebase could start a process, named. Two shapes are looked for: an
    import of a process module, and an attribute call on `os` that runs something."""
    found: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found += [a.name for a in node.names if a.name.split(".")[0] in PROCESS_MODULES]
        elif isinstance(node, ast.ImportFrom) and node.module:
            if node.module.split(".")[0] in PROCESS_MODULES:
                found.append(node.module)
        elif isinstance(node, ast.Attribute):
            value = node.value
            if isinstance(value, ast.Name) and value.id == "os" and node.attr in OS_RUNNERS:
                found.append(f"os.{node.attr}")
    return sorted(set(found))


def test_only_the_provenance_adapter_starts_a_process() -> None:
    """T-1.2, held to an allowlist of one rather than to a habit.

    `subprocess` arrived in `src/` for the first time in Chunk 27, to answer "which commit are
    these numbers measured from". That is a fine reason and the next one might not be, so the
    ban becomes a list: a second module reaching for a process fails here and somebody has to
    decide in the open, the way the lab sensor's one capability was.
    """
    offenders = {}
    for path in sorted(SRC.rglob("*.py")):
        relative = path.relative_to(SRC)
        if relative in MAY_START_A_PROCESS:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        if starters := _process_starters(tree):
            offenders[str(relative)] = starters
    assert not offenders, (
        f"these modules start a process, and only {sorted(MAY_START_A_PROCESS)[0]} may: "
        f"{offenders}"
    )


def test_the_allowlisted_module_is_the_one_that_actually_needs_it() -> None:
    """An allowlist entry for a module that stopped shelling out is an entry that will excuse
    the next one to start."""
    for relative in MAY_START_A_PROCESS:
        path = SRC / relative
        assert path.is_file(), f"{relative} is allowlisted and does not exist"
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        assert _process_starters(tree), f"{relative} no longer starts a process; drop the entry"
