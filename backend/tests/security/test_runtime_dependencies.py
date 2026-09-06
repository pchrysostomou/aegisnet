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
