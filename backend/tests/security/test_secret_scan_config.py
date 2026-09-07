"""The secret scan's allowlist is four strings, and it has to stay four strings (T-5.4, R-4).

The scan runs at two scopes and for a long time only the narrow one was ever seen.
`gitleaks-action` scans the commits of a *push*; on a schedule or a dispatch it scans the
**entire history**. Seven secret-shaped literals were committed, noticed, and rewritten to be
built at runtime in a follow-up commit — which clears the push scan and does nothing whatever
for the history scan, because the literals are still in the objects those commits left behind.
Every push was green and the weekly run was red, from 2026-09-05 until somebody looked at the
Security tab.

`.gitleaks.toml` is the fix, and this file is what stops the fix from becoming a hole. The
tempting version of that config is one line — `paths = ['^backend/tests/']` — which clears the
same seven findings and also means a real credential pasted into a test file is never reported
again. `backend/tests/security/` is exactly where somebody debugging a redaction failure would
paste one. So the allowlist names four exact strings, anchored, and the assertions below are
what that sentence looks like when it is checked rather than believed.
"""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any

import pytest
import yaml

from tests.conftest import REPO_ROOT

pytestmark = pytest.mark.security

CONFIG = REPO_ROOT / ".gitleaks.toml"
SECURITY_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "security.yml"
PRE_COMMIT = REPO_ROOT / ".pre-commit-config.yaml"


def _config() -> dict[str, Any]:
    assert CONFIG.exists(), "the gitleaks config is gone; the history scan will fail again"
    with CONFIG.open("rb") as handle:
        loaded: dict[str, Any] = tomllib.load(handle)
    return loaded


def _allowlist() -> dict[str, Any]:
    config = _config()
    # gitleaks accepts `[allowlist]` and the newer `[[allowlists]]`; either is a hole if it
    # exempts a location, so both are checked wherever one is looked at.
    lists = config.get("allowlists") or ([config["allowlist"]] if "allowlist" in config else [])
    assert len(lists) == 1, f"expected exactly one allowlist, found {len(lists)}"
    single: dict[str, Any] = lists[0]
    return single


def test_every_default_rule_is_still_on() -> None:
    """`useDefault = true`. Without it the config *replaces* the rule set rather than extending
    it, and a file whose visible purpose is to allow four strings would silently switch off the
    hundred-odd detectors that find everything else. A green scan would mean nothing."""
    assert _config().get("extend", {}).get("useDefault") is True


def test_nothing_is_exempted_by_location() -> None:
    """The hole this file exists to keep shut.

    `paths`, `files`, `commits` and `stopwords` all clear a finding without looking at what the
    finding is. In a global allowlist they combine as OR with the regexes, so a single `paths`
    entry would exempt a whole directory — and the directory anybody would reach for is the one
    holding the tests that handle credentials.
    """
    allowlist = _allowlist()
    for key in ("paths", "files", "commits", "stopwords"):
        assert key not in allowlist, (
            f"the allowlist exempts by {key!r}: findings are cleared without being read"
        )
    assert allowlist.get("regexes"), "an allowlist with no regexes allows nothing or everything"


def test_the_allowed_values_are_matched_whole_and_not_as_prefixes() -> None:
    """Anchored, and matched against the secret rather than the line.

    Unanchored, the test signing key also allows itself with a real key appended, and
    `regexTarget = "line"` would allow any secret sharing a line with an allowed one. Both were
    checked by probe before this was written: one character changed, a longer superstring and an
    unrelated PAT are all still findings. (The values are named here by description and never
    quoted — the test below is what enforces that, on this file along with every other.)
    """
    allowlist = _allowlist()
    assert allowlist.get("regexTarget", "secret") == "secret"
    for regex in allowlist["regexes"]:
        assert regex.startswith("^") and regex.endswith("$"), f"{regex} matches substrings"


def _allowed_literals() -> list[str]:
    """The allowed regexes turned back into the strings they match, for the test below."""
    return [regex[1:-1].replace("\\.", ".") for regex in _allowlist()["regexes"]]


SKIP_DIRS = {".git", "node_modules", ".venv", ".next", ".ruff_cache", ".pytest_cache", "captures"}


def _text_or_none(path: Path) -> str | None:
    """A file that is not UTF-8 text, or that cannot be read at all, is not evidence either way.

    The four allowed values are ASCII, so anything that fails to decode cannot contain one in a
    form a scanner would find.
    """
    try:
        return path.read_bytes().decode("utf-8")
    except (UnicodeDecodeError, OSError):
        return None


def test_no_allowed_value_appears_as_a_literal_in_the_tree() -> None:
    """The allowlist is a statement about history, and it must not quietly become a statement
    about the present.

    Each of these four strings was moved out of the source into a runtime expression precisely
    so the scanner would stop seeing it. The allowlist now means the scanner would not complain
    if one came back — so this asserts that none has. If a test needs a secret-shaped value,
    build it (`".".join(...)`, `"ghp" + "_" + ...`) as `CONTRIBUTING.md` says; do not re-add a
    literal on the grounds that this file already permits it.
    """
    literals = _allowed_literals()
    assert len(literals) == 4, f"the allowlist changed size: {len(literals)}"

    offenders: list[str] = []
    for path in REPO_ROOT.rglob("*"):
        if not path.is_file() or any(part in SKIP_DIRS for part in path.parts):
            continue
        if path == CONFIG:
            continue  # the config quotes all four by construction; that is the point of it
        text = _text_or_none(path)
        if text is None:
            continue
        offenders += [
            f"{path.relative_to(REPO_ROOT)} contains an allowlisted fake as a literal"
            for literal in literals
            if literal in text
        ]
    assert not offenders, "\n".join(offenders)


def test_both_readers_of_this_config_are_pointed_at_it() -> None:
    """One source of truth, and a config that fails loudly rather than silently.

    The CI job names the path explicitly instead of relying on gitleaks finding a root
    `.gitleaks.toml` on its own: a config that is not loaded looks exactly like a config that
    is, except that four known-fake findings come back and nobody can see why. The pre-commit
    hook runs from the repository root and auto-detects the same file, so a value allowed in
    one place is allowed in both.
    """
    workflow = yaml.safe_load(SECURITY_WORKFLOW.read_text(encoding="utf-8"))
    steps = workflow["jobs"]["secrets"]["steps"]
    scanner = [step for step in steps if "gitleaks-action" in str(step.get("uses", ""))]
    assert len(scanner) == 1, "the secrets job no longer runs gitleaks"
    configured = str(scanner[0].get("env", {}).get("GITLEAKS_CONFIG", ""))
    assert configured.endswith(CONFIG.name), f"GITLEAKS_CONFIG is {configured!r}"

    checkout = [step for step in steps if "actions/checkout" in str(step.get("uses", ""))]
    assert str(checkout[0]["with"]["fetch-depth"]) == "0", (
        "a shallow clone makes the history scan silently narrow"
    )
    assert "id: gitleaks" in PRE_COMMIT.read_text(encoding="utf-8")
