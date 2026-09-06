#!/usr/bin/env python3
"""Generate a local development-only .env from .env.example (decision F-1 / ADR-011).

Every ``__REPLACE_ME__`` placeholder is replaced with a cryptographically random,
URL-safe secret. The file is created with mode 0600 in the ``os.open`` call itself, so
on POSIX there is never a moment when it is readable by anyone else; the umask can only
tighten that mode, never loosen it, which is why no ``chmod`` follows.

Guarantees:
  * Idempotent: running it again when .env already exists is a no-op unless --force.
  * Never overwrites an existing .env without an explicit --force.
  * ``--add-missing`` appends keys the template has and the existing file does not, generating
    secrets for their placeholders, and changes no line that is already there. That is what an
    operator wants after pulling a release that added a variable — the alternative is a stack
    that starts and quietly lacks a role.
  * **Takes no path.** Both files are resolved from the checkout this script is in:
    ``<root>/.env.example`` and ``<root>/.env``. There used to be ``--example`` and ``--out``,
    and SonarCloud rated the change that added a second read and an append through them as a
    security finding on new code — a path from ``argv`` reaching file I/O, the same taint this
    project removed from both generators, ``eval-detectors`` and the capture sanitiser. The
    flags had no user beyond the tests, so the honest fix was to stop accepting them rather
    than to argue about whether this particular argv is trustworthy.
  * Never prints a generated secret to stdout.
  * Generates development-only credentials. These are NOT suitable for any
    production deployment; see SECURITY.md.

Usage:
    python infra/scripts/bootstrap_env.py [--force | --add-missing]
"""

from __future__ import annotations

import argparse
import os
import secrets
import sys
from pathlib import Path

PLACEHOLDER = "__REPLACE_ME__"
SECRET_BYTES = 48


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _is_assignment(line: str) -> bool:
    """True for a ``KEY=VALUE`` line, False for blanks and comments.

    Comment lines are skipped deliberately: ``.env.example`` documents the placeholder token
    in its own header, and substituting there would corrupt the explanation and inflate the
    reported count.
    """
    stripped = line.lstrip()
    return bool(stripped) and not stripped.startswith("#") and "=" in stripped


def _generate(line: str) -> str:
    """Replace every placeholder occurrence on a line with a fresh random secret."""
    while PLACEHOLDER in line:
        line = line.replace(PLACEHOLDER, secrets.token_urlsafe(SECRET_BYTES), 1)
    return line


def _key(line: str) -> str:
    return line.split("=", 1)[0].strip()


def _add_missing(example: Path, out: Path) -> int:
    """Append only what is absent. Existing values are never read, rewritten or reordered."""
    existing = {
        _key(line) for line in out.read_text(encoding="utf-8").splitlines() if _is_assignment(line)
    }
    added: list[str] = []
    for line in example.read_text(encoding="utf-8").splitlines(keepends=True):
        if _is_assignment(line) and _key(line) not in existing:
            added.append(_generate(line) if PLACEHOLDER in line else line)

    if not added:
        print(f"{out.name} already has every key in the template")
        return 0

    with out.open("a", encoding="utf-8") as handle:
        handle.write("\n# --- appended by bootstrap_env.py --add-missing ---\n")
        handle.writelines(line if line.endswith("\n") else line + "\n" for line in added)
    print(f"added {len(added)} missing key(s) to {out.name}: " + ", ".join(_key(a) for a in added))
    return 0


def main(argv: list[str] | None = None) -> int:
    root = _repo_root()
    parser = argparse.ArgumentParser(description="Bootstrap a local .env for AegisNet.")
    parser.add_argument("--force", action="store_true", help="overwrite an existing .env")
    parser.add_argument(
        "--add-missing",
        action="store_true",
        help="append keys the template has and .env does not; never edits an existing line",
    )
    args = parser.parse_args(argv)

    # Fixed names under the checkout this file is in. Nothing here is taken from a caller.
    example = root / ".env.example"
    out = root / ".env"

    if not example.is_file():
        print(f"error: template not found: {example}", file=sys.stderr)
        return 2

    if out.exists() and args.add_missing:
        return _add_missing(example, out)

    if out.exists() and not args.force:
        print(
            f"{out.name} already exists — leaving it untouched. "
            "Use --add-missing to append new keys, or --force to regenerate."
        )
        return 0

    generated = 0
    out_lines: list[str] = []
    for line in example.read_text(encoding="utf-8").splitlines(keepends=True):
        if PLACEHOLDER in line and _is_assignment(line):
            generated += line.count(PLACEHOLDER)
            line = _generate(line)
        out_lines.append(line)

    unresolved = [
        line.split("=", 1)[0].strip()
        for line in out_lines
        if PLACEHOLDER in line and _is_assignment(line)
    ]
    if unresolved:
        print(
            "error: placeholders left unresolved: " + ", ".join(unresolved),
            file=sys.stderr,
        )
        return 1

    # Create with restrictive permissions from the outset where possible, so there is no
    # window in which the file is world-readable.
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.writelines(out_lines)
    except Exception:  # pragma: no cover - surfaced to the operator
        raise

    print(f"wrote {out.name} with {generated} generated development-only secret(s)")
    if os.name != "posix":
        print(
            "warning: file permissions are not enforced on this platform — "
            "restrict access to .env manually",
            file=sys.stderr,
        )
    print("reminder: .env is gitignored and must never be committed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
