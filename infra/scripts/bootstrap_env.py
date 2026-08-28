#!/usr/bin/env python3
"""Generate a local development-only .env from .env.example (decision F-1 / ADR-011).

Every ``__REPLACE_ME__`` placeholder is replaced with a cryptographically random,
URL-safe secret. The result is written with 0600 permissions where the platform
supports it.

Guarantees:
  * Idempotent: running it again when .env already exists is a no-op unless --force.
  * Never overwrites an existing .env without an explicit --force.
  * Never prints a generated secret to stdout.
  * Generates development-only credentials. These are NOT suitable for any
    production deployment; see SECURITY.md.

Usage:
    python infra/scripts/bootstrap_env.py [--force] [--example PATH] [--out PATH]
"""

from __future__ import annotations

import argparse
import os
import secrets
import stat
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


def _restrict_permissions(path: Path) -> bool:
    """Best-effort 0600. Returns True when the mode was applied."""
    try:
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    except (OSError, NotImplementedError):
        return False
    return True


def main(argv: list[str] | None = None) -> int:
    root = _repo_root()
    parser = argparse.ArgumentParser(description="Bootstrap a local .env for AegisNet.")
    parser.add_argument("--force", action="store_true", help="overwrite an existing .env")
    parser.add_argument("--example", type=Path, default=root / ".env.example")
    parser.add_argument("--out", type=Path, default=root / ".env")
    args = parser.parse_args(argv)

    if not args.example.is_file():
        print(f"error: template not found: {args.example}", file=sys.stderr)
        return 2

    if args.out.exists() and not args.force:
        print(f"{args.out.name} already exists — leaving it untouched. Use --force to regenerate.")
        return 0

    generated = 0
    out_lines: list[str] = []
    for line in args.example.read_text(encoding="utf-8").splitlines(keepends=True):
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
    fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.writelines(out_lines)
    except Exception:  # pragma: no cover - surfaced to the operator
        raise

    restricted = _restrict_permissions(args.out)

    print(f"wrote {args.out.name} with {generated} generated development-only secret(s)")
    if not restricted:
        print(
            "warning: could not set 0600 permissions on this platform — "
            "restrict access to .env manually",
            file=sys.stderr,
        )
    print("reminder: .env is gitignored and must never be committed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
