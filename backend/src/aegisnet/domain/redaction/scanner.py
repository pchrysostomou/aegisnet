"""A denylist for things that must never leave (T-3.1, T-3.3).

This is the **second** line of defence and is written to be understood as such. The first is
the allow-list in `packet.py`: a field reaches a request body only because somebody added it
by name, and almost everything sent is a derived number. This scanner exists for the case
where an allow-listed field turns out to carry something it should not — a credential pasted
into a note, a token in a URL path, a key in a signature name.

It is deliberately eager. A false positive costs a dropped field and a recorded reason; a
false negative costs a secret sent to a third party, and the threat model says to assume
anything sent may be retained.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

# Each pattern is named, because "this field was dropped" is not a useful thing to record —
# "this field was dropped because it looked like an AWS access key id" is.
SECRET_PATTERNS: Final[tuple[tuple[str, re.Pattern[str]], ...]] = (
    ("email", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")),
    ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA)[0-9A-Z]{12,}\b")),
    ("private_key_block", re.compile(r"-{2,}\s*BEGIN[A-Z ]*PRIVATE KEY\s*-{2,}", re.IGNORECASE)),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("bearer_token", re.compile(r"\b(?:bearer|token)\s+[A-Za-z0-9._~+/-]{16,}=*", re.IGNORECASE)),
    (
        "credential_assignment",
        re.compile(
            r"\b(?:pass(?:word|wd)?|secret|api[_-]?key|access[_-]?key|client[_-]?secret|"
            r"auth|credential)\b\s*[:=]\s*\S{4,}",
            re.IGNORECASE,
        ),
    ),
    ("slack_or_github_token", re.compile(r"\b(?:xox[abprs]-|ghp_|gho_|ghs_|github_pat_)\S{8,}")),
    ("private_key_body", re.compile(r"\bMII[A-Za-z0-9+/]{40,}={0,2}")),
    # A long run of base64 is how a blob of anything travels. The pattern only finds the run;
    # whether it *looks* like encoded bytes — mixed case and a digit, which a real blob of
    # random bytes has within sixty characters with probability near one — is decided in
    # Python afterwards. Expressing that with lookaheads meant three more passes over the same
    # attacker-influenced run, and a regex that can backtrack over untrusted input is a denial
    # of service in the very code meant to make it safe.
    ("base64_blob", re.compile(r"\b[A-Za-z0-9+/]{60,}={0,2}\b")),
)

MAX_FREE_TEXT_CHARS: Final = 200
_CONTROL_CHARS: Final = re.compile(r"[\x00-\x08\x0a-\x1f\x7f-\x9f]")


@dataclass(frozen=True, slots=True)
class SecretFound:
    """Which rule matched, and where. The matched text itself is never carried: recording it
    would move the secret into the log this scanner exists to keep it out of."""

    pattern: str
    field: str


def _looks_encoded(run: str) -> bool:
    """Mixed case and a digit: what distinguishes a blob of bytes from a long hostname, a hex
    digest, or sixty of the same character."""
    return (
        any(c.islower() for c in run)
        and any(c.isupper() for c in run)
        and any(c.isdigit() for c in run)
    )


def _matches(name: str, pattern: re.Pattern[str], value: str) -> bool:
    if name != "base64_blob":
        return pattern.search(value) is not None
    return any(_looks_encoded(match.group(0)) for match in pattern.finditer(value))


def scan(value: str, *, field: str = "") -> tuple[SecretFound, ...]:
    """Every denylist rule that matches, in declaration order."""
    return tuple(
        SecretFound(pattern=name, field=field)
        for name, pattern in SECRET_PATTERNS
        if _matches(name, pattern, value)
    )


def clean_free_text(value: str, *, field: str = "", limit: int = MAX_FREE_TEXT_CHARS) -> str | None:
    """A string that may be sent, or ``None`` because it may not.

    Control characters go first — they are how a payload hides from a reader and from a regex
    written for one line. Then the denylist. Then the length cap, because a field that is
    suddenly long is a field being used as a channel (T-3.5).
    """
    cleaned = _CONTROL_CHARS.sub("", value).strip()
    if not cleaned:
        return None
    if scan(cleaned, field=field):
        return None
    return cleaned[:limit]
