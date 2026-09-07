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
    # The unbounded local part was the expensive half, and the bound is the whole fix. On text
    # with no at-sign, `[A-Za-z0-9._%+-]+` matched to the end from every start position and
    # failed on `@` each time — quadratic, 0.69 s on twenty thousand characters. RFC 5321 caps a
    # local part at 64 octets, so the bound is the true shape of an address rather than a number
    # picked to placate a profiler, and a mutation test brings the slowness back without it.
    #
    # The domain stays unbounded: capping it at RFC 5321's 255 was measured to *lose* a
    # detection, a 304-character domain with a real TLD stopped being seen.
    #
    # `\.[A-Za-z]{2,}` stays in the pattern, and the attempt to move it into Python is worth
    # recording because it was wrong twice over. It was justified as "one less backtracking
    # construct", which the mutation test contradicted — with the local part bounded, the tail is
    # linear. And it silently **lost detections**: the greedy domain run stops only at the next
    # `@`, so `finditer` yielded one run for `a@b.1analyst@corp.example.com`, the Python check
    # rejected it, and the scan resumed past it instead of backtracking to the shorter split. A
    # real address preceded by a near-miss went unseen. Two cases below pin that.
    ("email", re.compile(r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")),
    ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA)[0-9A-Z]{12,}\b")),
    # `-{2,}` unbounded is quadratic on a run of dashes — a separator line in a log, or the
    # body of a PEM block itself. The engine takes every dash, fails on `BEGIN`, gives one
    # back, fails again, and does that from every start position: 4.09 s on twenty thousand
    # dashes. PEM writes exactly five, so ten is already generous, and bounding it changes
    # no answer — a longer run still matches, because the search starts at every position.
    (
        "private_key_block",
        re.compile(r"-{2,10}\s*BEGIN[A-Z ]*PRIVATE KEY\s*-{2,10}", re.IGNORECASE),
    ),
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


_DECIDED_IN_PYTHON: Final = {"base64_blob": _looks_encoded}


def _matches(name: str, pattern: re.Pattern[str], value: str) -> bool:
    decide = _DECIDED_IN_PYTHON.get(name)
    if decide is None:
        return pattern.search(value) is not None
    return any(decide(match.group(0)) for match in pattern.finditer(value))


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
