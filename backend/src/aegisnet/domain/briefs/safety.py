"""What a brief is allowed to recommend (T-4.3).

A brief is advice to a person. It is never an instruction to a machine, and this project will
not ship something that reads like one — an incident tool whose AI output says "block
203.0.113.5" is one integration away from a tool that does.

So recommendations are an **enum**, not prose. The model chooses from a fixed vocabulary of
things an analyst does next, and anything outside it is a rejected brief rather than a
best-effort interpretation. The free-text detail beside each one is then scanned for the verbs
that would turn advice into an operation.
"""

from __future__ import annotations

import re
from enum import StrEnum, unique
from typing import Final


@unique
class Recommendation(StrEnum):
    """Everything a brief may suggest. All of it is something a human does, and none of it
    touches the network."""

    investigate_host = "investigate_host"
    review_with_asset_owner = "review_with_asset_owner"
    check_baseline = "check_baseline"
    collect_more_evidence = "collect_more_evidence"
    correlate_with_other_cases = "correlate_with_other_cases"
    monitor = "monitor"
    document_and_close = "document_and_close"
    escalate = "escalate"
    no_action_needed = "no_action_needed"


# Verbs that describe doing something *to* a system rather than learning about one. A brief
# containing any of these is rejected outright: the failure mode worth avoiding is a plausible,
# well-written paragraph that an analyst follows without noticing it crossed a line.
FORBIDDEN: Final[tuple[tuple[str, re.Pattern[str]], ...]] = (
    (
        "offensive_action",
        re.compile(r"\b(?:hack\s?back|retaliat\w*|counter-?attack|exploit)\b", re.I),
    ),
    (
        "active_scanning",
        re.compile(
            r"\b(?:scan|probe|enumerate|fingerprint)\s+(?:the\s+)?(?:attacker|source|host|target|remote)\b",
            re.I,
        ),
    ),
    (
        "automated_blocking",
        re.compile(
            r"\b(?:automatically|immediately)\s+(?:block|drop|null-?route|blackhole|quarantine|isolate)\b",
            re.I,
        ),
    ),
    (
        "destructive",
        re.compile(
            r"\b(?:wipe|destroy|delete\s+(?:the\s+)?(?:logs?|evidence)|format\s+the)\b", re.I
        ),
    ),
    ("takedown", re.compile(r"\b(?:take\s?down|deface|dos|ddos|flood)\b", re.I)),
    ("credential_use", re.compile(r"\b(?:brute[\s-]?force|crack|password\s+spray)\b", re.I)),
)


class SafetyRejectedError(ValueError):
    """A brief that will not be stored as written. Carries which rule refused it, so the
    stored record can say why without repeating the text."""

    def __init__(self, rule: str, where: str) -> None:
        self.rule = rule
        self.where = where
        super().__init__(f"{where} matched the {rule} rule")


def check(text: str, *, where: str) -> None:
    """Raise unless this passage is advice rather than an operation."""
    for rule, pattern in FORBIDDEN:
        if pattern.search(text):
            raise SafetyRejectedError(rule, where)


__all__ = ["FORBIDDEN", "Recommendation", "SafetyRejectedError", "check"]
