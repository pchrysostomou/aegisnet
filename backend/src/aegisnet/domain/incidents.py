"""What an incident is, and the only ways it may change (Milestone 3; ADR-023).

An incident is a case: a set of alerts that describe one story about one entity, with a
number a human can say out loud, a severity derived from its members, and a status that only
moves along paths written down here.

Everything in this module is pure. The state machine is data, so the API, the CLI and the
tests all read the same table rather than each deciding what "closed" means; the severity
rule is a function of the members, so an incident's severity can always be recomputed from
its alerts rather than trusted because it was stored.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Final

from aegisnet.domain.enums import IncidentStatus

MAX_SEVERITY: Final = 5
MIN_SEVERITY: Final = 1
# Three distinct rules about one entity is the point where a set of alerts stops reading as
# coincidence. `docs/delivery-plan.md` M3 fixes the number; the bump it earns is one step.
ESCALATION_RULE_COUNT: Final = 3
ESCALATION_BUMP: Final = 1

CASE_NUMBER: Final = re.compile(r"^AEG-\d{4}-\d{4,}$")
TITLE_CHARS: Final = 200
# The database says the same thing (`ck_incident_notes_body_length`); saying it here too means
# an over-long note is refused with the field named rather than as an integrity error.
MAX_NOTE_CHARS: Final = 8000
MAX_CLOSURE_REASON_CHARS: Final = 500
# Control characters, except tab and newline. `domain/eve/sanitize.clean_text` strips the
# newline as well, which is right for a log line being squeezed into one field and wrong for a
# note somebody wrote in paragraphs. Same rule, with \x0a kept.
_CONTROL_CHARS: Final = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


class IncidentError(ValueError):
    """A rule of this module was broken by its caller."""


class IllegalTransitionError(IncidentError):
    """A status change that the workflow does not allow."""


class NoteBodyError(IncidentError):
    """Free text an analyst supplied that cannot be stored as written. Carries ``field`` and
    ``issue`` so the API's validation handler can name the offending field to the caller."""

    def __init__(self, field: str, issue: str) -> None:
        self.field = field
        self.issue = issue
        super().__init__(issue)


CLOSED_STATUSES: Final = frozenset(
    {
        IncidentStatus.closed_true_positive,
        IncidentStatus.closed_false_positive,
        IncidentStatus.closed_benign,
    }
)

# The workflow, as data. Read it as: from this status, an analyst may move to these.
#
# Two properties are deliberate. A case can be closed from any open state, because an analyst
# who has seen enough should not have to walk through the middle of the process to say so. And
# a closed case can be reopened only to `investigating` — never straight back to `new`, which
# would erase the fact that it had been looked at.
TRANSITIONS: Final[Mapping[IncidentStatus, frozenset[IncidentStatus]]] = {
    IncidentStatus.new: frozenset(
        {IncidentStatus.triaging, IncidentStatus.investigating, *CLOSED_STATUSES}
    ),
    IncidentStatus.triaging: frozenset(
        {IncidentStatus.investigating, IncidentStatus.contained_recommended, *CLOSED_STATUSES}
    ),
    IncidentStatus.investigating: frozenset(
        {IncidentStatus.triaging, IncidentStatus.contained_recommended, *CLOSED_STATUSES}
    ),
    IncidentStatus.contained_recommended: frozenset(
        {IncidentStatus.investigating, *CLOSED_STATUSES}
    ),
    IncidentStatus.closed_true_positive: frozenset({IncidentStatus.investigating}),
    IncidentStatus.closed_false_positive: frozenset({IncidentStatus.investigating}),
    IncidentStatus.closed_benign: frozenset({IncidentStatus.investigating}),
}


def is_closed(status: IncidentStatus) -> bool:
    return status in CLOSED_STATUSES


def allowed_from(status: IncidentStatus) -> frozenset[IncidentStatus]:
    return TRANSITIONS[status]


def check_transition(current: IncidentStatus, target: IncidentStatus) -> None:
    """Raise unless the workflow allows ``current`` → ``target``.

    A move to the status a case is already in is refused rather than ignored: it is almost
    always a client that lost track, and answering "done" would hide that.
    """
    if target == current:
        raise IllegalTransitionError(f"{current.value} is already the status")
    if target not in TRANSITIONS[current]:
        allowed = ", ".join(sorted(s.value for s in TRANSITIONS[current]))
        raise IllegalTransitionError(f"{current.value} may become {allowed}, not {target.value}")


@dataclass(frozen=True, slots=True)
class Severity:
    """A case's severity and the arithmetic that produced it, so it can be re-derived rather
    than believed."""

    value: int
    member_max: int
    distinct_rules: int
    escalated: bool

    def rationale(self) -> dict[str, object]:
        return {
            "formula": "min(5, max(member severities) + (1 if distinct rules >= 3 else 0))",
            "member_max": self.member_max,
            "distinct_rules": self.distinct_rules,
            "escalated": self.escalated,
            "result": self.value,
        }


def severity_of(severities: Iterable[int], rule_ids: Iterable[str]) -> Severity:
    """The case's severity: the worst of its members, plus one step when at least three
    distinct rules agree that something is happening to this entity."""
    members = list(severities)
    if not members:
        raise IncidentError("an incident has at least one alert")
    for value in members:
        if not MIN_SEVERITY <= value <= MAX_SEVERITY:
            raise IncidentError(f"member severity {value} is outside 1..5")
    distinct = len(set(rule_ids))
    if distinct < 1:
        raise IncidentError("an incident names at least one rule")
    member_max = max(members)
    escalated = distinct >= ESCALATION_RULE_COUNT
    value = min(MAX_SEVERITY, member_max + (ESCALATION_BUMP if escalated else 0))
    return Severity(
        value=value, member_max=member_max, distinct_rules=distinct, escalated=escalated
    )


def case_number(year: int, ordinal: int) -> str:
    """``AEG-2026-0001``. The ordinal comes from a database sequence, so it is unique across
    concurrent runs; the year is the one the case was opened in, and the sequence does not
    reset, which keeps a case number unique for the life of the deployment."""
    if not 1970 <= year <= 9999:
        raise IncidentError(f"implausible year: {year}")
    if ordinal < 1:
        raise IncidentError("a case ordinal starts at 1")
    number = f"AEG-{year:04d}-{ordinal:04d}"
    if not CASE_NUMBER.match(number):  # pragma: no cover - the format is constructed above
        raise IncidentError(f"malformed case number: {number}")
    return number


def title_for(rule_ids: Iterable[str], entity: str, asset_hostname: str | None = None) -> str:
    """What the case is called in a list. Derived, never free text: a title an operator can
    scan is worth more than one an operator has to write, and a derived title cannot drift
    from the alerts underneath it."""
    rules = sorted(set(rule_ids))
    if not rules:
        raise IncidentError("an incident names at least one rule")
    subject = asset_hostname or entity
    if len(rules) == 1:
        body = f"{rules[0]} on {subject}"
    elif len(rules) == 2:
        body = f"{rules[0]} and {rules[1]} on {subject}"
    else:
        body = f"{len(rules)} rules on {subject}: {', '.join(rules)}"
    return body[:TITLE_CHARS]


@dataclass(frozen=True, slots=True)
class Window:
    """When a case's alerts happened. Grows as alerts join; never shrinks."""

    start: datetime
    end: datetime

    def __post_init__(self) -> None:
        if self.start.tzinfo is None or self.end.tzinfo is None:
            raise IncidentError("an incident window is timezone-aware")
        if self.end < self.start:
            raise IncidentError("an incident window ends after it starts")

    def extended_to(self, first_seen: datetime, last_seen: datetime) -> Window:
        return Window(min(self.start, first_seen), max(self.end, last_seen))


def clean_note_body(body: str) -> str:
    """What an analyst typed, made safe to store and to render, or a refusal.

    Refused rather than truncated: a note silently cut in half is worse than a note the
    author is told to shorten, and this is the one place free text enters a case.
    """
    cleaned = _CONTROL_CHARS.sub("", body).strip()
    if not cleaned:
        raise NoteBodyError("body", "a note needs something in it")
    if len(cleaned) > MAX_NOTE_CHARS:
        raise NoteBodyError("body", f"a note is at most {MAX_NOTE_CHARS} characters")
    return cleaned


def clean_closure_reason(reason: str | None) -> str | None:
    """Why a case was closed, under the same rules as a note and a shorter cap.

    ``None`` and blank both mean "no reason given", because a caller that sends an empty
    string is not making a statement and the column should not pretend it did.
    """
    if reason is None:
        return None
    cleaned = _CONTROL_CHARS.sub("", reason).strip()
    if not cleaned:
        return None
    if len(cleaned) > MAX_CLOSURE_REASON_CHARS:
        raise NoteBodyError(
            "closure_reason", f"a closure reason is at most {MAX_CLOSURE_REASON_CHARS} characters"
        )
    return cleaned
