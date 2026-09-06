"""The case as a document (Milestone 5, Chunk 24; ADR-032).

Two properties shape everything here, and they pull against each other.

**The same case renders to the same bytes.** Not "looks the same" — identical, so two exports
can be diffed and a difference means the case changed rather than the renderer did. That rules
out more than it sounds like: no clock (a "generated at" line would make every export unique),
no dictionary iteration order, no locale, no naive datetime read against the machine's zone, no
collection whose order the database did not fix. Every sort here ends in a unique key for that
reason, and the module takes no clock and does no I/O.

**Everything in it is untrusted text going into a document somebody will open.** A rule id, an
entity value, an alert's evidence, an analyst's note and a model's summary are all strings this
project did not write, and a Markdown viewer is a renderer like any other: a note containing
`# ` becomes a heading, one containing `[go](http://…)` becomes a link, one containing `<img>`
may become a request. So the document's structure is ours and its content is inert — every
untrusted string is backslash-escaped for prose or fenced for machine data, and the escape is
total rather than clever (every ASCII punctuation character, which CommonMark defines as
escapable) because an allow-list of "the ones that matter" is how a renderer gets surprised.

It is the same decision as `SafeMarkdown` in the dashboard (ADR-027) pointed the other way:
there, hostile text is parsed into elements so no markup can exist; here, hostile text is
escaped into a document so no markup can form.

What this report is **not** is redacted. It carries the case as it is — real addresses, real
hostnames, the analyst's own words — because it is written for the operator who can already
read every one of those through the API. `domain/redaction` exists for the other direction,
where the reader is a third party (ADR-029). The document says so at the top, in its own words,
so nobody learns that fact from a leak instead.
"""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

from aegisnet.domain.enums import BriefSource, BriefStatus
from aegisnet.domain.ports import (
    AlertRecord,
    AssetRecord,
    BatchSummary,
    BriefRecord,
    IncidentRecord,
    NoteRecord,
    TimelineEntryRecord,
)

ASCII_PUNCTUATION = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
"""CommonMark: a backslash before any of these makes it a literal. Escaping all of them is
uglier to read raw and impossible to get wrong; escaping a chosen subset is the reverse."""

# Everything C0 except tab, newline and carriage return, plus DEL. These are stripped rather
# than escaped: they have no rendering, and a document is not the place to preserve them.
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_BACKTICKS = re.compile(r"`+")

# Characters that change how text *looks* without being visible themselves: bidirectional
# overrides, zero-width spaces and joiners, word joiners, the byte-order mark. A right-to-left
# override in an analyst's note can make one string render as another, which in a document
# about an attack is the attack.
#
# They are not stripped. A report about somebody who used these must still show that they did,
# so each is replaced by its own code point written out — the evidence survives and the trick
# does not.
_INVISIBLE = re.compile("[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]")

MIN_FENCE = 3
UNVERIFIED = "**UNVERIFIED**"
"""What an external claim that cited nothing is marked with, here and in the dashboard. Never
dropped: a claim nobody can check is worth reading precisely because it is marked (ADR-030)."""


# ---------------------------------------------------------------- inert text


def _visible(text: str) -> str:
    """Control characters gone, invisible formatting characters written out."""
    return _INVISIBLE.sub(lambda match: f"<U+{ord(match.group()):04X}>", _CONTROL.sub("", text))


def escape(text: str) -> str:
    """Untrusted text as prose. Renders as itself and can never become markup."""
    return "".join(
        "\\" + character if character in ASCII_PUNCTUATION else character
        for character in _visible(text)
    )


def one_line(text: str) -> str:
    """For a table cell or a heading, where a newline would end the construct early."""
    return " ".join(_visible(text).split())


def cell(text: str) -> str:
    return escape(one_line(text))


def code(text: str) -> str:
    """An identifier as a code span, with a backtick run longer than anything inside it.

    CommonMark strips one leading and one trailing space from a code span, so the padding is
    invisible; it is what allows a value that itself starts or ends with a backtick.
    """
    flat = one_line(text)
    if not flat:
        return "``"
    longest = max((len(run.group()) for run in _BACKTICKS.finditer(flat)), default=0)
    ticks = "`" * (longest + 1)
    return f"{ticks} {flat} {ticks}" if longest else f"`{flat}`"


def code_cell(text: str) -> str:
    """A value in a table cell. **Not a code span**, and that is the point.

    Two rounds of this got it wrong. GFM splits a row on `|` before it parses anything inline,
    so a pipe inside a code span ends the cell, unmatches the backticks, and turns the rest of
    somebody else's text into ordinary Markdown — the poisoned-case test found that on its
    first run, when an entity value containing `| a | b |` made a `javascript:` URL two cells
    later into a link. Escaping the pipe as `\\|` looked like the fix and is not: **a backslash
    cannot itself be escaped inside a code span**, so a value already containing `\\|` emits two
    backslashes, and a renderer that consumes the escaped backslash reads the pipe as a live
    delimiter. `\\|` and `\\\\|` are indistinguishable in the emitted text, which means no
    arbitrary value can be rendered as a code span in a table at all.

    So a table cell is escaped text, like every other untrusted string in prose — `escape`
    escapes the backslash too, so nothing survives to be re-read. Monospace in a table is worth
    less than a rule with no exceptions. Code spans remain, outside tables, where a pipe means
    nothing.
    """
    return cell(text)


def fenced(text: str, language: str = "") -> str:
    """Machine data as a fenced block, with a fence longer than any backtick run inside it."""
    body = _visible(text)
    longest = max((len(run.group()) for run in _BACKTICKS.finditer(body)), default=0)
    fence = "`" * max(MIN_FENCE, longest + 1)
    return f"{fence}{language}\n{body}\n{fence}"


def prose(text: str) -> str:
    """Multi-line untrusted text: every line escaped, blank lines kept as paragraph breaks.

    Leading whitespace goes. Every block construct in CommonMark begins with ASCII punctuation
    — which `escape` neutralises — except the indented code block, which begins with four
    spaces or a tab and is the one thing a backslash cannot touch. A pasted log excerpt would
    otherwise become a code block the report never wrote, and inside one a backslash stops
    being an escape, so the analyst's evidence would arrive full of visible `\\/` and `\\=`.
    Indentation carries no meaning in a rendered paragraph anyway, so nothing readable is lost.
    """
    lines = [escape(line.strip()) for line in _visible(text).splitlines()]
    return "\n".join(lines).strip("\n") or "_(empty)_"


# ---------------------------------------------------------------- stable values


def _utc(value: datetime) -> datetime:
    """Everything is rendered in UTC, because `when` stamps a `Z` on it.

    Two different problems, one function. An **aware** value is converted, so a caller holding
    the same instant in another zone renders the same line — passing it through untouched would
    print a local time and label it `Z`, which is worse than printing it wrong. A **naive** one
    is read as UTC rather than against whatever zone the machine is in, so the same row cannot
    render differently on two hosts. Every store returns `timestamptz`, so the second branch is
    a guard; the first is a conversion, and the `Z` is what makes it necessary.
    """
    return value.astimezone(UTC) if value.tzinfo is not None else value.replace(tzinfo=UTC)


def when(value: datetime | None) -> str:
    return "—" if value is None else _utc(value).strftime("%Y-%m-%d %H:%M:%SZ")


def ratio(value: float) -> str:
    """Two decimal places, so a float's repr never reaches the page."""
    return f"{value:.2f}"


def _json(value: Any) -> str:
    """Sorted keys, so a dictionary's iteration order cannot change the document."""
    return json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False, default=str)


# ---------------------------------------------------------------- sections


def _header(incident: IncidentRecord) -> list[str]:
    return [
        f"# {cell(incident.case_number)} — {cell(incident.title)}",
        "",
        "> This document is the case as it stands, in full: real addresses and hostnames, the",
        "> evidence each rule recorded, what analysts wrote, and any investigation brief that",
        "> was generated. **It is not redacted.** Treat it as you would the deployment it came",
        "> from. Text quoted from logs, from analysts and from a language model is escaped so a",
        "> viewer renders it as itself; it is still somebody else's words.",
        "",
    ]


def _facts(incident: IncidentRecord) -> list[str]:
    rows = [
        ("Case", code_cell(incident.case_number)),
        ("Severity", str(incident.severity)),
        ("Status", code_cell(incident.status.value)),
        ("Correlation key", code_cell(incident.correlation_key)),
        ("Distinct rules", str(incident.distinct_rule_count)),
        ("Activity window", f"{when(incident.window_start)} → {when(incident.window_end)}"),
        ("Opened", when(incident.created_at)),
        ("Last change", when(incident.updated_at)),
        ("Closed", when(incident.closed_at)),
    ]
    lines = ["## The case", "", "| Field | Value |", "| --- | --- |"]
    lines += [f"| {name} | {value} |" for name, value in rows]
    lines += ["", "Severity was derived, not chosen:", "", _fence_json(incident.severity_rationale)]
    if incident.closure_reason:
        lines += ["", "**Closed because:**", "", prose(incident.closure_reason)]
    lines.append("")
    return lines


def _fence_json(value: Any) -> str:
    return fenced(_json(value), "json")


def _alerts(alerts: Sequence[AlertRecord]) -> list[str]:
    lines = ["## Alerts in this case", ""]
    if not alerts:
        lines += ["_No alert is linked to this case._", ""]
        return lines

    lines += ["| Rule | Severity | Confidence | Entity | Events | First seen | Last seen |"]
    lines += ["| --- | --- | --- | --- | --- | --- | --- |"]
    for alert in alerts:
        lines.append(
            f"| {code_cell(alert.rule_id)} v{alert.rule_version} | {alert.severity} "
            f"| {ratio(alert.confidence)} "
            f"| {code_cell(f'{alert.entity_type.value}={alert.entity_value}')} "
            f"| {alert.event_count} | {when(alert.first_seen)} | {when(alert.last_seen)} |"
        )
    lines.append("")

    for alert in alerts:
        lines += [
            f"### {cell(alert.rule_id)} on {cell(alert.entity_value)}",
            "",
            f"- Alert: {code(str(alert.id))}",
            f"- Status: {code(alert.status.value)}",
            f"- Raised: {when(alert.created_at)}",
            "",
            "Evidence, as the rule recorded it:",
            "",
            _fence_json(alert.evidence),
            "",
        ]
    return lines


def _timeline(entries: Sequence[TimelineEntryRecord], *, complete: bool) -> list[str]:
    lines = ["## Timeline", ""]
    if not complete:
        lines += [
            "_This is the beginning of a longer story: the case has more entries than one"
            " document holds, and the rest is at the timeline endpoint._",
            "",
        ]
    if not entries:
        lines += ["_Nothing has happened to this case yet._", ""]
        return lines

    lines += ["| When | What | Summary |", "| --- | --- | --- |"]
    for entry in entries:
        lines.append(
            f"| {when(entry.occurred_at)} | {code_cell(entry.entry_type.value)} "
            f"| {cell(entry.summary)} |"
        )
    lines.append("")
    return lines


def _notes(notes: Sequence[NoteRecord], *, complete: bool) -> list[str]:
    lines = ["## Notes", ""]
    if not complete:
        lines += ["_These are the newest notes; this case has more than one document holds._", ""]
    if not notes:
        lines += ["_Nobody has written on this case._", ""]
        return lines

    for note in notes:
        lines += [f"### {when(note.created_at)}", "", prose(note.body), ""]
    return lines


def _brief(brief: BriefRecord) -> list[str]:
    origin = (
        "the offline sample committed to this repository, not a model"
        if brief.source is BriefSource.offline_fixture
        else f"model {code(brief.model or 'unknown')}"
    )
    lines = [
        f"### Version {brief.version} — {brief.status.value}",
        "",
        f"- Written by: {origin}",
        f"- Generated: {when(brief.created_at)}",
        f"- Evidence packet: {code(brief.packet_hash)}"
        + (" (truncated)" if brief.packet_truncated else ""),
    ]

    if brief.status is BriefStatus.failed:
        lines += [
            f"- Could not be generated: {code(brief.failure_reason or 'unknown')}",
            "",
            "_No brief was produced. The case above is unaffected: a brief is a narrative"
            " about it and never a part of it._",
            "",
        ]
        return lines

    lines += [
        "",
        "> Written by a language model from a redacted summary of this case. It is a reading,"
        " not a finding: nothing in it changed a severity, a status or an alert, and every"
        " claim below is either something the packet said or something the model looked up.",
        "",
        "#### Summary",
        "",
        prose(brief.summary or ""),
        "",
    ]

    if brief.claims:
        lines += ["#### Claims", ""]
        for claim in brief.claims:
            kind = str(claim.get("kind", "observed"))
            refs = [int(ref) for ref in claim.get("citations", []) or []]
            marker = "" if claim.get("verified", False) else f" {UNVERIFIED}"
            cited = f" [{', '.join(str(ref) for ref in sorted(refs))}]" if refs else ""
            lines.append(f"- _{cell(kind)}_ — {cell(str(claim.get('text', '')))}{cited}{marker}")
        lines.append("")

    if brief.recommendations:
        lines += ["#### What a person could do next", ""]
        for advice in brief.recommendations:
            action = code(str(advice.get("action", "")))
            detail = cell(str(advice.get("detail", "")))
            lines.append(f"- {action} — {detail}" if detail else f"- {action}")
        lines += [
            "",
            "_These are things to look at, not things to do to a system. The vocabulary has no"
            " word for blocking, scanning or taking anything down (ADR-030)._",
            "",
        ]

    if brief.citations:
        lines += ["#### Sources", ""]
        for citation in brief.citations:
            lines.append(
                # The brackets are escaped: a bare `[1]` is a link reference waiting for a
                # `[1]: …` definition, and definitions are exactly what a hostile note would add.
                f"- \\[{citation.citation_id}\\] {cell(citation.title)} — {code(citation.url)}"
            )
        lines += [
            "",
            "_Links are written out rather than linked, so reading this document cannot"
            " navigate anywhere on its own._",
            "",
        ]

    if brief.limitations:
        lines += ["#### What the brief could not see", "", prose(brief.limitations), ""]
    if brief.has_unverified:
        lines += [
            f"_This brief contains at least one claim marked {UNVERIFIED}: the model asserted"
            " something about the outside world and cited nothing for it._",
            "",
        ]
    return lines


def _briefs(briefs: Sequence[BriefRecord]) -> list[str]:
    lines = ["## Investigation briefs", ""]
    if not briefs:
        lines += ["_No brief has been generated for this case._", ""]
        return lines
    for brief in briefs:
        lines += _brief(brief)
    return lines


def _assets(assets: Sequence[AssetRecord]) -> list[str]:
    """Whose machines this case is about (FR-9.1).

    An address is not an answer: `10.10.0.42` tells a reader nothing about who to ring. What
    the inventory knows — the owner, the environment, how much the asset matters — is the part
    that turns a case into a decision.
    """
    lines = ["## Assets", ""]
    if not assets:
        lines += [
            "_No asset in the inventory matches this case. The addresses below were not"
            " resolved to anything, which is itself worth knowing._",
            "",
        ]
        return lines

    lines += [
        "| Host | Environment | Criticality | Owner | Networks |",
        "| --- | --- | --- | --- | --- |",
    ]
    for asset in assets:
        networks = ", ".join(code_cell(str(network.cidr)) for network in asset.networks) or "—"
        lines.append(
            f"| {code_cell(asset.hostname or str(asset.id))} "
            f"| {code_cell(asset.environment.value)} | {asset.criticality} "
            f"| {cell(asset.owner or '—')} | {networks} |"
        )
    lines.append("")

    for asset in assets:
        if not asset.tags and not asset.description and asset.is_active:
            continue
        lines.append(f"### {cell(asset.hostname or str(asset.id))}")
        lines.append("")
        if not asset.is_active:
            lines += ["- **Deactivated** in the inventory.", ""]
        if asset.tags:
            lines += ["- Tags: " + ", ".join(code(tag) for tag in sorted(asset.tags)), ""]
        if asset.description:
            lines += [prose(asset.description), ""]
    return lines


def _limitations(*, timeline_complete: bool, notes_complete: bool, assets: bool) -> list[str]:
    """What this document is not (FR-9.1).

    Every one of these is derivable from the sections above, and every one of them is the kind
    of thing a reader assumes the other way round unless it is written down.
    """
    lines = ["## Limitations of this document", ""]
    points = [
        "This is the case as the system recorded it. It is evidence of what the detectors saw,"
        " not proof of what happened.",
        "Every alert is a rule firing on a window of events. Detector accuracy is unmeasured"
        " and this project makes no claim about it.",
    ]
    if not timeline_complete:
        points.append("The timeline above is the beginning of a longer story, not all of it.")
    if not notes_complete:
        points.append("Only the newest notes on this case are included.")
    if not assets:
        points.append(
            "No asset in the inventory matched this case, so there is no owner named here."
        )
    points.append(
        "An investigation brief, where one is present, was written by a language model from a"
        " redacted summary. It changed nothing about the case and is not a finding."
    )
    lines += [f"- {point}" for point in points]
    lines.append("")
    return lines


def _provenance(
    batches: Sequence[BatchSummary], *, complete: bool, withheld: bool = False
) -> list[str]:
    """Where the evidence came from (FR-9.1).

    A report that cannot say which import its alerts rest on is a report that cannot be
    checked. These are the ingest batches behind the sampled events of this case's alerts —
    sampled, because an alert keeps a bounded handful of the events that produced it, so this
    is the provenance of what was kept rather than of every packet that ever matched.
    """
    lines = ["## Appendix: where this evidence came from", ""]
    if withheld:
        lines += [
            "_Not included: naming the imports behind a case means naming their source labels,"
            " their datasets and their line counts, and reading those is a separate permission"
            " (`ingest.read`) this account does not hold. An analyst's export carries them._",
            "",
        ]
        return lines
    if not batches:
        lines += ["_The ingest batches behind these alerts could not be traced._", ""]
        return lines

    lines += ["| Batch | Source | Dataset | Received | Stored | Rejected | Started |"]
    lines += ["| --- | --- | --- | --- | --- | --- | --- |"]
    for batch in batches:
        lines.append(
            f"| {code_cell(str(batch.batch_id))} | {cell(batch.source_label)} "
            f"| {code_cell(batch.dataset_id or '—')} | {batch.counts.received} "
            f"| {batch.counts.stored} | {batch.counts.rejected} | {when(batch.started_at)} |"
        )
    lines.append("")
    if not complete:
        lines += [
            "_Traced from a sample of each alert's events, so a batch that contributed only"
            " events outside that sample is not listed._",
            "",
        ]
    return lines


# ---------------------------------------------------------------- the document


def render_report(
    *,
    incident: IncidentRecord,
    alerts: Sequence[AlertRecord] = (),
    assets: Sequence[AssetRecord] = (),
    timeline: Sequence[TimelineEntryRecord] = (),
    notes: Sequence[NoteRecord] = (),
    briefs: Sequence[BriefRecord] = (),
    batches: Sequence[BatchSummary] = (),
    timeline_complete: bool = True,
    notes_complete: bool = True,
    provenance_complete: bool = True,
    provenance_withheld: bool = False,
) -> str:
    """One case as Markdown. A pure function of its arguments — no clock, no I/O, no settings.

    Every collection is sorted here rather than trusted to arrive ordered, and every sort ends
    in a unique key, because two rows sharing an instant must not be able to swap places
    between two exports.
    """
    ordered_alerts = sorted(alerts, key=lambda a: (_utc(a.first_seen), a.rule_id, str(a.id)))
    ordered_assets = sorted(assets, key=lambda a: (a.hostname or "", str(a.id)))
    ordered_batches = sorted(batches, key=lambda b: (_utc(b.started_at), str(b.batch_id)))
    ordered_timeline = sorted(timeline, key=lambda e: (_utc(e.occurred_at), str(e.id)))
    ordered_notes = sorted(notes, key=lambda n: (_utc(n.created_at), str(n.id)))
    ordered_briefs = sorted(briefs, key=lambda b: b.version)

    lines: list[str] = []
    lines += _header(incident)
    lines += _facts(incident)
    lines += _assets(ordered_assets)
    lines += _alerts(ordered_alerts)
    lines += _timeline(ordered_timeline, complete=timeline_complete)
    lines += _notes(ordered_notes, complete=notes_complete)
    lines += _briefs(ordered_briefs)
    lines += _limitations(
        timeline_complete=timeline_complete,
        notes_complete=notes_complete,
        assets=bool(ordered_assets),
    )
    lines += _provenance(
        ordered_batches, complete=provenance_complete, withheld=provenance_withheld
    )

    # One trailing newline, and no run of blank lines longer than one, so the bytes do not
    # depend on which sections happened to end with a spacer.
    document: list[str] = []
    for line in lines:
        if line == "" and document and document[-1] == "":
            continue
        document.append(line)
    return "\n".join(document).rstrip("\n") + "\n"


__all__ = [
    "ASCII_PUNCTUATION",
    "UNVERIFIED",
    "cell",
    "code",
    "code_cell",
    "escape",
    "fenced",
    "one_line",
    "prose",
    "ratio",
    "render_report",
    "when",
]
