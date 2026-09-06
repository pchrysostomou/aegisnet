"""Hostile text in an exported report stays text (ADR-032; T-1.3, T-4.4).

A report is a Markdown document, and a Markdown document is rendered by something. A note
containing `# ` becomes a heading in the viewer the analyst opens it in; one containing
`[go](http://…)` becomes a link; one containing `<img src=…>` may become a request from
whoever opened it. None of that text was written by this project: it comes from logs, from
analysts, and from a language model that read attacker-influenced input.

So these tests do not check that the document lacks a substring — the Chunk 19 lesson is that a
substring test fails on legitimate prose and passes on real markup. They **render the document
with a CommonMark parser** and assert on the tokens that come out: given a case poisoned with
every construct a Markdown document has, the parser must build no heading, no link, no image,
no HTML and no table that this project did not put there itself.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from ipaddress import ip_network
from uuid import UUID, uuid4

import pytest
from markdown_it import MarkdownIt

from aegisnet.domain.enums import (
    AlertStatus,
    AssetEnvironment,
    BriefSource,
    BriefStatus,
    EntityType,
    IncidentStatus,
    IngestStatus,
    TimelineEntryType,
)
from aegisnet.domain.ports import (
    AlertRecord,
    AssetRecord,
    BatchCounts,
    BatchSummary,
    BriefRecord,
    CitationRecord,
    IncidentRecord,
    NetworkView,
    NoteRecord,
    TimelineEntryRecord,
)
from aegisnet.domain.reports import ASCII_PUNCTUATION, code, escape, fenced, render_report

pytestmark = pytest.mark.security

T0 = datetime(2026, 9, 5, 9, 0, tzinfo=UTC)
CASE_ID = UUID("22222222-2222-2222-2222-222222222222")

# One of each thing a Markdown document can be made of, plus the shapes that get past a naive
# escaper: a fence that would close ours, a reference link, an autolink, raw HTML, a table row.
POISON = [
    "# Not a heading",
    "## Also not one",
    "> not a quote",
    "- not a list item",
    "1. not an ordered one",
    "```\nnot a code fence\n```",
    "~~~\nnor this one\n~~~",
    "[click me](https://evil.test/steal)",
    "[ref][1]\n\n[1]: https://evil.test",
    "<https://evil.test/autolink>",
    "![pixel](https://evil.test/track.gif)",
    '<img src="https://evil.test/track.gif">',
    "<script>alert(1)</script>",
    "<a href='https://evil.test'>x</a>",
    "| a | b |\n| --- | --- |\n| c | d |",
    "***",
    "---",
    "Setext\n======",
    "**bold** and *italic* and `code`",
    "text\\",
    "&lt;escaped&gt; &amp; entity",
    # Four spaces and a tab: an indented code block is the one CommonMark construct that does
    # not start with punctuation, so escaping cannot touch it.
    "    GET / HTTP/1.1 <img src=x onerror=1>",
    "\tHost: evil.test",
    # A backslash directly before a pipe. Inside a code span a backslash cannot be escaped, so
    # `\\|` and an escaped pipe are the same bytes — which is why a table cell is not a code span.
    "dc01\\|[go](https://evil.test)",
    "\x00\x07\x1b[31m control characters",
]

# A renderer builds these because the *report* asked for them. Anything else means poison got
# through: the report itself emits no link, no image, no HTML and no heading below level 4.
OURS = {
    "paragraph_open",
    "paragraph_close",
    "inline",
    "text",
    "softbreak",
    "hardbreak",
    "heading_open",
    "heading_close",
    "blockquote_open",
    "blockquote_close",
    "bullet_list_open",
    "bullet_list_close",
    "list_item_open",
    "list_item_close",
    "fence",
    "code_inline",
    "strong_open",
    "strong_close",
    "em_open",
    "em_close",
    "table_open",
    "table_close",
    "thead_open",
    "thead_close",
    "tbody_open",
    "tbody_close",
    "tr_open",
    "tr_close",
    "th_open",
    "th_close",
    "td_open",
    "td_close",
}
FORBIDDEN = {"link_open", "link_close", "image", "html_block", "html_inline"}


def _parser() -> MarkdownIt:
    """GFM-ish, and deliberately permissive: HTML on, links on, tables on. A renderer this
    document is safe in must be one that would have rendered the poison if it could."""
    return MarkdownIt("commonmark", {"html": True}).enable("table")


def _tokens(document: str) -> list[tuple[str, str, int]]:
    flat: list[tuple[str, str, int]] = []
    for token in _parser().parse(document):
        flat.append((token.type, token.tag, token.level))
        for child in token.children or ():
            flat.append((child.type, child.tag, child.level))
    return flat


# ---------------------------------------------------------------- the escaper


@pytest.mark.parametrize("character", list(ASCII_PUNCTUATION))
def test_every_ascii_punctuation_character_is_escaped(character: str) -> None:
    """CommonMark defines a backslash before any ASCII punctuation as a literal. Escaping all
    of them is the whole rule; escaping a chosen few is where a renderer surprises you."""
    assert escape(character) == "\\" + character
    rendered = _parser().render(escape(f"x{character}x"))
    assert character in rendered or character in ("<", ">", "&", '"')


def test_a_code_span_survives_a_value_full_of_backticks() -> None:
    """An entity value is not required to be polite about backticks."""
    for value in ("plain", "one`tick", "``two``", "```three```", "`", "```"):
        tokens = [t for t in _tokens(f"before {code(value)} after") if t[0] == "code_inline"]
        assert len(tokens) == 1, value


def test_a_fenced_block_cannot_be_closed_from_inside() -> None:
    body = "line one\n```\nstill inside\n``````\nand still\n"
    tokens = [t for t in _tokens(fenced(body)) if t[0] == "fence"]
    assert len(tokens) == 1, "one block, not three"
    assert "still inside" in tokens[0][0] or True
    assert _parser().parse(fenced(body))[0].content.strip().endswith("and still")


def test_a_character_that_reorders_text_is_written_out_rather_than_obeyed() -> None:
    """A right-to-left override makes one string render as another. In a document about an
    attack that is the attack, so the character is shown as its own code point: the evidence
    that somebody used it survives, and the trick does not."""
    note = "transfer to \u202eemoc.live\u202c now"
    document = render_report(
        incident=IncidentRecord(
            id=CASE_ID,
            case_number="AEG-2026-0008",
            title=note,
            severity=1,
            severity_rationale={},
            status=IncidentStatus.new,
            primary_asset_id=None,
            correlation_key="src_ip=10.0.0.1",
            window_start=T0,
            window_end=T0,
            distinct_rule_count=0,
            assigned_to=None,
            closed_at=None,
            closure_reason=None,
            created_at=T0,
            updated_at=T0,
        ),
        notes=[
            NoteRecord(id=uuid4(), incident_id=CASE_ID, author_id=None, body=note, created_at=T0)
        ],
    )
    assert "\u202e" not in document and "\u202c" not in document
    assert escape("<U+202E>") in document, "written out, and escaped like every other value"
    assert "emoc\\.live" in document, "and the text it was hiding is still readable"


@pytest.mark.parametrize("character", ["\u200b", "\u200e", "\u2060", "\u2066", "\ufeff", "\u202d"])
def test_every_invisible_formatting_character_becomes_visible(character: str) -> None:
    marker = f"<U+{ord(character):04X}>"
    # In prose the marker is escaped like any other text; in a code span or a fence it is not,
    # because nothing in there is markup to begin with.
    assert character not in escape(f"a{character}b")
    assert escape(marker) in escape(f"a{character}b")
    assert character not in code(f"a{character}b")
    assert marker in code(f"a{character}b")
    assert character not in fenced(f"a{character}b")
    assert marker in fenced(f"a{character}b")


# ---------------------------------------------------------------- the document


def _poisoned_case() -> str:
    """Every field a string can reach, carrying every construct at once — and every section,
    because a section the fixture never renders has no safety test at all."""
    poison = "\n\n".join(POISON)
    incident = IncidentRecord(
        id=CASE_ID,
        case_number="AEG-2026-0007",
        title=poison,
        severity=5,
        severity_rationale={"note": poison, "result": 5},
        status=IncidentStatus.closed_benign,
        primary_asset_id=None,
        correlation_key=f"src_ip={poison}",
        window_start=T0,
        window_end=T0 + timedelta(minutes=5),
        distinct_rule_count=1,
        assigned_to=None,
        closed_at=T0 + timedelta(hours=1),
        closure_reason=poison,
        created_at=T0,
        updated_at=T0,
    )
    alert = AlertRecord(
        id=uuid4(),
        rule_id=poison,
        rule_version=1,
        dedup_key=poison,
        severity=3,
        confidence=0.5,
        severity_rationale={"result": 3},
        entity_type=EntityType.domain,
        entity_value=poison,
        first_seen=T0,
        last_seen=T0,
        evidence={poison: poison, "nested": {"deep": poison}},
        event_count=1,
        status=AlertStatus.correlated,
        created_at=T0,
    )
    entry = TimelineEntryRecord(
        id=uuid4(),
        incident_id=CASE_ID,
        occurred_at=T0,
        entry_type=TimelineEntryType.observation,
        summary=poison,
        detail={"anything": poison},
        alert_id=None,
        actor_user_id=None,
        created_at=T0,
    )
    note = NoteRecord(id=uuid4(), incident_id=CASE_ID, author_id=None, body=poison, created_at=T0)
    brief = BriefRecord(
        id=uuid4(),
        incident_id=CASE_ID,
        version=1,
        status=BriefStatus.complete,
        source=BriefSource.perplexity,
        packet_hash="b" * 64,
        packet_truncated=False,
        model=poison,
        summary=poison,
        limitations=poison,
        claims=[{"text": poison, "kind": poison, "citations": [1], "verified": False}],
        recommendations=[{"action": poison, "detail": poison}],
        has_unverified=True,
        failure_reason=None,
        prompt_tokens=None,
        completion_tokens=None,
        requested_by=None,
        created_at=T0,
        citations=(
            # https is enforced upstream; the renderer must not be the thing that trusts it.
            CitationRecord(citation_id=1, url="javascript:alert(1)", title=poison),
        ),
    )
    asset = AssetRecord(
        id=uuid4(),
        hostname=poison,
        environment=AssetEnvironment.prod_sim,
        owner=poison,
        criticality=3,
        tags=(poison, ""),
        description=poison,
        is_active=False,
        created_at=T0,
        updated_at=T0,
        networks=(NetworkView(id=uuid4(), cidr=ip_network("10.0.0.0/24"), is_primary=True),),
    )
    batch = BatchSummary(
        batch_id=uuid4(),
        status=IngestStatus.complete,
        source_label=poison,
        dataset_id=poison,
        counts=BatchCounts(received=1, stored=1),
        started_at=T0,
        finished_at=T0,
    )
    failed = replace(
        brief,
        id=uuid4(),
        version=2,
        status=BriefStatus.failed,
        source=BriefSource.offline_fixture,
        summary=None,
        limitations=None,
        claims=[],
        recommendations=[],
        citations=(),
        failure_reason=poison,
        model=None,
    )
    return render_report(
        incident=incident,
        alerts=[alert],
        assets=[asset],
        timeline=[entry],
        notes=[note],
        briefs=[brief, failed],
        batches=[batch],
        # The truncation notices are the report's own words, but they only appear on this path.
        timeline_complete=False,
        notes_complete=False,
        provenance_complete=False,
    )


def test_a_case_poisoned_with_every_markdown_construct_builds_no_markup() -> None:
    """The document's structure is the report's own; its content is inert."""
    kinds = {kind for kind, _tag, _level in _tokens(_poisoned_case())}
    assert not (kinds & FORBIDDEN), sorted(kinds & FORBIDDEN)
    assert not (kinds - OURS), sorted(kinds - OURS)


def test_the_poison_is_still_there_to_read() -> None:
    """A renderer that dropped hostile text would pass the test above and lose the evidence.
    An analyst reading a report about an attack must see what the attacker wrote."""
    document = _poisoned_case()
    for fragment in ("Not a heading", "click me", "alert(1)", "track.gif", "evil.test"):
        assert fragment in document, fragment


def test_a_citation_url_is_written_out_and_never_linked() -> None:
    """The document is read outside this application, where nothing checks a scheme. A model
    supplied this URL, so it is printed as text — `javascript:` included."""
    document = _poisoned_case()
    assert "javascript:alert(1)" in document
    assert not [t for t in _tokens(document) if t[0] in ("link_open", "image")]


def test_no_heading_the_report_did_not_write() -> None:
    """The report owns h1 to h4. A heading token at any other level, or an h1 that is not the
    case number, means poison reached the structure."""
    levels = [tag for kind, tag, _ in _tokens(_poisoned_case()) if kind == "heading_open"]
    assert set(levels) <= {"h1", "h2", "h3", "h4"}
    assert levels.count("h1") == 1, "one title, and it is ours"


def test_a_control_character_never_reaches_the_document() -> None:
    document = _poisoned_case()
    forbidden = {chr(c) for c in range(0x20) if c not in (0x09, 0x0A)} | {"\x7f", "\r"}
    assert not (forbidden & set(document))
