"""What a model is allowed to say, and what happens when it says something else (TB-4).

The fixtures are committed responses. Each one is a way an answer can be plausible, fluent and
unfit to store — an uncited claim about a threat actor, a citation number pointing at nothing,
a plaintext link, a recommendation that has quietly become an instruction.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from aegisnet.domain.briefs import (
    Claim,
    InvestigationBrief,
    Recommendation,
    SafetyRejectedError,
    admit,
)

pytestmark = pytest.mark.security

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "briefs"


def document(name: str) -> dict[str, Any]:
    """The brief the model wrote, out of the completion that carried it."""
    completion = json.loads((FIXTURES / f"{name}.json").read_text())
    return json.loads(completion["choices"][0]["message"]["content"])


def test_a_good_brief_is_admitted_whole() -> None:
    brief = InvestigationBrief.model_validate(document("good"))
    assert brief.summary.startswith("Host asset-A scanned")
    assert len(brief.claims) == 3
    assert [c.kind for c in brief.claims] == ["observed", "observed", "external"]
    assert brief.recommendations[0].action is Recommendation.investigate_host
    assert brief.has_unverified is False
    assert brief.limitations


def test_a_brief_says_what_it_could_not_see() -> None:
    """Not a formality: an analyst reading a confident paragraph needs to know it was written
    without process or user context."""
    brief = InvestigationBrief.model_validate(document("good"))
    assert "no process or user context" in brief.limitations


# ---------------------------------------------------------------- T-4.2


def test_an_uncited_external_claim_is_kept_and_marked_unverified() -> None:
    """Kept, not dropped. A reader deciding what to trust is better served by seeing the claim
    and its status than by a silent deletion they cannot know happened."""
    brief = InvestigationBrief.model_validate(document("uncited"))
    assert brief.has_unverified is True
    (unverified,) = brief.unverified
    assert "APT-99" in unverified.text
    assert unverified.kind == "external"
    # Everything else in the same brief is unaffected.
    assert len(brief.claims) == 4
    assert sum(1 for c in brief.claims if c.verified) == 3


def test_an_observed_claim_needs_no_citation_because_it_came_from_the_packet() -> None:
    observed = Claim(text="asset-A reached 40 ports.", kind="observed", citations=[])
    external = Claim(text="This is a known campaign.", kind="external", citations=[])
    assert observed.verified is True
    assert external.verified is False


def test_a_citation_number_pointing_at_nothing_is_a_refusal() -> None:
    """A dangling reference is a fabricated citation wearing a number, which reads as more
    trustworthy than no citation at all."""
    with pytest.raises(ValidationError, match="does not list"):
        InvestigationBrief.model_validate(document("dangling-citation"))


def test_a_plaintext_citation_is_refused() -> None:
    with pytest.raises(ValidationError, match="https"):
        InvestigationBrief.model_validate(document("insecure-citation"))


@pytest.mark.parametrize(
    "url",
    [
        "http://example.test/a",
        "javascript:alert(1)",
        "https://user:pass@example.test/a",
        "ftp://example.test",
        "example.test/a",
        "https://exa mple.test",
    ],
)
def test_a_citation_url_must_be_something_safe_to_click(url: str) -> None:
    with pytest.raises(ValidationError):
        InvestigationBrief.model_validate(
            {
                "summary": "s",
                "claims": [],
                "recommendations": [],
                "citations": [{"id": 1, "url": url, "title": "t"}],
                "limitations": "",
            }
        )


# ---------------------------------------------------------------- T-4.3


def test_a_brief_that_recommends_acting_on_a_system_is_rejected() -> None:
    with pytest.raises(SafetyRejectedError) as rejected:
        admit(document("unsafe"))
    assert rejected.value.rule in {"automated_blocking", "active_scanning"}
    assert rejected.value.where.startswith("recommendations[")


@pytest.mark.parametrize(
    ("passage", "rule"),
    [
        ("We should hack back at the source.", "offensive_action"),
        ("Scan the attacker to map their infrastructure.", "active_scanning"),
        ("Immediately block the remote address at the edge.", "automated_blocking"),
        ("Delete the logs once you have looked at them.", "destructive"),
        ("Take down the domain through the registrar.", "takedown"),
        ("Brute force the account to see if it is weak.", "credential_use"),
        ("Exploit the service to confirm the version.", "offensive_action"),
    ],
)
def test_every_forbidden_shape_is_caught_wherever_it_appears(passage: str, rule: str) -> None:
    with pytest.raises(SafetyRejectedError) as rejected:
        admit(
            {
                "summary": passage,
                "claims": [],
                "recommendations": [],
                "citations": [],
                "limitations": "",
            }
        )
    assert rejected.value.rule == rule


def test_a_recommendation_outside_the_vocabulary_is_not_interpreted() -> None:
    """The action is an enum, so a model that invents one is refused rather than
    approximated."""
    with pytest.raises(ValidationError):
        InvestigationBrief.model_validate(
            {
                "summary": "s",
                "claims": [],
                "recommendations": [{"action": "block_at_firewall", "detail": ""}],
                "citations": [],
                "limitations": "",
            }
        )


def test_ordinary_advice_is_not_mistaken_for_an_instruction() -> None:
    """The filter has to leave the useful sentences alone, or it will be turned off."""
    brief = admit(
        {
            "summary": "asset-A behaved unusually; the owner may recognise the upload.",
            "claims": [],
            "recommendations": [
                {
                    "action": "review_with_asset_owner",
                    "detail": "Ask whether a backup job runs at this hour.",
                },
                {"action": "monitor", "detail": "Watch for another sixty-second pattern."},
            ],
            "citations": [],
            "limitations": "No user context.",
        }
    )
    assert len(brief.recommendations) == 2


# ---------------------------------------------------------------- bounds and shape


def test_an_unknown_field_is_a_refusal_rather_than_something_to_ignore() -> None:
    payload = document("good")
    payload["severity"] = 1
    with pytest.raises(ValidationError, match=r"[Ee]xtra"):
        InvestigationBrief.model_validate(payload)


def test_a_brief_cannot_change_anything_about_the_case() -> None:
    """The narrative-only property of T-4.1, asserted at the type: there is no field here
    through which a model could express a severity, a status or a verdict."""
    fields = set(InvestigationBrief.model_fields)
    assert fields == {"summary", "claims", "recommendations", "citations", "limitations"}
    assert not fields & {"severity", "status", "verdict", "confidence", "alert_ids"}


def test_control_characters_are_stripped_from_everything_a_reader_sees() -> None:
    brief = InvestigationBrief.model_validate(
        {
            "summary": "line\x07one\x00",
            "claims": [{"text": "a\x1fclaim", "kind": "observed", "citations": []}],
            "recommendations": [{"action": "monitor", "detail": "de\x08tail"}],
            "citations": [],
            "limitations": "",
        }
    )
    assert brief.summary == "lineone"
    assert brief.claims[0].text == "aclaim"
    assert brief.recommendations[0].detail == "detail"


def test_an_enormous_answer_is_refused_field_by_field() -> None:
    with pytest.raises(ValidationError):
        InvestigationBrief.model_validate(
            {
                "summary": "x" * 5000,
                "claims": [],
                "recommendations": [],
                "citations": [],
                "limitations": "",
            }
        )
    with pytest.raises(ValidationError):
        InvestigationBrief.model_validate(
            {
                "summary": "s",
                "claims": [{"text": "c", "kind": "observed", "citations": []} for _ in range(50)],
                "recommendations": [],
                "citations": [],
                "limitations": "",
            }
        )
