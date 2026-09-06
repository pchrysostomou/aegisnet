"""The only shape a brief may take (TB-4).

Everything on the far side of the Perplexity boundary is untrusted: the model may be wrong,
may have been steered by something an attacker planted, or may simply have invented a CVE that
reads plausibly. So the response is not "parsed" so much as *admitted* — it must arrive in this
schema, every field is bounded, and two rules decide whether it is fit to store:

* **A claim about the outside world needs a citation** (T-4.2). Anything the model asserts that
  did not come from the packet — a threat actor, a CVE, a campaign — must point at a resolvable
  https source. Uncited claims are kept and marked `UNVERIFIED` rather than dropped, because a
  reader deciding what to trust is better served by seeing the claim and its status than by a
  silent deletion.
* **A recommendation is advice, from a fixed vocabulary** (T-4.3, `safety.py`).

The brief is narrative only. Nothing here can change a severity, a status, or a detection
outcome — that is the structural half of T-4.1, and it is a property of where this type is
allowed to be used rather than of the type itself.
"""

from __future__ import annotations

import re
from typing import Annotated, Final, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from aegisnet.domain.briefs.safety import Recommendation, check

MAX_SUMMARY = 1200
MAX_CLAIM = 600
MAX_DETAIL = 400
MAX_CLAIMS = 20
MAX_CITATIONS = 20
MAX_RECOMMENDATIONS = 8

# https only, and no credentials in the URL. A citation is something a reader will click.
_HTTPS_URL: Final = re.compile(r"^https://[^\s/@]+(?:/[^\s]*)?$")
_CONTROL: Final = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def _clean(value: str, limit: int) -> str:
    return _CONTROL.sub("", value).strip()[:limit]


class Strict(BaseModel):
    """Unknown fields are a refusal, not something to ignore: a response carrying a key this
    schema does not know is a response written against a different contract."""

    model_config = ConfigDict(extra="forbid")


class Citation(Strict):
    id: Annotated[int, Field(ge=1, le=MAX_CITATIONS)]
    url: Annotated[str, Field(max_length=500)]
    title: Annotated[str, Field(max_length=200)]

    @field_validator("url")
    @classmethod
    def _https_only(cls, value: str) -> str:
        cleaned = value.strip()
        if not _HTTPS_URL.match(cleaned):
            raise ValueError("a citation must be an https URL with no credentials")
        return cleaned

    @field_validator("title")
    @classmethod
    def _clean_title(cls, value: str) -> str:
        return _clean(value, 200)


class Claim(Strict):
    """One statement. `observed` came from the packet; `external` came from the model's own
    research and is what needs a citation."""

    text: Annotated[str, Field(min_length=1, max_length=MAX_CLAIM)]
    kind: Literal["observed", "external"]
    citations: Annotated[list[int], Field(default_factory=list, max_length=MAX_CITATIONS)]

    @field_validator("text")
    @classmethod
    def _clean_text(cls, value: str) -> str:
        cleaned = _clean(value, MAX_CLAIM)
        if not cleaned:
            raise ValueError("a claim needs text")
        return cleaned

    @property
    def verified(self) -> bool:
        """An observed claim is grounded in the packet by construction. An external one is
        only as good as its citation."""
        return self.kind == "observed" or bool(self.citations)


class Advice(Strict):
    action: Recommendation
    detail: Annotated[str, Field(default="", max_length=MAX_DETAIL)]

    @field_validator("detail")
    @classmethod
    def _clean_detail(cls, value: str) -> str:
        return _clean(value, MAX_DETAIL)


class InvestigationBrief(Strict):
    summary: Annotated[str, Field(min_length=1, max_length=MAX_SUMMARY)]
    claims: Annotated[list[Claim], Field(default_factory=list, max_length=MAX_CLAIMS)]
    recommendations: Annotated[
        list[Advice], Field(default_factory=list, max_length=MAX_RECOMMENDATIONS)
    ]
    citations: Annotated[list[Citation], Field(default_factory=list, max_length=MAX_CITATIONS)]
    limitations: Annotated[str, Field(default="", max_length=MAX_SUMMARY)]

    @field_validator("summary", "limitations")
    @classmethod
    def _clean_prose(cls, value: str) -> str:
        return _clean(value, MAX_SUMMARY)

    @model_validator(mode="after")
    def _citations_resolve(self) -> InvestigationBrief:
        """A claim may only cite a source the brief actually carries. A dangling reference is
        a fabricated citation wearing a number, which is worse than none."""
        known = {citation.id for citation in self.citations}
        for index, claim in enumerate(self.claims):
            unknown = sorted(set(claim.citations) - known)
            if unknown:
                raise ValueError(f"claims[{index}] cites {unknown}, which the brief does not list")
        return self

    @property
    def unverified(self) -> tuple[Claim, ...]:
        """External claims with nothing behind them. Rendered `UNVERIFIED`, never dropped."""
        return tuple(claim for claim in self.claims if not claim.verified)

    @property
    def has_unverified(self) -> bool:
        return bool(self.unverified)


def enforce_safety(brief: InvestigationBrief) -> None:
    """The safety filter, over every passage a reader will see (T-4.3).

    Deliberately *not* a pydantic validator. Pydantic converts any `ValueError` raised inside
    one into a `ValidationError`, which would make "the model recommended attacking something"
    indistinguishable from "a field was too long" — and those need different records and
    different conversations. Shape is validation; this is policy, and it is its own step.
    """
    check(brief.summary, where="summary")
    check(brief.limitations, where="limitations")
    for index, claim in enumerate(brief.claims):
        check(claim.text, where=f"claims[{index}]")
    for index, advice in enumerate(brief.recommendations):
        check(advice.detail, where=f"recommendations[{index}]")


def admit(document: object) -> InvestigationBrief:
    """Validate the shape, then apply the policy. Raises `ValidationError` for the first and
    `SafetyRejectedError` for the second, because the caller records them differently."""
    brief = InvestigationBrief.model_validate(document)
    enforce_safety(brief)
    return brief


__all__ = [
    "Advice",
    "Citation",
    "Claim",
    "InvestigationBrief",
    "Recommendation",
    "admit",
    "enforce_safety",
]
