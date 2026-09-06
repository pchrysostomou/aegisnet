"""The one failure the brief path has (TB-3; ADR-030).

It lives in its own module so the client and the budget can both raise it without importing
each other.
"""

from __future__ import annotations


class BriefUnavailableError(RuntimeError):
    """The brief cannot be produced right now — disabled, unconfigured, out of budget, or the
    API would not answer. Never a reason to fail the incident it was about."""

    def __init__(self, reason: str, detail: str = "") -> None:
        self.reason = reason
        super().__init__(detail or reason)


__all__ = ["BriefUnavailableError"]
