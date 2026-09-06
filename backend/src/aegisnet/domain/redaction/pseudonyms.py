"""Stable, per-case names for the things a brief needs to refer to (T-3.2).

A brief has to be able to say "the host scanned forty ports on one neighbour, then uploaded to
an external address it had never contacted". None of that needs a real address, and sending
one would hand a third party the shape of somebody's network.

So every address and every name becomes a token — `asset-A`, `int-1`, `ext-1`, `domain-1` —
allocated in order of first appearance and stable for the life of one packet. The mapping is
kept locally so an analyst reading the brief can resolve a token; it is never sent.

Deterministic on purpose: the same case produces the same tokens, so a cached response stays
valid and two runs of the brief can be compared.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from ipaddress import ip_address
from typing import Final

from aegisnet.domain.detectors.addresses import is_internal

# `asset-A` for the entity a case is about, so a brief can talk about "the asset" without a
# number that looks like an index into something.
SUBJECT_LABEL: Final = "asset-A"

MAX_LABELS: Final = 200
"""Past this the packet is doing something other than describing one case."""

# An address or a hostname sitting inside a sentence. This project writes summaries like
# "D-003 fired on src_ip 10.10.0.42", so a sentence is a place a real address leaves from
# unless something goes looking for it (T-3.2).
# Every quantifier here is bounded and no group repeats over a class another group can also
# match. That is not style: this runs over text an attacker influenced, so a pattern that can
# backtrack catastrophically is a denial of service in the redactor itself.
_IN_TEXT: Final = re.compile(
    r"\b(?:\d{1,3}(?:\.\d{1,3}){3}"
    r"|[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{0,4}){2,7}"
    r"|(?:[a-zA-Z0-9-]{1,63}\.){1,10}[a-zA-Z]{2,24})\b"
)


def label_for(value: str) -> str:
    """The *kind* of label a value deserves, before a number is attached."""
    try:
        address = ip_address(value)
    except ValueError:
        return "domain"
    return "int" if is_internal(str(address)) else "ext"


@dataclass
class Pseudonymizer:
    """One case's mapping. Not thread-safe and not meant to be: a packet is built in one go."""

    subject: str | None = None
    _forward: dict[str, str] = field(default_factory=dict)
    _counts: dict[str, int] = field(default_factory=dict)

    def token(self, value: str) -> str:
        """The token for ``value``, allocating one on first sight."""
        if self.subject is not None and value == self.subject:
            return SUBJECT_LABEL
        existing = self._forward.get(value)
        if existing is not None:
            return existing
        if len(self._forward) >= MAX_LABELS:
            # Not an error: a very noisy case still deserves a brief, and the alternative is
            # to leak by falling back to the real value.
            return "other"
        kind = label_for(value)
        self._counts[kind] = self._counts.get(kind, 0) + 1
        token = f"{kind}-{self._counts[kind]}"
        self._forward[value] = token
        return token

    def tokens(self, values: object) -> list[str]:
        """A list-shaped evidence value, tokenised. Non-strings are stringified first, because
        an address may arrive as an `IPv4Address` and a port as an `int`."""
        if not isinstance(values, list | tuple):
            return []
        return [self.token(str(item)) for item in values]

    def scrub(self, text: str) -> str:
        """A sentence with every address and hostname in it replaced by its token.

        Summaries are written by this project, not by a sensor, but they quote the entity a
        case is about — so without this a packet's timeline would carry the very addresses the
        rest of the packet is careful to withhold.
        """
        return _IN_TEXT.sub(lambda match: self.token(match.group(0)), text)

    @property
    def mapping(self) -> dict[str, str]:
        """token → real value, for the analyst's side of the screen. Never sent."""
        reverse = {token: value for value, token in self._forward.items()}
        if self.subject is not None:
            reverse[SUBJECT_LABEL] = self.subject
        return reverse
