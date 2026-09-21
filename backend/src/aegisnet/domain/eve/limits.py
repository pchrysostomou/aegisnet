"""Pre-parse and post-parse structural limits (THREAT_MODEL T-1.4, T-1.5).

A hostile line can be enormous, nested thousands of levels deep, or carry an object with
tens of thousands of keys. The checks here run in this order in the normaliser:

1. byte length of the line, before anything else touches it;
2. bracket depth, by scanning the raw text without parsing it, so pathological nesting is
   refused before ``json.loads`` can recurse into it;
3. after parsing, an iterative walk that enforces depth again (against the parsed shape)
   plus per-object key counts and per-array item counts.

The defaults match ``docs/api-milestone-1.md``; the ingest service makes them configurable.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Final

from aegisnet.domain.enums import RejectReason


@dataclass(frozen=True, slots=True)
class ParseLimits:
    max_line_bytes: int = 64 * 1024
    max_json_depth: int = 12
    max_keys_per_object: int = 200
    max_items_per_array: int = 1000
    max_string_chars: int = 4096


DEFAULT_LIMITS: Final = ParseLimits()


def encoded_size(line: str) -> int:
    return len(line.encode("utf-8", errors="surrogatepass"))


def bracket_depth(text: str, *, stop_above: int | None = None) -> int:
    """Maximum nesting depth of ``{``/``[`` outside string literals.

    A linear scan that tracks string state and backslash escapes, so braces inside string
    values do not count. When ``stop_above`` is given the scan returns as soon as that
    depth is exceeded, which bounds the work on a hostile line to the first few bytes.
    Malformed text (unbalanced brackets) simply yields a depth; the JSON parser rejects it.
    """
    # No ceiling is a ceiling nothing reaches, so the loop has one comparison rather than two.
    ceiling = stop_above if stop_above is not None else len(text)
    depth = 0
    deepest = 0
    in_string = False
    escaped = False  # only ever true inside a string: it is set there and cleared one char later
    for char in text:
        if escaped:
            escaped = False
        elif in_string:
            if char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
        elif char == '"':
            in_string = True
        elif char in "{[":
            depth += 1
            deepest = max(deepest, depth)
            if deepest > ceiling:
                return deepest
        elif char in "}]":
            depth = max(0, depth - 1)
    return deepest


def structure_violation(value: object, limits: ParseLimits = DEFAULT_LIMITS) -> RejectReason | None:
    """First limit a parsed value breaks, or ``None``. Iterative, so it cannot recurse."""
    stack: list[tuple[object, int]] = [(value, 1)]
    while stack:
        node, depth = stack.pop()
        children: Iterable[object]
        if isinstance(node, dict):
            children, size, cap = node.values(), len(node), limits.max_keys_per_object
        elif isinstance(node, list):
            children, size, cap = node, len(node), limits.max_items_per_array
        else:
            continue
        if depth > limits.max_json_depth:
            return RejectReason.too_deep
        if size > cap:
            return RejectReason.too_large
        stack.extend((child, depth + 1) for child in children)
    return None
