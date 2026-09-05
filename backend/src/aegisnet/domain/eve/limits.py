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
    depth = 0
    deepest = 0
    in_string = False
    escaped = False
    for char in text:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char in "{[":
            depth += 1
            if depth > deepest:
                deepest = depth
                if stop_above is not None and deepest > stop_above:
                    return deepest
        elif char in "}]" and depth > 0:
            depth -= 1
    return deepest


def structure_violation(value: object, limits: ParseLimits = DEFAULT_LIMITS) -> RejectReason | None:
    """First limit a parsed value breaks, or ``None``. Iterative, so it cannot recurse."""
    stack: list[tuple[object, int]] = [(value, 1)]
    while stack:
        node, depth = stack.pop()
        if isinstance(node, dict):
            if depth > limits.max_json_depth:
                return RejectReason.too_deep
            if len(node) > limits.max_keys_per_object:
                return RejectReason.too_large
            stack.extend((child, depth + 1) for child in node.values())
        elif isinstance(node, list):
            if depth > limits.max_json_depth:
                return RejectReason.too_deep
            if len(node) > limits.max_items_per_array:
                return RejectReason.too_large
            stack.extend((child, depth + 1) for child in node)
    return None
