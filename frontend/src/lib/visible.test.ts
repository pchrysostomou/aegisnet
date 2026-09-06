import { describe, expect, it } from "vitest";

import { visible } from "./visible";

/** The twenty code points the class covers, built from the ranges rather than typed out: a
 * literal U+202E in a test file is exactly as unreviewable as one in the source it tests. */
const POINTS = [
  ...range(0x200b, 0x200f),
  ...range(0x202a, 0x202e),
  ...range(0x2060, 0x2064),
  ...range(0x2066, 0x2069),
  0xfeff,
];

function range(from: number, to: number): number[] {
  return Array.from({ length: to - from + 1 }, (_, i) => from + i);
}

describe("invisible characters are written out, not stripped (T-4.4)", () => {
  it("writes out every character that can change what text says", () => {
    // One plain `it`, with the loop inside, rather than `it.each`: THREAT_MODEL.md §6 cites
    // this test by title and the checker matches `it("…"` literally in the source.
    expect(POINTS).toHaveLength(20);
    for (const point of POINTS) {
      const marker = `<U+${point.toString(16).toUpperCase().padStart(4, "0")}>`;
      expect(visible(`before${String.fromCharCode(point)}after`)).toBe(
        `before${marker}after`,
      );
    }
  });

  it("shows the reader that the reading order was reversed", () => {
    // The attack this exists for: everything after U+202E renders right-to-left, so a note
    // recording a hostile domain can be made to read as a reassuring one.
    expect(visible("transfer to \u202Eevil.test\u202C now")).toBe(
      "transfer to <U+202E>evil.test<U+202C> now",
    );
  });

  it("leaves text that is merely not English alone", () => {
    // Arabic and Hebrew letters carry their own direction. What is written out is the ability
    // to *override* the bidi algorithm, not the right to write in a right-to-left script.
    const arabic = "شبكة 10.10.0.42";
    expect(visible(arabic)).toBe(arabic);
    expect(visible("ordinary note about 10.10.0.42")).toBe("ordinary note about 10.10.0.42");
  });

  it("is idempotent, because the marker contains nothing it matches", () => {
    const once = visible("a\u200Bb\uFEFFc");
    expect(visible(once)).toBe(once);
    expect(once).toBe("a<U+200B>b<U+FEFF>c");
  });

  it("does not carry state between calls, though the pattern is global", () => {
    // A /g regex shares lastIndex across calls when it is used with .test or .exec. Only
    // .replace is ever called on it, which resets; this pins that it stays that way.
    expect(visible("\u200B")).toBe("<U+200B>");
    expect(visible("\u200B")).toBe("<U+200B>");
  });

  it("survives an empty string and a string with nothing to write out", () => {
    expect(visible("")).toBe("");
    expect(visible("plain")).toBe("plain");
  });
});
