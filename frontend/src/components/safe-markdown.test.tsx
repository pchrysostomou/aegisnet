import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { SafeMarkdown, parseBlocks, parseInline } from "./safe-markdown";

const render = (source: string) => renderToStaticMarkup(<SafeMarkdown source={source} />);

describe("hostile input renders as text, never as markup (T-4.4, T-1.3)", () => {
  const hostile = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<iframe src='javascript:alert(1)'></iframe>",
    "<svg/onload=alert(1)>",
    "[click me](javascript:alert(1))",
    "[click me](https://evil.test)",
    "![pixel](https://evil.test/track.gif)",
    "<a href='https://evil.test'>x</a>",
    "&lt;script&gt;alert(1)&lt;/script&gt;",
    "&#60;script&#62;",
    "<!-- --><script>alert(1)</script>",
    "</p><script>alert(1)</script><p>",
    "<style>body{display:none}</style>",
    "<base href='https://evil.test'>",
    "<form action='https://evil.test'><input name=p>",
  ];

  /** Every tag this renderer is allowed to emit, with the only attribute it ever sets.
   * Asserting on the tags rather than on forbidden substrings is the honest test: a note whose
   * *text* reads `onerror=alert(1)` is exactly what an analyst investigating an attack writes,
   * and it must render — as text. What must never appear is an element that can act. */
  const ALLOWED_TAG = /^<\/?(?:div(?: class="[a-z- ]+")?|p|span|br|ul|li|blockquote|pre|code|strong|em)\/?>$/;

  const tagsIn = (html: string) => html.match(/<[^<>]*>/g) ?? [];

  it.each(hostile)("emits only inert elements for %s", (source) => {
    const html = render(source);
    for (const tag of tagsIn(html)) {
      expect(tag, `${source} produced ${tag}`).toMatch(ALLOWED_TAG);
    }
  });

  it.each(hostile)("keeps the dangerous characters escaped for %s", (source) => {
    const html = render(source);
    // Nothing that could open a tag survives unescaped outside the elements above.
    const withoutTags = html.replace(/<[^<>]*>/g, "");
    expect(withoutTags).not.toContain("<");
    expect(withoutTags).not.toContain(">");
  });

  it("never produces a link, however the markdown asks for one", () => {
    for (const source of ["[a](https://evil.test)", "<https://evil.test>", "https://evil.test"]) {
      expect(render(source)).not.toMatch(/<a[\s>]/i);
    }
  });

  it("shows the characters that were typed, so a note about a script reads as one", () => {
    const html = render("the payload was <script>alert(1)</script>");
    expect(html).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
  });

  it("does not decode entities into markup", () => {
    // A note that literally contains `&lt;script&gt;` must stay that text, not become a tag.
    expect(render("&lt;script&gt;")).toContain("&amp;lt;script&amp;gt;");
  });
});

describe("the grammar it does support", () => {
  it("renders paragraphs, bold, italic and inline code", () => {
    const html = render("plain **bold** and *italic* and `code`");
    expect(html).toContain("<strong>bold</strong>");
    expect(html).toContain("<em>italic</em>");
    expect(html).toContain("<code>code</code>");
    expect(html).toContain("<p>");
  });

  it("keeps a code span's contents literal, asterisks and all", () => {
    expect(parseInline("`a*b*c`")).toEqual([{ kind: "code", value: "a*b*c" }]);
  });

  it("renders bullets and quotes", () => {
    const html = render("- one\n- two\n\n> quoted");
    expect(html).toContain("<ul>");
    expect(html).toContain("<li>");
    expect(html).toContain("<blockquote>");
  });

  it("renders a fenced block without touching what is inside it", () => {
    const html = render("```\n<script>alert(1)</script>\n**not bold**\n```");
    expect(html).toContain("<pre>");
    expect(html).toContain("&lt;script&gt;");
    expect(html).toContain("**not bold**");
    expect(html).not.toContain("<strong>");
  });

  it("keeps an unterminated fence rather than dropping what somebody wrote", () => {
    const blocks = parseBlocks("```\nstill here");
    expect(blocks).toEqual([{ kind: "code", lines: ["still here"] }]);
  });

  it("joins wrapped lines into one paragraph and breaks them visibly", () => {
    const html = render("first line\nsecond line");
    expect(html.match(/<p>/g)).toHaveLength(1);
    expect(html).toContain("<br/>");
  });

  it("bounds what a single note can produce", () => {
    const blocks = parseBlocks(Array.from({ length: 500 }, (_, i) => `- item ${String(i)}`).join("\n"));
    expect(blocks).toHaveLength(1);
    const many = parseBlocks(Array.from({ length: 500 }, (_, i) => `para ${String(i)}\n`).join("\n"));
    expect(many.length).toBeLessThanOrEqual(200);
  });

  it("survives an empty note", () => {
    expect(parseBlocks("")).toEqual([]);
    expect(render("")).toContain("<div");
  });
});

describe("invisible characters are written out wherever text is rendered (T-4.4)", () => {
  /** Built from the ranges, never typed: a literal U+202E in a source file cannot be reviewed. */
  const INVISIBLE = [
    ...Array.from({ length: 5 }, (_, i) => 0x200b + i),
    ...Array.from({ length: 5 }, (_, i) => 0x202a + i),
    ...Array.from({ length: 5 }, (_, i) => 0x2060 + i),
    ...Array.from({ length: 4 }, (_, i) => 0x2066 + i),
    0xfeff,
  ].map((point) => String.fromCharCode(point));

  /** Every construct the grammar has, each carrying every invisible character. */
  const poisoned = [
    `a paragraph ${INVISIBLE.join("")} of text`,
    `- a list item ${INVISIBLE.join("")}`,
    `> a quote ${INVISIBLE.join("")}`,
    "```",
    `a fenced block ${INVISIBLE.join("")}`,
    "```",
    `an \`inline code ${INVISIBLE.join("")}\` span`,
    `**bold ${INVISIBLE.join("")}** and *italic ${INVISIBLE.join("")}*`,
  ].join("\n");

  it("leaves not one of them in the rendered output, in any construct", () => {
    // The construction guard, and the reason it asserts absence rather than presence: a new
    // text node added to this renderer that forgets `visible()` fails here, which is how this
    // regresses in practice. Two character lists drifting apart is the other way, and the
    // backend's parity test covers that one.
    const html = render(poisoned);
    for (const character of INVISIBLE) {
      expect(html, `U+${character.charCodeAt(0).toString(16)} survived rendering`).not.toContain(
        character,
      );
    }
  });

  it("says which character it was, so a case can still record that somebody used one", () => {
    const html = render("payment to \u202Eevil.test\u202C today");
    expect(html).toContain("&lt;U+202E&gt;");
    expect(html).toContain("&lt;U+202C&gt;");
    expect(html).toContain("evil.test");
  });

  it("does not let a zero-width character disguise itself as the space before a marker", () => {
    // JavaScript's \s and String.trim() include U+FEFF. While the block grammar used them, a
    // line beginning U+FEFF was read as a quote and the character was swallowed by the marker —
    // gone from the screen and absent from it, while the exported report wrote it out.
    expect(parseBlocks("\uFEFF> quoted")).toEqual([
      { kind: "paragraph", lines: ["\uFEFF> quoted"] },
    ]);
    expect(render("\uFEFF> quoted")).toContain("&lt;U+FEFF&gt;");

    // A line made only of one is a line with something on it, not a blank.
    expect(parseBlocks("\u200B")).toEqual([{ kind: "paragraph", lines: ["\u200B"] }]);

    // An ordinary space or tab before a marker still starts the block it always did.
    expect(parseBlocks("  > quoted")[0]?.kind).toBe("quote");
    expect(parseBlocks("\t- item")[0]?.kind).toBe("list");
  });
});

describe("a blank line ends the block above it", () => {
  it("makes two paragraphs, not one with a line break", () => {
    const html = render("first\n\nsecond");
    expect(html).toContain("<p>");
    expect(html.match(/<p>/g)).toHaveLength(2);
    expect(html).not.toContain("<br/>");
  });

  it("still joins lines that are only separated by a newline", () => {
    const html = render("first\nsecond");
    expect(html.match(/<p>/g)).toHaveLength(1);
    expect(html).toContain("<br/>");
  });

  it("leaves a loose list as one list, which is what markdown says", () => {
    const html = render("- a\n\n- b");
    expect(html.match(/<ul>/g)).toHaveLength(1);
    expect(html.match(/<li>/g)).toHaveLength(2);
  });

  it("separates two quotes", () => {
    const html = render("> a\n\n> b");
    expect(html.match(/<blockquote>/g)).toHaveLength(2);
  });

  it("keeps blank lines inside a fence, where they are content", () => {
    const html = render("```\na\n\nb\n```");
    expect(html.match(/<pre>/g)).toHaveLength(1);
    expect(html).toContain("a\n\nb");
  });
});
