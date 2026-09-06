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

  const tagsIn = (html: string) => html.match(/<[^>]*>/g) ?? [];

  it.each(hostile)("emits only inert elements for %s", (source) => {
    const html = render(source);
    for (const tag of tagsIn(html)) {
      expect(tag, `${source} produced ${tag}`).toMatch(ALLOWED_TAG);
    }
  });

  it.each(hostile)("keeps the dangerous characters escaped for %s", (source) => {
    const html = render(source);
    // Nothing that could open a tag survives unescaped outside the elements above.
    const withoutTags = html.replace(/<[^>]*>/g, "");
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
