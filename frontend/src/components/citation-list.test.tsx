import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import type { BriefCitation } from "@/lib/api/schemas";

import { CitationList, isFollowable } from "./citation-list";

const cite = (url: string, id = 1, title = "A source"): BriefCitation => ({ id, url, title });
const render = (citations: BriefCitation[]) =>
  renderToStaticMarkup(<CitationList citations={citations} />);

const anchors = (html: string) => html.match(/<a\b[^>]*>/g) ?? [];

const ENTITIES: Record<string, string> = {
  "&lt;": "<",
  "&gt;": ">",
  "&quot;": '"',
  "&#x27;": "'",
  "&amp;": "&",
};

/** Tags removed, entities decoded: the string a person actually reads on the page. Asserting
 * on the raw markup would only be asserting that React escapes, which is not the claim. */
const visibleText = (html: string) =>
  html.replace(/<[^>]*>/g, "").replace(/&(?:lt|gt|quot|#x27|amp);/g, (match) => ENTITIES[match]);

describe("a citation URL came from a language model (T-4.4)", () => {
  // The rule is the scheme, not the host. This app keeps no list of acceptable domains and
  // inventing one would be a promise it could not keep, so `https://evil.test` is followable
  // and is tested below as such: what is refused here is a URL that could act.
  const hostile = [
    "javascript:alert(1)",
    "JavaScript:alert(1)",
    "  javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "vbscript:msgbox(1)",
    "file:///etc/passwd",
    "http://evil.test/plain",
    "//evil.test/protocol-relative",
    "/incidents/1",
    "evil.test",
    "",
    // https, and goes to evil.test. The part a reader recognises is the part that is inert.
    "https://attack.mitre.org@evil.test/advisory",
    "https://user:pass@evil.test",
  ];

  it.each(hostile)("renders %s as text and never as a link", (url) => {
    const html = render([cite(url)]);
    expect(anchors(html), `${url} became a link`).toHaveLength(0);
    expect(isFollowable(url)).toBe(false);
  });

  it.each(hostile)("still shows %s: a source nobody can follow is still a claim", (url) => {
    if (url === "") return;
    expect(visibleText(render([cite(url)]))).toContain(url.trim());
  });

  it("says why an unfollowable source is not a link", () => {
    expect(render([cite("http://evil.test")])).toContain("not linked");
  });
});

describe("an https source is followable, on terms this app sets", () => {
  it("carries rel and target on every anchor", () => {
    const html = render([
      cite("https://attack.mitre.org/techniques/T1071/", 1, "T1071"),
      cite("https://evil.test/still-https", 2, "Two"),
    ]);
    const links = anchors(html);
    expect(links).toHaveLength(2);
    for (const link of links) {
      expect(link).toContain('rel="noopener noreferrer nofollow"');
      expect(link).toContain('target="_blank"');
    }
  });

  it("links the title and prints the address underneath, so the destination is readable first", () => {
    const html = render([cite("https://example.test/a", 1, "Some advisory")]);
    expect(html).toContain(">Some advisory</a>");
    expect(html).toContain("https://example.test/a</code>");
  });

  it("falls back to the address when a source has no title", () => {
    expect(render([cite("https://example.test/a", 1, "")])).toContain(">https://example.test/a</a>");
  });

  it("accepts an https URL whose host looks unusual, because the scheme is the whole rule", () => {
    expect(isFollowable("https://xn--80ak6aa92e.example/path?a=1#f")).toBe(true);
  });

  it("emits nothing at all when a brief cited nothing", () => {
    expect(render([])).toBe("");
  });

  it("numbers each source the way the claims refer to it", () => {
    expect(render([cite("https://example.test/a", 7, "Seven")])).toContain("[7]");
  });
});
