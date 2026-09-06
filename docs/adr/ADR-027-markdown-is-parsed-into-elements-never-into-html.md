# ADR-027 — Markdown is parsed into elements, never into HTML

- Status: accepted
- Date: 2026-09-06
- Milestone: 4 (Chunk 19); the renderer T-4.4 asks for, built before the content that needs it

## Context

Chunk 19 puts a case on screen: its alerts, its timeline, and the notes analysts write on it.
Notes are markdown, and from Milestone 5 an investigation brief will be markdown a language
model wrote *about attacker-controlled input* — a DNS query name, an HTTP host, a Suricata
signature that an attacker chose. `THREAT_MODEL.md` names both: T-1.3 (stored XSS from log
content) and T-4.4 (hostile markdown).

The usual answer is a markdown library plus a sanitiser. That is a bet that the sanitiser
understands every construct the parser can produce, on every browser, for ever. It is a bet
this project keeps losing in other people's codebases: mutation XSS, `<svg>` namespace
confusion, entity double-decoding, `<noscript>` parsing differences. And it needs
`dangerouslySetInnerHTML`, which Chunk 18 banned outright (ADR-026).

## Decision

### A small grammar, parsed straight into React elements

`components/safe-markdown.tsx` parses a fixed grammar into React elements. **No HTML string
exists at any point in the pipeline.** There is nothing for a sanitiser to miss, because there
is no sanitiser and no serialised markup — the output is a tree of elements the renderer chose,
with text in the text positions, and React escapes text.

What it supports: paragraphs, line breaks, `- ` bullets, `> ` quotes, fenced code blocks,
`inline code`, `**bold**`, `*italic*`. Inline code is matched first, so an indicator containing
an asterisk survives being written down.

Anything the grammar does not recognise renders as text. That is the whole safety property, and
it is the reason the grammar is small enough to read in one sitting: a rule that cannot be
reasoned about is a rule that cannot be trusted.

### No links and no images, on purpose

Both are the obvious omissions and both are deliberate.

A note is read by somebody deciding whether a host is compromised. A link is how that reader
gets taken somewhere else, and a rendered image is how a note phones home with the reader's
address the moment the case is opened — a tracking pixel in an incident record is an
intelligence leak about which cases are being worked and when.

An indicator belongs in a code span, where it can be read and copied and cannot be clicked.
When links are wanted later, they arrive as a decision with an allow-list of schemes and hosts,
not as a side effect of adopting a parser.

### Raw HTML is shown, not stripped

`<script>alert(1)</script>` in a note renders as those exact characters. Stripping it would be
worse in both directions: an analyst writing *about* a payload would find their evidence
silently edited, and a reader would not know what had been removed. The characters are text and
React escapes them; there is no path by which they become an element.

Entities are not decoded either. A note containing the literal `&lt;script&gt;` stays that
text, because decoding it would be the first half of the double-decoding bug this design
exists to make impossible.

### Bounded output

A single note produces at most 200 blocks and 400 inline tokens per line. A case with a
thousand notes is a page an analyst can still open.

### Proved, not asserted

Fifteen hostile inputs — script tags, `onerror` attributes, `javascript:` links, markdown image
and link syntax, `<svg/onload>`, `<base>`, `<form>`, comment-and-tag-splitting, pre-encoded
entities — are rendered in the test suite and checked two ways: every tag in the output must
be one of the eleven inert elements this renderer can emit, and nothing outside those tags may
contain `<` or `>`.

The assertions are on the *tags*, not on forbidden substrings, and that distinction is the
point. A note whose text reads `onerror=alert(1)` is exactly what an analyst investigating an
attack writes down, and it must render. What must never appear is an element that can act.

## Consequences

- Positive: hostile markdown cannot become markup here, by construction rather than by
  vigilance. The property does not depend on keeping a sanitiser current.
- Positive: the same renderer is ready for M5's AI briefs, which are the higher-risk case — a
  model summarising attacker-chosen strings is a laundering path for exactly this content.
- Positive: no markdown dependency, so no markdown CVE and nothing to keep pinned.
- Negative: analysts cannot write links, and will occasionally want to. A URL in a code span is
  copy-pasteable, which is the cost being paid, and the reason is written above rather than
  discovered by whoever asks.
- Negative: the grammar is a subset, so a note written elsewhere in full markdown renders its
  unsupported constructs as literal text. For headings and tables in a note, that is the right
  failure — visible, not silent.
- Neutral: the renderer is ~150 lines with no dependencies, and every line of it is a line this
  project owns and can be asked about in review.
