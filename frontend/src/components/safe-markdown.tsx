/**
 * The only markdown this dashboard renders (T-4.4, T-1.3).
 *
 * A note is free text an analyst typed, and an investigation brief is free text a language
 * model wrote about attacker-controlled input. Both are hostile until
 * proven otherwise, so this renderer is built the other way round from a normal one: instead
 * of parsing markdown into HTML and then trying to clean the HTML, it parses a **small, fixed
 * grammar** straight into React elements. There is no HTML string at any point, so there is
 * nothing for a sanitiser to miss and no `dangerouslySetInnerHTML` to reach for — the linter
 * bans that anyway.
 *
 * What it supports, and nothing else:
 *
 *   paragraphs · line breaks · `- ` bullet lists · `> ` quotes · fenced ``` code blocks ·
 *   `inline code` · **bold** · *italic*
 *
 * What it deliberately does not support, and why:
 *
 * - **Links and images.** A note is read by somebody deciding whether a host is compromised;
 *   a link is how that reader gets taken somewhere else, and an image is how a note phones
 *   home with the reader's address. An IOC belongs in a code span, where it can be copied and
 *   cannot be clicked.
 * - **Raw HTML and entities.** Passed through as the literal characters typed, because a note
 *   containing `<script>` is a note about a script, and that is exactly what an analyst
 *   investigating an attack would write.
 * - **Headings and tables.** A note is a paragraph, not a document.
 *
 * Everything the grammar does not recognise renders as text. There is no escape hatch, and
 * unrecognised input can never become markup — the worst it can do is look like itself.
 */
import type { ReactNode } from "react";

import { visible } from "@/lib/visible";

export const MAX_BLOCKS = 200;
export const MAX_INLINE_TOKENS = 400;

type Inline = { kind: "text" | "code" | "strong" | "em"; value: string };

/** `code` first, so a backtick span protects whatever is inside it from every other rule: an
 * IOC containing an asterisk must survive being written down. */
const INLINE = /(`[^`\n]+`)|(\*\*[^*\n]+\*\*)|(\*[^*\n]+\*)/;

export function parseInline(text: string): Inline[] {
  const out: Inline[] = [];
  let rest = text;
  while (rest.length > 0 && out.length < MAX_INLINE_TOKENS) {
    const match = INLINE.exec(rest);
    if (!match || match.index === undefined) break;
    if (match.index > 0) out.push({ kind: "text", value: rest.slice(0, match.index) });
    const token = match[0];
    if (token.startsWith("`")) out.push({ kind: "code", value: token.slice(1, -1) });
    else if (token.startsWith("**")) out.push({ kind: "strong", value: token.slice(2, -2) });
    else out.push({ kind: "em", value: token.slice(1, -1) });
    rest = rest.slice(match.index + token.length);
  }
  if (rest.length > 0) out.push({ kind: "text", value: rest });
  return out;
}

function Inlines({ text }: { text: string }): ReactNode {
  return parseInline(text).map((token, index) => {
    const key = `${String(index)}:${token.kind}`;
    // Once, above the branches: a fifth kind added below cannot forget to do it, and the
    // substitution happens after the grammar has finished, so the marker it writes can never
    // be parsed as anything (T-4.4).
    const shown = visible(token.value);
    if (token.kind === "code") return <code key={key}>{shown}</code>;
    if (token.kind === "strong") return <strong key={key}>{shown}</strong>;
    if (token.kind === "em") return <em key={key}>{shown}</em>;
    return <span key={key}>{shown}</span>;
  });
}

type Block =
  | { kind: "paragraph"; lines: string[] }
  | { kind: "list"; items: string[] }
  | { kind: "quote"; lines: string[] }
  | { kind: "code"; lines: string[] };

/** Line-oriented on purpose: a grammar small enough to read in one sitting is a grammar whose
 * failure modes can be reasoned about.
 *
 * Every marker below matches `[ \t]` rather than `\s`, which is not a detail: JavaScript's `\s`
 * and `String.trim()` both include U+FEFF and friends, so `\uFEFF> quoted` used to be read as a
 * quote and the character was eaten by the marker — invisible in the output and absent from it,
 * while the exported report wrote it out. Python's `str.strip()` does not strip format
 * characters, so the backend never had the bug; narrowing the class here is what makes the two
 * renderers agree (T-4.4). */
export function parseBlocks(source: string): Block[] {
  const lines = source.replace(/\r\n?/g, "\n").split("\n");
  const blocks: Block[] = [];
  let fence: Block | null = null;

  for (const line of lines) {
    if (blocks.length >= MAX_BLOCKS) break;

    if (/^[ \t]*```/.test(line)) {
      if (fence) {
        blocks.push(fence);
        fence = null;
      } else {
        fence = { kind: "code", lines: [] };
      }
      continue;
    }
    if (fence) {
      fence.lines.push(line);
      continue;
    }

    const last = blocks[blocks.length - 1];
    if (/^[ \t]*$/.test(line)) continue;

    if (/^[ \t]*[-*][ \t]+/.test(line)) {
      const item = line.replace(/^[ \t]*[-*][ \t]+/, "");
      if (last?.kind === "list") last.items.push(item);
      else blocks.push({ kind: "list", items: [item] });
      continue;
    }
    if (/^[ \t]*>[ \t]?/.test(line)) {
      const quoted = line.replace(/^[ \t]*>[ \t]?/, "");
      if (last?.kind === "quote") last.lines.push(quoted);
      else blocks.push({ kind: "quote", lines: [quoted] });
      continue;
    }
    if (last?.kind === "paragraph") last.lines.push(line);
    else blocks.push({ kind: "paragraph", lines: [line] });
  }
  // An unterminated fence is still a code block: dropping it would hide what somebody wrote.
  if (fence) blocks.push(fence);
  return blocks;
}

function Lines({ lines }: { lines: string[] }): ReactNode {
  return lines.map((line, index) => (
    <span key={`${String(index)}:${line.slice(0, 8)}`}>
      {index > 0 ? <br /> : null}
      <Inlines text={line} />
    </span>
  ));
}

export function SafeMarkdown({ source, className }: { source: string; className?: string }) {
  const blocks = parseBlocks(source);
  return (
    <div className={className ?? "prose"}>
      {blocks.map((block, index) => {
        const key = String(index);
        if (block.kind === "code") {
          // No inline parsing inside a fence: what is in a code block is what was typed.
          return (
            <pre key={key}>
              <code>{visible(block.lines.join("\n"))}</code>
            </pre>
          );
        }
        if (block.kind === "list") {
          return (
            <ul key={key}>
              {block.items.map((item, i) => (
                <li key={`${key}:${String(i)}`}>
                  <Inlines text={item} />
                </li>
              ))}
            </ul>
          );
        }
        if (block.kind === "quote") {
          return (
            <blockquote key={key}>
              <Lines lines={block.lines} />
            </blockquote>
          );
        }
        return (
          <p key={key}>
            <Lines lines={block.lines} />
          </p>
        );
      })}
    </div>
  );
}
