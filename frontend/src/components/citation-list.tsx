/**
 * The sources a brief pointed at, and the only anchor to somewhere else this app has ever
 * rendered (T-4.4; ADR-032).
 *
 * That is worth saying out loud rather than slipping in. `SafeMarkdown` refuses links on
 * purpose — a note is read by somebody deciding whether a host is compromised, and a link is
 * how that reader gets taken somewhere else. A citation is the one case where the link *is*
 * the point: a claim about the outside world is worth nothing if the analyst cannot go and
 * check it.
 *
 * So the anchor is built here, from the structured `citations[]` array the API already parsed,
 * and never from a markdown string. `SafeMarkdown`'s property — that no HTML string exists at
 * any point and no link can be produced from prose — is untouched; this component simply is
 * not a markdown renderer.
 *
 * A URL that reached this array came from a language model. The API checks it and the database
 * checks it again, and this checks it a third time, because the check that matters is the one
 * next to the `href`:
 *
 * - **https only.** Anything else — `http:`, `javascript:`, `data:`, a protocol-relative
 *   `//host` — is shown as text and is not clickable, and so is one carrying credentials
 *   (`https://attack.mitre.org@evil.test` is https and goes to `evil.test`). None of them are
 *   hidden: a citation nobody can follow is still evidence of what the model said.
 * - **`rel="noopener noreferrer nofollow"`**, so the destination gets no handle on this window,
 *   no referrer naming the case being investigated, and no ranking signal.
 * - **`target="_blank"`**, so following a source never loses the case the analyst was reading.
 */
import type { BriefCitation } from "@/lib/api/schemas";
import { visible } from "@/lib/visible";

/** Parsed rather than pattern-matched: `new URL` is what the browser will do with the value,
 * and a prefix test can be fooled by things a parser cannot (`https:/\evil`, whitespace, a
 * scheme in a different case).
 *
 * Credentials are refused as well as the scheme. `https://attack.mitre.org@evil.test` is a
 * perfectly good https URL that goes to `evil.test`, and the part a reader recognises is the
 * part that means nothing. The API refuses one too — this is the copy of the check that sits
 * next to the `href`, which is the one that has to be right. */
export function isFollowable(url: string): boolean {
  try {
    const parsed = new URL(url);
    return parsed.protocol === "https:" && !parsed.username && !parsed.password;
  } catch {
    return false;
  }
}

export function CitationList({ citations }: { citations: readonly BriefCitation[] }) {
  if (citations.length === 0) return null;
  return (
    <ol className="citations">
      {citations.map((citation) => (
        <li key={citation.id}>
          <span className="citation-id mono">[{citation.id}]</span>{" "}
          {isFollowable(citation.url) ? (
            <a href={citation.url} target="_blank" rel="noopener noreferrer nofollow">
              {visible(citation.title || citation.url)}
            </a>
          ) : (
            <>
              <span>{visible(citation.title || "Untitled source")}</span>{" "}
              <span className="notice-inline">
                not linked: a source must be <code className="mono">https</code>
              </span>
            </>
          )}
          <br />
          <code className="mono citation-url">{visible(citation.url)}</code>
        </li>
      ))}
    </ol>
  );
}
