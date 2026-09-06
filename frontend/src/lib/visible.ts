/**
 * Characters that change what text says without appearing in it (T-4.4).
 *
 * The dashboard renders three kinds of hostile string: a note an analyst typed about an attack,
 * a summary a language model wrote about attacker-controlled input, and values lifted straight
 * out of a sensor's logs. All three are cleaned of control characters before they are stored —
 * `domain/incidents.clean_note_body` and `domain/briefs/schema._clean` — and none of them is
 * cleaned of *formatting* characters, deliberately, because evidence is not edited.
 *
 * That leaves twenty code points which are invisible and yet load-bearing. `U+202E` reverses the
 * reading order of everything after it, so a note recording `evil.test` can be made to read as
 * something reassuring while the stored bytes stay what they were. `U+200B` splits a word that
 * a reader searches for. `U+2066`–`U+2069` isolate a run so it renders out of place.
 *
 * Nothing here can *run* — the renderer builds elements and never an HTML string (ADR-027), and
 * a browser suite asserts it. This is about a different failure: text that reads wrongly. So the
 * characters are **written out rather than stripped**, in exactly the notation and from exactly
 * the same list as `backend/src/aegisnet/domain/reports.py`, because the same note is read on
 * this screen and in the exported document and the two must not tell different stories. A case
 * about somebody who used one of these has to show that they did.
 *
 * `backend/tests/security/test_report_safety.py` compiles the class below and the report's own
 * and fails if the two lists ever diverge.
 */

/** U+200B–200F, U+202A–202E, U+2060–2064, U+2066–2069, U+FEFF — twenty code points.
 *
 * Written as escapes, not as the characters themselves: ESLint's `no-irregular-whitespace`
 * rejects a literal U+200B or U+FEFF in source (and is right to — a reviewer cannot see one). */
const INVISIBLE = /[\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF]/gu;

/** `text` with every invisible formatting character replaced by its own code point, written out.
 *
 * Idempotent: the replacement contains no character it matches. Every code point in the class is
 * in the basic plane, so `charCodeAt` and `codePointAt` agree and no surrogate pair is split. */
export function visible(text: string): string {
  return text.replace(
    INVISIBLE,
    (character) =>
      `<U+${character.charCodeAt(0).toString(16).toUpperCase().padStart(4, "0")}>`,
  );
}
