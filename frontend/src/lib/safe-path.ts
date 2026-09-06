/**
 * Where a sign-in is allowed to land.
 *
 * The `next` parameter arrives in a query string, so it is attacker-controlled, and an open
 * redirect is how a convincing phishing page gets a URL bar the victim trusts. The usual
 * defence — "it has to start with a slash" — is the version of this that keeps being wrong:
 * `//evil.test` is a protocol-relative URL, and a backslash is a slash to some parsers.
 *
 * So nothing is passed through. A destination is *rebuilt* from what the pattern captured,
 * out of characters this module chose. There is no path from the parameter's bytes to the
 * redirect's, which is what makes this safe by construction rather than by vigilance.
 */
export const QUEUE = "/incidents";

/** The other pages a sign-in may land on. Fixed strings, compared exactly. */
const SECTIONS = ["/incidents", "/assets", "/audit"] as const;

const CASE_PATH =
  /^\/incidents\/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$/;

/** The route `raw` asked for, or the queue. Never anything else, and never `raw` itself. */
export function safeNext(raw: string): string {
  const match = CASE_PATH.exec(raw);
  if (match) return `${QUEUE}/${match[1].toLowerCase()}`;
  const section = SECTIONS.find((known) => known === raw);
  return section ?? QUEUE;
}

/** Whether a path is worth remembering across a sign-in at all. `/` is not: it only
 * redirects to the queue, which is where an unremembered sign-in lands anyway. */
export function isWorthRemembering(pathname: string): boolean {
  return pathname !== "/" && safeNext(pathname) === pathname;
}
