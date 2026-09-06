/**
 * Keeps a session alive, and keeps everything else behind one.
 *
 * A server component cannot write a cookie, so a token that expires mid-render has nowhere to
 * put its replacement. Middleware can: it runs before the render, rotates the pair when the
 * short-lived access cookie has gone and the session cookie has not, and hands the refreshed
 * request on. The alternative — bouncing an analyst to the login form every fifteen minutes —
 * would teach them to keep a password manager open on the incident queue.
 *
 * This is a convenience, not the boundary. The API refuses every request on its own
 * permissions; a forged or edited cookie buys nothing, and no page trusts what this file says.
 *
 * Two things here are written the long way on purpose, because both handle attacker-controlled
 * input. The redirect target is assembled from a cloned URL whose path and query this file
 * sets, so no part of the request's own path reaches the `Location` header unexamined. And the
 * onward cookie header is rebuilt from parsed name/value pairs rather than by echoing the
 * header the browser sent.
 */
import { NextResponse, type NextRequest } from "next/server";

import { isWorthRemembering, safeNext } from "@/lib/safe-path";
import { ACCESS_COOKIE, SESSION_COOKIE, cookieOptions, refresh } from "@/lib/session";

/** Reachable without a session. Everything else redirects to the login form. */
const PUBLIC_PATHS = ["/login", "/api/health"];

/** `/login` on this same origin, carrying where the analyst was going — rebuilt by `safeNext`,
 * never copied. `search` is cleared first so nothing the caller appended survives. */
function loginUrl(request: NextRequest, pathname: string, expired: boolean): URL {
  const login = request.nextUrl.clone();
  login.pathname = "/login";
  login.search = "";
  if (expired) login.searchParams.set("expired", "1");
  if (isWorthRemembering(pathname)) login.searchParams.set("next", safeNext(pathname));
  return login;
}

/** The cookie header for the onward request: every cookie the browser sent, with this app's
 * two replaced by the rotated pair. Built from parsed pairs, so the browser's raw header is
 * never spliced into an outgoing one. */
function rotatedCookieHeader(
  request: NextRequest,
  rotated: readonly { name: string; value: string }[],
): string {
  const replaced = new Map(rotated.map((cookie) => [cookie.name, cookie.value]));
  const pairs = request.cookies
    .getAll()
    .filter((cookie) => !replaced.has(cookie.name))
    .map((cookie) => [cookie.name, cookie.value] as const);
  return [...pairs, ...replaced].map(([name, value]) => `${name}=${value}`).join("; ");
}

export async function middleware(request: NextRequest) {
  const pathname = request.nextUrl.pathname;
  if (PUBLIC_PATHS.some((path) => pathname === path || pathname.startsWith(`${path}/`))) {
    return NextResponse.next();
  }

  if (request.cookies.has(ACCESS_COOKIE)) return NextResponse.next();

  const session = request.cookies.get(SESSION_COOKIE)?.value;
  if (!session) return NextResponse.redirect(loginUrl(request, pathname, false));

  try {
    const rotated = await refresh(session);
    // The rotated cookies go on both the onward request and the response: the former so this
    // render sees them, the latter so the browser keeps them.
    const headers = new Headers(request.headers);
    headers.set("cookie", rotatedCookieHeader(request, rotated));
    const response = NextResponse.next({ request: { headers } });
    for (const cookie of rotated) {
      response.cookies.set(cookie.name, cookie.value, cookieOptions(cookie.maxAge));
    }
    return response;
  } catch {
    // A refresh token the API will not honour is a session that is over — including the case
    // where it was replayed and the API revoked the whole chain on purpose.
    const response = NextResponse.redirect(loginUrl(request, pathname, true));
    response.cookies.delete(ACCESS_COOKIE);
    response.cookies.delete(SESSION_COOKIE);
    return response;
  }
}

export const config = {
  // Everything but Next's own assets and the favicon.
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
