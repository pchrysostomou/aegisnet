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
 */
import { NextResponse, type NextRequest } from "next/server";

import { refresh } from "@/lib/session";
import { ACCESS_COOKIE, SESSION_COOKIE, cookieOptions } from "@/lib/session";

/** Reachable without a session. Everything else redirects to the login form. */
const PUBLIC_PATHS = ["/login", "/api/health"];

export async function middleware(request: NextRequest) {
  const { pathname, search } = request.nextUrl;
  if (PUBLIC_PATHS.some((path) => pathname === path || pathname.startsWith(`${path}/`))) {
    return NextResponse.next();
  }

  const access = request.cookies.get(ACCESS_COOKIE)?.value;
  const session = request.cookies.get(SESSION_COOKIE)?.value;
  if (access) return NextResponse.next();

  if (!session) {
    const login = new URL("/login", request.url);
    if (pathname !== "/") login.searchParams.set("next", `${pathname}${search}`);
    return NextResponse.redirect(login);
  }

  try {
    const written = await refresh(session);
    // The rotated cookies go on both the onward request and the response: the former so this
    // render sees them, the latter so the browser keeps them.
    const headers = new Headers(request.headers);
    const jar = written.map((cookie) => `${cookie.name}=${cookie.value}`).join("; ");
    headers.set("cookie", [request.headers.get("cookie"), jar].filter(Boolean).join("; "));
    const response = NextResponse.next({ request: { headers } });
    for (const cookie of written) {
      response.cookies.set(cookie.name, cookie.value, cookieOptions(cookie.maxAge));
    }
    return response;
  } catch {
    // A refresh token the API will not honour is a session that is over — including the case
    // where it was replayed and the API revoked the whole chain on purpose.
    const login = new URL("/login", request.url);
    login.searchParams.set("expired", "1");
    if (pathname !== "/") login.searchParams.set("next", `${pathname}${search}`);
    const response = NextResponse.redirect(login);
    response.cookies.delete(ACCESS_COOKIE);
    response.cookies.delete(SESSION_COOKIE);
    return response;
  }
}

export const config = {
  // Everything but Next's own assets and the favicon.
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
