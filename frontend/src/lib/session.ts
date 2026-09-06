/**
 * Who is logged in, and how this app keeps that true (T-2.4).
 *
 * The API issues a short-lived bearer token and a rotating refresh cookie. Neither ever
 * reaches the browser. Next stores both in its own `HttpOnly`, `SameSite=Lax` cookies, and the
 * browser holds nothing but an opaque session it cannot read from script. A stolen page
 * therefore yields no credential, and an XSS bug — the thing this milestone is most exposed to
 * — cannot exfiltrate one.
 *
 * The access cookie expires exactly when its token does, so "no access cookie" and "the token
 * is spent" are the same condition and there is nothing to keep in step. When it goes and the
 * refresh cookie remains, `middleware.ts` rotates the pair before the page renders.
 */
import { cookies } from "next/headers";

import { apiRequest, refreshCookieFrom } from "./api/client";
import { currentUser, tokenResponse, type CurrentUser } from "./api/schemas";

export const ACCESS_COOKIE = "aegisnet_access";
export const SESSION_COOKIE = "aegisnet_session";

/** Long enough to outlive a shift, short enough that a forgotten tab does not stay live for
 * ever. The API's own refresh token is the real authority; this only bounds the cookie. */
const SESSION_MAX_AGE_SECONDS = 12 * 60 * 60;

/** A second of slack, so a token is never presented in the instant it expires. */
const EXPIRY_SKEW_SECONDS = 1;

export interface SessionCookie {
  name: string;
  value: string;
  maxAge: number;
}

export function sessionCookies(accessToken: string, expiresIn: number, refresh: string | null) {
  const written: SessionCookie[] = [
    {
      name: ACCESS_COOKIE,
      value: accessToken,
      maxAge: Math.max(1, expiresIn - EXPIRY_SKEW_SECONDS),
    },
  ];
  if (refresh) {
    written.push({ name: SESSION_COOKIE, value: refresh, maxAge: SESSION_MAX_AGE_SECONDS });
  }
  return written;
}

export function cookieOptions(maxAge: number) {
  return {
    httpOnly: true,
    sameSite: "lax" as const,
    // The dashboard is served over http on localhost in development; a Secure cookie would
    // simply not be stored there. Anything that is not development gets the flag.
    secure: process.env.NODE_ENV === "production",
    path: "/",
    maxAge,
  };
}

export async function readAccessToken(): Promise<string | null> {
  return (await cookies()).get(ACCESS_COOKIE)?.value ?? null;
}

export async function readSessionToken(): Promise<string | null> {
  return (await cookies()).get(SESSION_COOKIE)?.value ?? null;
}

/** Exchange a password for a session. Returns the cookies the caller must write. */
export async function login(email: string, password: string): Promise<SessionCookie[]> {
  const { data, setCookie } = await apiRequest("/api/v1/auth/login", {
    schema: tokenResponse,
    method: "POST",
    body: { email, password },
  });
  return sessionCookies(data.access_token, data.expires_in, refreshCookieFrom(setCookie));
}

/** Rotate the pair. The API revokes the whole chain if a refresh token is ever replayed, so
 * the new cookie must replace the old one even when the caller then fails. */
export async function refresh(sessionToken: string): Promise<SessionCookie[]> {
  const { data, setCookie } = await apiRequest("/api/v1/auth/refresh", {
    schema: tokenResponse,
    method: "POST",
    refreshCookie: sessionToken,
  });
  return sessionCookies(data.access_token, data.expires_in, refreshCookieFrom(setCookie));
}

/** Ask the API to revoke the chain. Best effort: the cookies are cleared either way, because a
 * logout that leaves a live cookie behind because the network hiccuped is not a logout. */
export async function revoke(accessToken: string | null, sessionToken: string | null) {
  if (!accessToken) return;
  try {
    await apiRequest("/api/v1/auth/logout", {
      schema: tokenResponse.optional(),
      method: "POST",
      accessToken,
      refreshCookie: sessionToken,
    });
  } catch {
    // Nothing to tell the analyst: their session is over on this side regardless.
  }
}

export async function currentUserOrNull(): Promise<CurrentUser | null> {
  const accessToken = await readAccessToken();
  if (!accessToken) return null;
  try {
    const { data } = await apiRequest("/api/v1/auth/me", { schema: currentUser, accessToken });
    return data;
  } catch {
    return null;
  }
}

/** Analyst and admin may change a case; a viewer may not (SECURITY.md, ADR-024). The server
 * enforces it — this only decides whether to draw a control the API would refuse. */
export function canWrite(user: CurrentUser | null): boolean {
  return user?.role === "analyst" || user?.role === "admin";
}
