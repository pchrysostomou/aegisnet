import { describe, expect, it } from "vitest";

import { ACCESS_COOKIE, SESSION_COOKIE, canWrite, cookieOptions, sessionCookies } from "./session";

describe("session cookies", () => {
  it("expires the access cookie with its token, a second early", () => {
    const [access] = sessionCookies("tok", 900, null);
    expect(access.name).toBe(ACCESS_COOKIE);
    expect(access.maxAge).toBe(899);
  });

  it("never writes a zero or negative lifetime", () => {
    expect(sessionCookies("tok", 1, null)[0].maxAge).toBe(1);
    expect(sessionCookies("tok", 0, null)[0].maxAge).toBe(1);
  });

  it("writes the session cookie only when the API rotated one", () => {
    expect(sessionCookies("tok", 900, null)).toHaveLength(1);
    const both = sessionCookies("tok", 900, "refresh-value");
    expect(both.map((cookie) => cookie.name)).toEqual([ACCESS_COOKIE, SESSION_COOKIE]);
    expect(both[1].maxAge).toBeGreaterThan(900);
  });

  it("keeps every cookie out of reach of script (T-2.4)", () => {
    const options = cookieOptions(900);
    expect(options.httpOnly).toBe(true);
    expect(options.sameSite).toBe("lax");
    expect(options.path).toBe("/");
  });
});

describe("canWrite", () => {
  it("lets an analyst and an admin act, and nobody else", () => {
    const base = { id: "1", email: "a@b.test", display_name: "A" };
    expect(canWrite({ ...base, role: "analyst" })).toBe(true);
    expect(canWrite({ ...base, role: "admin" })).toBe(true);
    expect(canWrite({ ...base, role: "viewer" })).toBe(false);
    expect(canWrite(null)).toBe(false);
  });
});
