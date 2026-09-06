import { afterEach, describe, expect, it, vi } from "vitest";
import { z } from "zod";

import { ApiContractError, ApiError, apiBaseUrl, apiRequest, refreshCookieFrom } from "./client";

const shape = z.object({ ok: z.boolean() });

function respondWith(body: unknown, init: ResponseInit = {}) {
  const response = new Response(JSON.stringify(body), {
    status: init.status ?? 200,
    headers: { "content-type": "application/json", ...(init.headers ?? {}) },
  });
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue(response));
  return response;
}

afterEach(() => {
  vi.unstubAllGlobals();
  delete process.env.AEGISNET_API_URL;
});

describe("apiBaseUrl", () => {
  it("falls back to the local API and rebuilds the origin it was given", () => {
    expect(apiBaseUrl()).toBe("http://localhost:8000");
    process.env.AEGISNET_API_URL = "http://api:8000/";
    expect(apiBaseUrl()).toBe("http://api:8000");
    process.env.AEGISNET_API_URL = "https://aegis.example.test";
    expect(apiBaseUrl()).toBe("https://aegis.example.test");
  });

  it.each([
    ["not-a-url", "not a URL"],
    ["file:///etc/passwd", "a scheme that is not http"],
    ["http://user:pass@api:8000", "embedded credentials"],
    ["http://api:8000/v1", "a path"],
    ["http://api:8000/?x=1", "a query"],
  ])("refuses %s (%s)", (value) => {
    process.env.AEGISNET_API_URL = value;
    expect(() => apiBaseUrl()).toThrow();
  });
});

describe("apiRequest", () => {
  it("sends the bearer token and returns the parsed body", async () => {
    respondWith({ ok: true });
    const { data } = await apiRequest("/api/v1/thing", { schema: shape, accessToken: "tok" });
    expect(data).toEqual({ ok: true });
    const [, init] = vi.mocked(fetch).mock.calls[0];
    expect(new Headers(init?.headers).get("Authorization")).toBe("Bearer tok");
  });

  it("omits an absent filter rather than sending it empty", async () => {
    respondWith({ ok: true });
    await apiRequest("/api/v1/incidents", {
      schema: shape,
      query: { status: undefined, open: "true", severity_min: null, cursor: "" },
    });
    const [target] = vi.mocked(fetch).mock.calls[0];
    expect(target).toBe("http://localhost:8000/api/v1/incidents?open=true");
  });

  it("never sends a cookie header unless a refresh token was passed", async () => {
    respondWith({ ok: true });
    await apiRequest("/api/v1/thing", { schema: shape, accessToken: "tok" });
    const [, init] = vi.mocked(fetch).mock.calls[0];
    expect(new Headers(init?.headers).has("Cookie")).toBe(false);
  });

  it("turns the documented envelope into a typed error", async () => {
    respondWith(
      {
        error: {
          code: "forbidden",
          message: "This action is not permitted.",
          correlation_id: "c-1",
          details: [],
        },
      },
      { status: 403 },
    );
    const failure = await apiRequest("/api/v1/incidents", { schema: shape }).catch(
      (error: unknown) => error,
    );
    expect(failure).toBeInstanceOf(ApiError);
    const error = failure as ApiError;
    expect(error.isForbidden).toBe(true);
    expect(error.code).toBe("forbidden");
    expect(error.correlationId).toBe("c-1");
  });

  it("still reports the status when the body is not the envelope", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(new Response("<html>502</html>", { status: 502 })),
    );
    const error = (await apiRequest("/x", { schema: shape }).catch((e: unknown) => e)) as ApiError;
    expect(error).toBeInstanceOf(ApiError);
    expect(error.status).toBe(502);
    expect(error.code).toBe("http_error");
  });

  it("refuses a body that does not match the contract", async () => {
    respondWith({ ok: "yes" });
    const error = await apiRequest("/x", { schema: shape }).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ApiContractError);
  });

  it("asks for a conflict to be recognisable, because a refused transition is not a fault", async () => {
    respondWith(
      { error: { code: "conflict", message: "no", correlation_id: null, details: [] } },
      { status: 409 },
    );
    const error = (await apiRequest("/x", { schema: shape }).catch((e: unknown) => e)) as ApiError;
    expect(error.isConflict).toBe(true);
  });
});

describe("refreshCookieFrom", () => {
  it("finds the API's refresh cookie among others", () => {
    expect(
      refreshCookieFrom([
        "other=1; Path=/",
        "aegisnet_refresh=abc.def; HttpOnly; Path=/; SameSite=Lax",
      ]),
    ).toBe("abc.def");
  });

  it("reads a cleared cookie as no cookie", () => {
    expect(refreshCookieFrom(["aegisnet_refresh=; Max-Age=0"])).toBeNull();
    expect(refreshCookieFrom([])).toBeNull();
  });
});
