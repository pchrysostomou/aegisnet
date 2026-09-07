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

/* The `http://` literals below are the assertions, not a configuration choice, so the
 * `NOSONAR`s — six of them, not five as the commit that added them said — are the honest
 * form of "reviewed, and it stays". `S5332` ("use https instead")
 * is right about product code and wrong here: the stack binds loopback with nothing
 * terminating TLS in front of it, so `http://localhost:8000` is what `apiBaseUrl()` must
 * return, and `http://user:pass@api:8000` is a string this function must *refuse*. Rewriting
 * either to https would delete the behaviour under test to satisfy the rule.
 *
 * Why annotate rather than exclude: these files are analysed as source because the frontend's
 * tests live beside their code and `sonar.tests` cannot reach them without overlapping
 * `sonar.sources`. Excluding them would buy a green rating by not looking — the trade this
 * project refused for the container image scan (ADR-037) — and would also stop Sonar catching
 * a dead assertion here, which it has done before. */
describe("apiBaseUrl", () => {
  it("falls back to the local API and rebuilds the origin it was given", () => {
    expect(apiBaseUrl()).toBe("http://localhost:8000"); // NOSONAR - loopback default is the assertion
    process.env.AEGISNET_API_URL = "http://api:8000/"; // NOSONAR - the input under test
    expect(apiBaseUrl()).toBe("http://api:8000"); // NOSONAR - the expected normalisation
    process.env.AEGISNET_API_URL = "https://aegis.example.test";
    expect(apiBaseUrl()).toBe("https://aegis.example.test");
  });

  it.each([
    ["not-a-url", "not a URL"],
    ["file:///etc/passwd", "a scheme that is not http"],
    ["http://user:pass@api:8000", "embedded credentials"], // NOSONAR - must be refused
    ["http://api:8000/v1", "a path"], // NOSONAR - must be refused
    ["http://api:8000/?x=1", "a query"], // NOSONAR - must be refused
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
