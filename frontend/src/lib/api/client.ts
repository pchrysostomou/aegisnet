/**
 * The only place this app talks to the API.
 *
 * Server-side only, on purpose. The browser never holds an access token and never learns the
 * API's address: it talks to Next, Next talks to the API. That is what lets the session live
 * in `HttpOnly` cookies a script cannot read (T-2.4), and it means one place — this file —
 * decides what leaves the process.
 *
 * Every response is parsed against a zod schema before it is returned. A failure arrives in
 * the documented envelope and becomes an `ApiError` carrying the status and code, so callers
 * branch on facts rather than on string matching.
 */
import { z } from "zod";

import { errorEnvelope } from "./schemas";

export const DEFAULT_TIMEOUT_MS = 10_000;

/** Where the API lives, from the server environment. Never `NEXT_PUBLIC_`: the browser has no
 * business knowing, and a public variable is baked into the bundle at build time. */
export function apiBaseUrl(): string {
  const raw = process.env.AEGISNET_API_URL ?? "http://localhost:8000";
  return raw.replace(/\/+$/, "");
}

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly correlationId: string | null = null,
    readonly details: readonly { field: string; issue: string }[] = [],
  ) {
    super(message);
    this.name = "ApiError";
  }

  /** The caller's credentials are missing or spent; the session layer retries once. */
  get isUnauthenticated(): boolean {
    return this.status === 401;
  }

  get isForbidden(): boolean {
    return this.status === 403;
  }

  get isNotFound(): boolean {
    return this.status === 404;
  }

  /** A refused workflow transition, which is a normal answer rather than a fault (ADR-024). */
  get isConflict(): boolean {
    return this.status === 409;
  }
}

/** The response did not match the contract. Distinct from `ApiError`: nobody refused us, the
 * shape was simply not what this build was written against. */
export class ApiContractError extends Error {
  constructor(
    readonly path: string,
    readonly issues: string,
  ) {
    super(`the API's answer for ${path} did not match the expected shape: ${issues}`);
    this.name = "ApiContractError";
  }
}

export interface RequestOptions<T extends z.ZodType> {
  schema: T;
  method?: "GET" | "POST" | "PATCH" | "DELETE";
  body?: unknown;
  accessToken?: string | null;
  /** Sent verbatim as the API's refresh cookie; only the refresh call needs it. */
  refreshCookie?: string | null;
  query?: Record<string, string | number | boolean | null | undefined>;
  timeoutMs?: number;
}

export interface ApiResponse<T> {
  data: T;
  /** `Set-Cookie` values the API returned, for the one caller that rotates them. */
  setCookie: string[];
}

const REFRESH_COOKIE_NAME = "aegisnet_refresh";

function url(path: string, query: RequestOptions<z.ZodType>["query"]): string {
  const target = new URL(`${apiBaseUrl()}${path}`);
  for (const [key, value] of Object.entries(query ?? {})) {
    if (value !== null && value !== undefined && value !== "") {
      target.searchParams.set(key, String(value));
    }
  }
  return target.toString();
}

async function readError(response: Response): Promise<never> {
  let code = "http_error";
  let message = `the API answered ${response.status}`;
  let correlationId: string | null = null;
  let details: { field: string; issue: string }[] = [];
  try {
    const parsed = errorEnvelope.safeParse(await response.json());
    if (parsed.success) {
      ({ code, message, correlation_id: correlationId, details } = parsed.data.error);
    }
  } catch {
    // A body that is not JSON tells us nothing beyond the status, which we already have.
  }
  throw new ApiError(response.status, code, message, correlationId, details);
}

export async function apiRequest<T extends z.ZodType>(
  path: string,
  options: RequestOptions<T>,
): Promise<ApiResponse<z.infer<T>>> {
  const headers = new Headers({ Accept: "application/json" });
  if (options.accessToken) headers.set("Authorization", `Bearer ${options.accessToken}`);
  if (options.refreshCookie) {
    headers.set("Cookie", `${REFRESH_COOKIE_NAME}=${options.refreshCookie}`);
  }
  if (options.body !== undefined) headers.set("Content-Type", "application/json");

  const response = await fetch(url(path, options.query), {
    method: options.method ?? "GET",
    headers,
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
    // The dashboard shows what the API holds now; a cached case is a wrong case.
    cache: "no-store",
    signal: AbortSignal.timeout(options.timeoutMs ?? DEFAULT_TIMEOUT_MS),
  });

  if (!response.ok) await readError(response);

  const setCookie =
    typeof response.headers.getSetCookie === "function" ? response.headers.getSetCookie() : [];

  if (response.status === 204) {
    return { data: options.schema.parse(undefined), setCookie };
  }

  const parsed = options.schema.safeParse(await response.json());
  if (!parsed.success) {
    throw new ApiContractError(path, z.prettifyError(parsed.error));
  }
  return { data: parsed.data, setCookie };
}

/** The refresh cookie the API just issued, if it issued one. */
export function refreshCookieFrom(setCookie: readonly string[]): string | null {
  for (const raw of setCookie) {
    const [pair] = raw.split(";");
    const [name, ...rest] = pair.split("=");
    if (name.trim() === REFRESH_COOKIE_NAME) {
      const value = rest.join("=").trim();
      return value.length > 0 ? value : null;
    }
  }
  return null;
}
