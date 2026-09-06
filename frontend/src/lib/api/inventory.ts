/**
 * The asset inventory and the audit trail, read-only.
 *
 * Both are server-side reads like the incident routes: the token comes from the session
 * cookie, and the API decides what the caller may see. `assets.read` is a viewer permission;
 * `audit.read` is an admin one, so the audit page is drawn only for an admin and the API
 * refuses anybody else regardless.
 */
import { readAccessToken } from "@/lib/session";

import { apiRequest } from "./client";
import { assetPage, auditPage, type AssetPage, type AuditPage } from "./schemas";

async function token(): Promise<string> {
  const accessToken = await readAccessToken();
  if (!accessToken) throw new Error("no session");
  return accessToken;
}

export async function listAssets(options: {
  q?: string;
  environment?: string;
  cursor?: string;
  limit?: number;
}): Promise<AssetPage> {
  const { data } = await apiRequest("/api/v1/assets", {
    schema: assetPage,
    accessToken: await token(),
    query: {
      q: options.q,
      environment: options.environment,
      cursor: options.cursor,
      limit: options.limit ?? 50,
    },
  });
  return data;
}

export async function listAudit(options: {
  action?: string;
  result?: string;
  cursor?: string;
  limit?: number;
}): Promise<AuditPage> {
  const { data } = await apiRequest("/api/v1/audit", {
    schema: auditPage,
    accessToken: await token(),
    query: {
      action: options.action,
      result: options.result,
      cursor: options.cursor,
      limit: options.limit ?? 50,
    },
  });
  return data;
}
