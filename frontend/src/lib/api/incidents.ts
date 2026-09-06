/**
 * Reading cases. Server-side only; the token comes from the session cookie, never from a
 * caller, so a component cannot accidentally ask on somebody else's behalf.
 */
import { readAccessToken } from "@/lib/session";

import { apiRequest } from "./client";
import { incidentPage, type IncidentPage, type IncidentStatus } from "./schemas";

export const PAGE_SIZE = 25;

export interface IncidentFilters {
  status?: IncidentStatus;
  open?: boolean;
  severityMin?: number;
  correlationKey?: string;
  cursor?: string;
  limit?: number;
}

export class NotAuthenticated extends Error {
  constructor() {
    super("no session");
    this.name = "NotAuthenticated";
  }
}

async function token(): Promise<string> {
  const accessToken = await readAccessToken();
  if (!accessToken) throw new NotAuthenticated();
  return accessToken;
}

export async function listIncidents(filters: IncidentFilters = {}): Promise<IncidentPage> {
  const { data } = await apiRequest("/api/v1/incidents", {
    schema: incidentPage,
    accessToken: await token(),
    query: {
      status: filters.status,
      // The API reads `open` as a flag; sending it as false would still narrow nothing, but
      // an absent parameter is the honest way to say "no opinion".
      open: filters.open ? "true" : undefined,
      severity_min: filters.severityMin,
      correlation_key: filters.correlationKey,
      cursor: filters.cursor,
      limit: filters.limit ?? PAGE_SIZE,
    },
  });
  return data;
}
