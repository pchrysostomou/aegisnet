/**
 * Reading cases. Server-side only; the token comes from the session cookie, never from a
 * caller, so a component cannot accidentally ask on somebody else's behalf.
 */
import { readAccessToken } from "@/lib/session";

import { apiRequest } from "./client";
import {
  incidentDetail,
  incidentPage,
  note,
  notePage,
  timelinePage,
  type IncidentDetail,
  type IncidentPage,
  type IncidentStatus,
  type Note,
  type NotePage,
  type TimelinePage,
} from "./schemas";

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

export async function getIncident(id: string): Promise<IncidentDetail> {
  const { data } = await apiRequest(`/api/v1/incidents/${encodeURIComponent(id)}`, {
    schema: incidentDetail,
    accessToken: await token(),
  });
  return data;
}

export async function listNotes(id: string, limit = 50): Promise<NotePage> {
  const { data } = await apiRequest(`/api/v1/incidents/${encodeURIComponent(id)}/notes`, {
    schema: notePage,
    accessToken: await token(),
    query: { limit },
  });
  return data;
}

export async function listTimeline(
  id: string,
  cursor?: string,
  limit = 200,
): Promise<TimelinePage> {
  const { data } = await apiRequest(`/api/v1/incidents/${encodeURIComponent(id)}/timeline`, {
    schema: timelinePage,
    accessToken: await token(),
    query: { limit, cursor },
  });
  return data;
}

/** Move a case. A refusal is a `409` and comes back as an `ApiError` the caller shows to the
 * analyst; it is a normal answer, not a fault (ADR-024). */
export async function changeStatus(
  id: string,
  status: IncidentStatus,
  closureReason: string | null,
): Promise<IncidentDetail> {
  const { data } = await apiRequest(`/api/v1/incidents/${encodeURIComponent(id)}/status`, {
    schema: incidentDetail,
    method: "POST",
    accessToken: await token(),
    body: closureReason ? { status, closure_reason: closureReason } : { status },
  });
  return data;
}

export async function addNote(id: string, body: string): Promise<Note> {
  const { data } = await apiRequest(`/api/v1/incidents/${encodeURIComponent(id)}/notes`, {
    schema: note,
    method: "POST",
    accessToken: await token(),
    body: { body },
  });
  return data;
}
