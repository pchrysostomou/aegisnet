/**
 * Reading cases. Server-side only; the token comes from the session cookie, never from a
 * caller, so a component cannot accidentally ask on somebody else's behalf.
 */
import { readAccessToken } from "@/lib/session";

import { apiRequest, apiText } from "./client";
import {
  brief,
  briefList,
  incidentDetail,
  incidentPage,
  note,
  notePage,
  timelinePage,
  type BriefList,
  type IncidentDetail,
  type IncidentPage,
  type IncidentStatus,
  type Note,
  type NotePage,
  type TimelinePage,
} from "./schemas";

export const PAGE_SIZE = 25;

/** Asking for a brief can legitimately take minutes: the API allows a 30-second call and two
 * retries, so the default 10-second budget would abort a request the API then completes — the
 * analyst would be told it failed while a brief was quietly stored, and would press the button
 * again. The wait belongs to whichever is longer, and it is the API's. */
export const BRIEF_TIMEOUT_MS = 150_000;

/** A large case is assembled from several queries. Longer than a list, far shorter than a brief. */
export const REPORT_TIMEOUT_MS = 60_000;

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

/** Every brief written about a case, newest version first. A viewer may read these: a brief is
 * a narrative about alerts they can already see (ADR-031). */
export async function listBriefs(id: string): Promise<BriefList> {
  const { data } = await apiRequest(`/api/v1/incidents/${encodeURIComponent(id)}/briefs`, {
    schema: briefList,
    accessToken: await token(),
  });
  return data;
}

/** Ask for a brief. Answers `201` even when the answer could not be produced — a failure is a
 * stored brief with a reason, not an error (ADR-031) — so the caller re-reads and shows it. */
export async function generateBrief(id: string): Promise<void> {
  await apiRequest(`/api/v1/incidents/${encodeURIComponent(id)}/briefs`, {
    schema: brief,
    method: "POST",
    accessToken: await token(),
    timeoutMs: BRIEF_TIMEOUT_MS,
  });
}

/** The case as Markdown, straight through. Not `apiRequest`: that one parses JSON against a
 * schema, and this body is a document. */
export async function exportReport(id: string): Promise<string> {
  return apiText(
    `/api/v1/incidents/${encodeURIComponent(id)}/report.md`,
    await token(),
    REPORT_TIMEOUT_MS,
  );
}
