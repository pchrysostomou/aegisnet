/**
 * The shapes the API promises, restated so this app can refuse anything else.
 *
 * These mirror `backend/src/aegisnet/api/schemas.py` and are documented in
 * `docs/api-milestone-1.md` … `api-milestone-5.md`. Parsing at the boundary is not ceremony:
 * every string below started life in a packet somebody else sent, and a response that has
 * drifted from the contract should fail here — loudly, in one place — rather than as an
 * undefined halfway down a component tree.
 *
 * Deliberately not exhaustive. A field this dashboard does not render is a field it does not
 * validate; `.loose()` would be the opposite trade and would let a rename pass silently.
 */
import { z } from "zod";

export const incidentStatuses = [
  "new",
  "triaging",
  "investigating",
  "contained_recommended",
  "closed_true_positive",
  "closed_false_positive",
  "closed_benign",
] as const;
export const incidentStatus = z.enum(incidentStatuses);
export type IncidentStatus = z.infer<typeof incidentStatus>;

export const closedStatuses: readonly IncidentStatus[] = [
  "closed_true_positive",
  "closed_false_positive",
  "closed_benign",
];

export const isClosed = (status: IncidentStatus): boolean => closedStatuses.includes(status);

export const timelineEntryType = z.enum([
  "alert_fired",
  "observation",
  "status_change",
  "note_added",
  "brief_generated",
  "report_exported",
  "asset_linked",
]);
export type TimelineEntryType = z.infer<typeof timelineEntryType>;

export const entityType = z.enum(["asset", "src_ip", "dest_ip", "domain"]);

/** 1..5, the only severities the backend will emit. */
export const severity = z.number().int().min(1).max(5);

const isoDateTime = z.string().min(1);

export const incident = z.object({
  id: z.uuid(),
  case_number: z.string(),
  title: z.string(),
  severity,
  severity_rationale: z.record(z.string(), z.unknown()),
  status: incidentStatus,
  primary_asset_id: z.uuid().nullable(),
  correlation_key: z.string(),
  window_start: isoDateTime,
  window_end: isoDateTime,
  distinct_rule_count: z.number().int(),
  assigned_to: z.uuid().nullable(),
  closed_at: isoDateTime.nullable(),
  closure_reason: z.string().nullable(),
  created_at: isoDateTime,
  updated_at: isoDateTime,
});
export type Incident = z.infer<typeof incident>;

export const alert = z.object({
  id: z.uuid(),
  rule_id: z.string(),
  severity,
  confidence: z.number(),
  entity_type: entityType,
  entity_value: z.string(),
  first_seen: isoDateTime,
  last_seen: isoDateTime,
  event_count: z.number().int(),
  status: z.enum(["open", "correlated", "suppressed"]),
  evidence: z.record(z.string(), z.unknown()),
});
export type Alert = z.infer<typeof alert>;

export const timelineEntry = z.object({
  id: z.uuid(),
  occurred_at: isoDateTime,
  entry_type: timelineEntryType,
  summary: z.string(),
  detail: z.record(z.string(), z.unknown()),
  alert_id: z.uuid().nullable(),
  actor_user_id: z.uuid().nullable(),
  created_at: isoDateTime,
});
export type TimelineEntry = z.infer<typeof timelineEntry>;

export const incidentDetail = incident.extend({
  alerts: z.array(alert),
  timeline: z.array(timelineEntry),
  timeline_truncated: z.boolean(),
  allowed_transitions: z.array(incidentStatus),
});
export type IncidentDetail = z.infer<typeof incidentDetail>;

/** Every list route answers this shape; `next_cursor` is null on the last page. */
export const page = <T extends z.ZodType>(item: T) =>
  z.object({ items: z.array(item), next_cursor: z.string().nullable() });

export const incidentPage = page(incident);
export type IncidentPage = z.infer<typeof incidentPage>;

export const note = z.object({
  id: z.uuid(),
  incident_id: z.uuid(),
  author_id: z.uuid().nullable(),
  body: z.string(),
  created_at: isoDateTime,
});
export type Note = z.infer<typeof note>;

export const notePage = page(note);
export type NotePage = z.infer<typeof notePage>;

export const timelinePage = page(timelineEntry);
export type TimelinePage = z.infer<typeof timelinePage>;

export const briefStatus = z.enum(["complete", "failed"]);
export type BriefStatus = z.infer<typeof briefStatus>;

/** `offline_fixture` is the sample committed to the repository, served when the feature is off.
 * It must never be shown as something a model said (ADR-031), which is why it is a field rather
 * than an inference from `model` being null. */
export const briefSource = z.enum(["perplexity", "offline_fixture"]);
export type BriefSource = z.infer<typeof briefSource>;

export const briefCitation = z.object({
  id: z.number().int(),
  url: z.string(),
  title: z.string(),
});
export type BriefCitation = z.infer<typeof briefCitation>;

export const briefClaim = z.object({
  text: z.string(),
  /** `observed` or `external`, but typed as the API types it. A narrower enum here would turn a
   * value the domain adds later into a contract error that blanks the whole case page. */
  kind: z.string(),
  citations: z.array(z.number().int()),
  /** False means the model asserted something about the outside world and cited nothing for it.
   * Shown as `UNVERIFIED`; never dropped (ADR-030). */
  verified: z.boolean(),
});
export type BriefClaim = z.infer<typeof briefClaim>;

export const briefRecommendation = z.object({ action: z.string(), detail: z.string() });
export type BriefRecommendation = z.infer<typeof briefRecommendation>;

export const brief = z.object({
  id: z.uuid(),
  incident_id: z.uuid(),
  version: z.number().int(),
  status: briefStatus,
  source: briefSource,
  packet_hash: z.string(),
  packet_truncated: z.boolean(),
  model: z.string().nullable(),
  summary: z.string().nullable(),
  limitations: z.string().nullable(),
  claims: z.array(briefClaim),
  recommendations: z.array(briefRecommendation),
  citations: z.array(briefCitation),
  has_unverified: z.boolean(),
  failure_reason: z.string().nullable(),
  created_at: isoDateTime,
});
export type Brief = z.infer<typeof brief>;

/** A bare array: `GET /briefs` is `response_model=list[BriefOut]`, with no page envelope. */
export const briefList = z.array(brief);
export type BriefList = z.infer<typeof briefList>;

export const assetEnvironment = z.enum(["prod", "staging", "dev", "lab", "unknown"]);

export const assetNetwork = z.object({
  id: z.uuid(),
  cidr: z.string(),
  is_primary: z.boolean(),
});

export const asset = z.object({
  id: z.uuid(),
  hostname: z.string().nullable(),
  environment: assetEnvironment,
  owner: z.string().nullable(),
  criticality: z.number().int().min(1).max(5),
  tags: z.array(z.string()),
  description: z.string().nullable(),
  is_active: z.boolean(),
  created_at: isoDateTime,
  updated_at: isoDateTime,
  networks: z.array(assetNetwork),
});
export type Asset = z.infer<typeof asset>;

export const assetPage = page(asset);
export type AssetPage = z.infer<typeof assetPage>;

export const auditResult = z.enum(["success", "denied", "error"]);

export const auditRow = z.object({
  id: z.number().int(),
  occurred_at: isoDateTime,
  action: z.string(),
  target_type: z.string(),
  target_id: z.string().nullable(),
  result: auditResult,
  detail: z.record(z.string(), z.unknown()),
  actor_user_id: z.uuid().nullable(),
  actor_token_id: z.uuid().nullable(),
  actor_ip: z.string().nullable(),
  correlation_id: z.uuid().nullable(),
});
export type AuditRow = z.infer<typeof auditRow>;

export const auditPage = page(auditRow);
export type AuditPage = z.infer<typeof auditPage>;

export const roles = ["viewer", "analyst", "admin"] as const;
export const role = z.enum(roles);
export type Role = z.infer<typeof role>;

export const currentUser = z.object({
  id: z.uuid(),
  email: z.string(),
  display_name: z.string(),
  role,
});
export type CurrentUser = z.infer<typeof currentUser>;

export const tokenResponse = z.object({
  access_token: z.string().min(1),
  token_type: z.string(),
  expires_in: z.number().int().positive(),
});
export type TokenResponse = z.infer<typeof tokenResponse>;

/** The documented error envelope; every failure arrives in it (`api-milestone-1.md`). */
export const errorEnvelope = z.object({
  error: z.object({
    code: z.string(),
    message: z.string(),
    correlation_id: z.string().nullable(),
    details: z.array(z.object({ field: z.string(), issue: z.string() })).default([]),
  }),
});
export type ErrorEnvelope = z.infer<typeof errorEnvelope>;
