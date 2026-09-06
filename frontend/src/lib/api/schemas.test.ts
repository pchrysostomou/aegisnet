import { describe, expect, it } from "vitest";

import { incidentDetail, incidentPage, isClosed, errorEnvelope } from "./schemas";

const incident = {
  id: "5a4419f6-af88-4b2b-bdab-672f20331af7",
  case_number: "AEG-2026-0001",
  title: "4 rules on 10.10.0.42: D-001, D-002, D-004, D-005",
  severity: 5,
  severity_rationale: { escalated: true, result: 5 },
  status: "new",
  primary_asset_id: null,
  correlation_key: "src_ip=10.10.0.42",
  window_start: "2026-09-05T09:02:00Z",
  window_end: "2026-09-05T09:40:00Z",
  distinct_rule_count: 4,
  assigned_to: null,
  closed_at: null,
  closure_reason: null,
  created_at: "2026-09-06T07:18:54Z",
  updated_at: "2026-09-06T07:18:54Z",
};

describe("the incident contract", () => {
  it("accepts what the API sends", () => {
    const parsed = incidentPage.parse({ items: [incident], next_cursor: null });
    expect(parsed.items[0].case_number).toBe("AEG-2026-0001");
  });

  it("refuses a severity outside the documented range", () => {
    expect(incidentPage.safeParse({ items: [{ ...incident, severity: 9 }], next_cursor: null }).success).toBe(
      false,
    );
  });

  it("refuses a status the workflow does not have", () => {
    expect(
      incidentPage.safeParse({ items: [{ ...incident, status: "resolved" }], next_cursor: null })
        .success,
    ).toBe(false);
  });

  it("refuses a renamed field rather than rendering undefined", () => {
    const without: Record<string, unknown> = { ...incident };
    delete without.case_number;
    expect(incidentPage.safeParse({ items: [without], next_cursor: null }).success).toBe(false);
  });

  it("keeps the detail's derived fields", () => {
    const detail = incidentDetail.parse({
      ...incident,
      alerts: [],
      timeline: [],
      timeline_truncated: false,
      allowed_transitions: ["triaging", "investigating"],
    });
    expect(detail.allowed_transitions).toEqual(["triaging", "investigating"]);
    expect(detail.timeline_truncated).toBe(false);
  });
});

describe("isClosed", () => {
  it("agrees with the domain's three closed statuses", () => {
    expect(isClosed("closed_true_positive")).toBe(true);
    expect(isClosed("closed_false_positive")).toBe(true);
    expect(isClosed("closed_benign")).toBe(true);
    expect(isClosed("new")).toBe(false);
    expect(isClosed("contained_recommended")).toBe(false);
  });
});

describe("the error envelope", () => {
  it("tolerates an absent details array", () => {
    const parsed = errorEnvelope.parse({
      error: { code: "not_found", message: "No such resource.", correlation_id: null },
    });
    expect(parsed.error.details).toEqual([]);
  });
});
