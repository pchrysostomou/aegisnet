import { beforeEach, describe, expect, it, vi } from "vitest";

import { ApiError } from "@/lib/api/client";

vi.mock("next/cache", () => ({ revalidatePath: vi.fn() }));
const changeStatus = vi.hoisted(() => vi.fn());
const addNote = vi.hoisted(() => vi.fn());
vi.mock("@/lib/api/incidents", () => ({ changeStatus, addNote }));

const { idle, moveStatus, writeNote } = await import("./actions");

const ID = "5a4419f6-af88-4b2b-bdab-672f20331af7";

function form(fields: Record<string, string>): FormData {
  const data = new FormData();
  for (const [key, value] of Object.entries(fields)) data.set(key, value);
  return data;
}

beforeEach(() => {
  changeStatus.mockReset();
  addNote.mockReset();
});

describe("moveStatus", () => {
  it("passes a legal move to the API and reports success", async () => {
    changeStatus.mockResolvedValue({});
    const state = await moveStatus(idle, form({ id: ID, status: "triaging" }));
    expect(state).toEqual({ error: null, ok: true });
    expect(changeStatus).toHaveBeenCalledWith(ID, "triaging", null);
  });

  it("sends a closure reason only with a closing status", async () => {
    changeStatus.mockResolvedValue({});
    await moveStatus(idle, form({ id: ID, status: "closed_benign", closure_reason: " known " }));
    expect(changeStatus).toHaveBeenCalledWith(ID, "closed_benign", "known");
  });

  it("refuses a closure reason on a move that closes nothing, before calling the API", async () => {
    const state = await moveStatus(idle, form({ id: ID, status: "triaging", closure_reason: "x" }));
    expect(state.ok).toBe(false);
    expect(state.error).toContain("closing status");
    expect(changeStatus).not.toHaveBeenCalled();
  });

  it("refuses a status the workflow does not have", async () => {
    const state = await moveStatus(idle, form({ id: ID, status: "resolved" }));
    expect(state.ok).toBe(false);
    expect(changeStatus).not.toHaveBeenCalled();
  });

  it("refuses a case reference that is not one", async () => {
    for (const id of ["", "../../etc", "not-a-uuid", `${ID}/x`]) {
      const state = await moveStatus(idle, form({ id, status: "triaging" }));
      expect(state.ok, id).toBe(false);
    }
    expect(changeStatus).not.toHaveBeenCalled();
  });

  it("repeats the workflow's own words when it refuses a move (409)", async () => {
    changeStatus.mockRejectedValue(
      new ApiError(409, "conflict", "new may become investigating, triaging, not contained"),
    );
    const state = await moveStatus(idle, form({ id: ID, status: "contained_recommended" }));
    expect(state.ok).toBe(false);
    expect(state.error).toContain("may become");
  });

  it("does not repeat an unexpected server message back to the analyst", async () => {
    changeStatus.mockRejectedValue(new ApiError(500, "internal_error", "psycopg: relation x"));
    const state = await moveStatus(idle, form({ id: ID, status: "triaging" }));
    expect(state.error).toBe("The case could not be moved.");
    expect(state.error).not.toContain("psycopg");
  });

  it("explains a forbidden move in the role's terms", async () => {
    changeStatus.mockRejectedValue(new ApiError(403, "forbidden", "This action is not permitted."));
    const state = await moveStatus(idle, form({ id: ID, status: "triaging" }));
    expect(state.error).toContain("may not change a case");
  });
});

describe("writeNote", () => {
  it("sends the body as typed, whitespace and markdown intact", async () => {
    addNote.mockResolvedValue({});
    const body = ["line one", "", "- a", "- b", "", "`ioc`"].join("\n");
    const state = await writeNote(idle, form({ id: ID, body }));
    expect(state.ok).toBe(true);
    expect(addNote).toHaveBeenCalledWith(ID, body);
  });

  it("refuses an empty note without troubling the API", async () => {
    for (const body of ["", "   ", "\n\n"]) {
      const state = await writeNote(idle, form({ id: ID, body }));
      expect(state.ok).toBe(false);
    }
    expect(addNote).not.toHaveBeenCalled();
  });

  it("names the field when the server refuses the body (422)", async () => {
    addNote.mockRejectedValue(
      new ApiError(422, "validation_failed", "Request failed validation.", null, [
        { field: "body", issue: "a note needs something in it" },
      ]),
    );
    // A body this app is willing to send: only the server can know it is too long, or empty
    // once its own cleaning has run.
    const state = await writeNote(idle, form({ id: ID, body: "\u0007\u0007 x" }));
    expect(addNote).toHaveBeenCalled();
    expect(state.error).toBe("a note needs something in it");
  });
});
