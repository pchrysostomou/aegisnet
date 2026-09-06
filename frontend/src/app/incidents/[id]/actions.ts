"use server";

import { revalidatePath } from "next/cache";

import { ApiError } from "@/lib/api/client";
import { addNote, changeStatus } from "@/lib/api/incidents";
import { incidentStatus, isClosed } from "@/lib/api/schemas";

export interface ActionState {
  error: string | null;
  ok: boolean;
}

export const idle: ActionState = { error: null, ok: false };

function field(form: FormData, name: string): string {
  const value = form.get(name);
  return typeof value === "string" ? value : "";
}

/** A case id only ever comes from a link this app rendered, but it arrives through a form, so
 * it is checked against the shape the API will accept rather than passed on trust. */
const CASE_ID = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

/** What the API said, when it is safe to repeat. A `409` is the workflow refusing a move and
 * its message is written for an analyst; anything else gets a generic line, because an API
 * error message is not a channel this app should widen (T-2.7). */
function explain(error: unknown, fallback: string): string {
  if (error instanceof ApiError) {
    if (error.isConflict) return error.message;
    if (error.isForbidden) return "This account may not change a case.";
    if (error.isNotFound) return "That case no longer exists.";
    if (error.status === 422) {
      return error.details[0]?.issue ?? "The server would not accept that.";
    }
  }
  return fallback;
}

export async function moveStatus(_previous: ActionState, form: FormData): Promise<ActionState> {
  const id = field(form, "id");
  if (!CASE_ID.test(id)) return { error: "That case reference is not valid.", ok: false };

  const parsed = incidentStatus.safeParse(field(form, "status"));
  if (!parsed.success) return { error: "Choose a status to move to.", ok: false };

  const reason = field(form, "closure_reason").trim();
  if (reason && !isClosed(parsed.data)) {
    return { error: "A closure reason belongs on a closing status.", ok: false };
  }

  try {
    await changeStatus(id, parsed.data, reason || null);
  } catch (error) {
    return { error: explain(error, "The case could not be moved."), ok: false };
  }
  revalidatePath(`/incidents/${id}`);
  revalidatePath("/incidents");
  return { error: null, ok: true };
}

export async function writeNote(_previous: ActionState, form: FormData): Promise<ActionState> {
  const id = field(form, "id");
  if (!CASE_ID.test(id)) return { error: "That case reference is not valid.", ok: false };

  const body = field(form, "body");
  if (!body.trim()) return { error: "A note needs something in it.", ok: false };

  try {
    await addNote(id, body);
  } catch (error) {
    return { error: explain(error, "The note could not be saved."), ok: false };
  }
  revalidatePath(`/incidents/${id}`);
  return { error: null, ok: true };
}
