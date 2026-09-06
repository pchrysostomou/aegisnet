"use client";

import { useActionState } from "react";

import { idle } from "./action-state";
import { writeNote } from "./actions";

/** Notes are never edited or deleted, which is why the form says so before it is used rather
 * than after (ADR-024). */
export function NoteForm({ id }: { id: string }) {
  const [state, action, pending] = useActionState(writeNote, idle);
  return (
    <form action={action} className="note-form" aria-labelledby="note-heading">
      <h3 id="note-heading" className="control-heading">
        Write a note
      </h3>
      {state.error ? (
        <p className="error" role="alert">
          {state.error}
        </p>
      ) : null}
      <input type="hidden" name="id" value={id} />
      <label htmlFor="body">
        What you found. Markdown for emphasis, lists and `code`; links are not rendered. A note
        cannot be edited or deleted once written.
      </label>
      <textarea id="body" name="body" rows={5} maxLength={8000} required />
      <button type="submit" disabled={pending}>
        {pending ? "Saving…" : "Add note"}
      </button>
    </form>
  );
}
