"use client";

import { useActionState, useState } from "react";

import { STATUS_WORDS } from "@/components/badges";
import { isClosed, type IncidentStatus } from "@/lib/api/schemas";

import { idle } from "./action-state";
import { moveStatus } from "./actions";

/** The moves the *server* says are legal, drawn from `allowed_transitions` on the case. The
 * list is never computed here: a client that keeps its own copy of the workflow is a client
 * that will one day disagree with the server about what a case may do (ADR-024). */
export function StatusControl({
  id,
  allowed,
}: {
  id: string;
  allowed: readonly IncidentStatus[];
}) {
  const [state, action, pending] = useActionState(moveStatus, idle);
  const [target, setTarget] = useState<IncidentStatus | "">("");
  const closing = target !== "" && isClosed(target);

  if (allowed.length === 0) {
    return <p className="notice">This case has no move available from its current status.</p>;
  }

  return (
    <form action={action} className="filters" aria-labelledby="move-heading">
      <h3 id="move-heading" className="control-heading">
        Move this case
      </h3>
      {state.error ? (
        <p className="error" role="alert">
          {state.error}
        </p>
      ) : null}
      <input type="hidden" name="id" value={id} />
      <div className="field">
        <label htmlFor="status">New status</label>
        <select
          id="status"
          name="status"
          value={target}
          onChange={(event) => {
            setTarget(event.target.value as IncidentStatus | "");
          }}
          required
        >
          <option value="">Choose…</option>
          {allowed.map((status) => (
            <option key={status} value={status}>
              {STATUS_WORDS[status]}
            </option>
          ))}
        </select>
      </div>
      {closing ? (
        <div className="field grow">
          <label htmlFor="closure_reason">Why (optional, kept in the timeline)</label>
          <input
            id="closure_reason"
            name="closure_reason"
            type="text"
            maxLength={500}
            placeholder="confirmed with the owner"
          />
        </div>
      ) : null}
      <button type="submit" disabled={pending || target === ""}>
        {pending ? "Moving…" : "Move"}
      </button>
    </form>
  );
}
