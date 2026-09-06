"use client";

import { useActionState } from "react";

import { idle } from "./action-state";
import { requestBrief } from "./actions";

/** Only an analyst sees this: reading a brief is a viewer's business, asking for one spends a
 * budget and sends an evidence packet outside the deployment (ADR-031). The button says what
 * it does *before* it is pressed, because with the feature configured it is an outbound
 * request, and afterwards is the wrong time to learn that. */
export function BriefForm({ id, existing }: { id: string; existing: number }) {
  const [state, action, pending] = useActionState(requestBrief, idle);
  return (
    <form action={action} className="note-form" aria-labelledby="brief-request-heading">
      <h3 id="brief-request-heading" className="control-heading">
        {existing === 0 ? "Ask for a brief" : "Ask again"}
      </h3>
      {state.error ? (
        <p className="error" role="alert">
          {state.error}
        </p>
      ) : null}
      <input type="hidden" name="id" value={id} />
      {/* A <p>, not a <label>: a label attached to a button *becomes* its accessible name,
        which would leave a screen reader announcing this whole paragraph instead of "Generate
        brief" — and there is no field here to label. The browser suite caught it. */}
      <p className="control-note">
        Sends a redacted summary of this case — derived numbers and opaque tokens, never
        addresses or log text — to the configured model, and keeps whatever comes back as a new
        version. Nothing is edited or replaced. With the feature off, the committed offline
        sample is stored instead and nothing leaves this machine.
      </p>
      <button type="submit" disabled={pending}>
        {pending ? "Asking…" : existing === 0 ? "Generate brief" : "Generate a new version"}
      </button>
    </form>
  );
}
