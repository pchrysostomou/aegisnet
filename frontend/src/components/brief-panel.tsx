/**
 * An investigation brief on the case page (Milestone 5, Chunk 24; ADR-030, ADR-031, ADR-032).
 *
 * Everything shown here is prose a language model wrote after reading a redacted summary of
 * attacker-influenced input, which makes it the most hostile text this dashboard renders. It
 * all goes through `SafeMarkdown` for that reason — the same renderer an analyst's note uses,
 * parsing a fixed grammar straight into React elements so no markup can form (ADR-027). The
 * one thing it cannot render is a link, and the one thing a brief needs is links to its
 * sources; that is what `CitationList` is for, and it is deliberately a separate component
 * that never sees a markdown string.
 *
 * Three things the panel is obliged to say plainly, because a brief that is read as fact is
 * worse than no brief at all:
 *
 * - **Where it came from.** `offline_fixture` is the sample committed to this repository,
 *   shown when the feature is off. Nothing here may let it read as something a model said.
 * - **What is unverified.** A claim about the outside world that cited nothing is kept and
 *   marked, never dropped — an uncited claim is still worth reading, precisely because it is
 *   marked.
 * - **That it decided nothing.** A brief cannot move a severity, a status or an alert; it is
 *   a reading of the case, and the case is what it is with or without one.
 */
import { CitationList } from "@/components/citation-list";
import { SafeMarkdown } from "@/components/safe-markdown";
import { Timestamp } from "@/components/timestamp";
import type { Brief } from "@/lib/api/schemas";

/** The nine things a brief may suggest, in the words an analyst uses. The vocabulary has no
 * word for blocking, scanning or taking anything down, and that is the point (ADR-030). */
const ACTION_WORDS: Record<string, string> = {
  investigate_host: "Investigate the host",
  review_with_asset_owner: "Review with the asset owner",
  check_baseline: "Check the baseline",
  collect_more_evidence: "Collect more evidence",
  correlate_with_other_cases: "Correlate with other cases",
  monitor: "Keep monitoring",
  document_and_close: "Document and close",
  escalate: "Escalate",
  no_action_needed: "No action needed",
};

/** Why an answer did not arrive, in a sentence rather than a reason code. An unfamiliar code
 * is shown as itself: a brief that failed for a new reason should say so, not say nothing. */
const FAILURE_WORDS: Record<string, string> = {
  disabled: "Brief generation is turned off for this deployment.",
  unconfigured: "No API key is configured, so nothing could be asked.",
  budget_exhausted: "The daily budget for briefs is spent.",
  response_too_large: "The answer was too large to read safely.",
  malformed_json: "The API's answer was not readable.",
  malformed_brief: "The model did not answer in the required shape.",
  no_content: "The API answered with nothing in it.",
  schema_rejected: "The answer did not match the shape a brief must have.",
  safety_rejected: "The answer recommended acting on a system, so it was refused.",
};

export function UnverifiedTag() {
  return (
    <span className="badge unverified" title="No source was cited for this claim">
      UNVERIFIED
    </span>
  );
}

/** `Object.hasOwn`, never `in`: `in` walks the prototype chain, so a reason called `toString`
 * would find a function and render as nothing, and one called `__proto__` would find an object
 * and throw — blanking the whole case page from a server component with no boundary above it.
 * `failure_reason` is deliberately an unconstrained string so a new code shows itself, and this
 * is the one path where a new code has to. */
function look(table: Record<string, string>, key: string): string | null {
  return Object.hasOwn(table, key) ? table[key] : null;
}

function failureSentence(reason: string | null): string {
  if (!reason) return "The brief could not be generated.";
  const known = look(FAILURE_WORDS, reason);
  if (known !== null) return known;
  if (reason.startsWith("http_")) return `The API answered ${reason.slice(5)}.`;
  return `The request did not complete: ${reason}.`;
}

function Origin({ brief }: { brief: Brief }) {
  if (brief.source === "offline_fixture") {
    return (
      <p className="notice">
        This is the <strong>offline sample</strong> committed to this repository, not something
        a model wrote. It is shown because brief generation is off or unconfigured, so the
        feature can be seen without sending anything anywhere.
      </p>
    );
  }
  return (
    <p className="notice">
      Written by <span className="mono">{brief.model ?? "an unnamed model"}</span> from a
      redacted summary of this case. It is a reading, not a finding: it did not change the
      severity, the status or any alert.
    </p>
  );
}

function BriefBody({ brief }: { brief: Brief }) {
  if (brief.status === "failed") {
    return (
      <>
        <p className="error" role="alert">
          {failureSentence(brief.failure_reason)}
        </p>
        <p className="empty">
          The case is unaffected. A brief is a narrative about it, never a part of it.
        </p>
      </>
    );
  }

  return (
    <>
      <Origin brief={brief} />
      {brief.packet_truncated ? (
        <p className="notice">
          This case was larger than one evidence packet holds, so the brief was written from
          part of it.
        </p>
      ) : null}

      {brief.summary ? <SafeMarkdown source={brief.summary} /> : null}

      {brief.claims.length > 0 ? (
        <>
          <h4>What it says</h4>
          <ul className="claims">
            {brief.claims.map((claim, index) => (
              <li key={index} className={`claim claim-${claim.kind}`}>
                <span className="badge status">{claim.kind}</span>{" "}
                <SafeMarkdown source={claim.text} className="prose inline-prose" />
                {claim.citations.length > 0 ? (
                  <span className="mono citation-ref">
                    {" "}
                    [{claim.citations.join(", ")}]
                  </span>
                ) : null}
                {claim.verified ? null : (
                  <>
                    {" "}
                    <UnverifiedTag />
                  </>
                )}
              </li>
            ))}
          </ul>
        </>
      ) : null}

      {brief.recommendations.length > 0 ? (
        <>
          <h4>What a person could do next</h4>
          <ul className="advice">
            {brief.recommendations.map((item, index) => (
              <li key={index}>
                <strong>{look(ACTION_WORDS, item.action) ?? item.action}</strong>
                {item.detail ? (
                  <>
                    <span aria-hidden="true"> — </span>
                    <SafeMarkdown source={item.detail} className="prose inline-prose" />
                  </>
                ) : null}
              </li>
            ))}
          </ul>
          <p className="empty">
            These are things to look at, not things to do to a system. There is no vocabulary
            here for blocking, scanning or taking anything down.
          </p>
        </>
      ) : null}

      {brief.citations.length > 0 ? (
        <>
          <h4>Sources</h4>
          <CitationList citations={brief.citations} />
        </>
      ) : null}

      {brief.limitations ? (
        <>
          <h4>What it could not see</h4>
          <SafeMarkdown source={brief.limitations} />
        </>
      ) : null}
    </>
  );
}

export function BriefPanel({ briefs }: { briefs: readonly Brief[] }) {
  if (briefs.length === 0) {
    return <p className="empty">No brief has been generated for this case.</p>;
  }

  // Newest first is how the API returns them; the first is the one an analyst wants.
  const [latest, ...older] = briefs;
  return (
    <div className="brief">
      <p className="badges">
        <span className="badge status">v{latest.version}</span>
        {/* Status first: a failed brief was not generated by anything, and a badge saying
          it was, directly above the sentence saying it could not be, is the one place the
          page states provenance (ADR-031). */}
        <span className={`badge status brief-${latest.status === "failed" ? "failed" : latest.source}`}>
          {latest.status === "failed"
            ? "not generated"
            : latest.source === "offline_fixture"
              ? "offline sample"
              : "generated"}
        </span>
        {latest.has_unverified ? <UnverifiedTag /> : null}
        <span className="note-meta">
          <Timestamp value={latest.created_at} />
        </span>
      </p>

      <BriefBody brief={latest} />

      {older.length > 0 ? (
        <p className="empty">
          {older.length === 1 ? "One earlier version" : `${older.length} earlier versions`} of
          this brief {older.length === 1 ? "was" : "were"} written and kept. A brief is never
          edited or replaced; asking again writes a new one.
        </p>
      ) : null}
    </div>
  );
}
