import type { IncidentStatus } from "@/lib/api/schemas";

/** Severity as a number plus a word, never colour alone: colour is not information somebody
 * with a colour vision deficiency can read (WCAG 1.4.1). */
const SEVERITY_WORDS: Record<number, string> = {
  1: "informational",
  2: "low",
  3: "medium",
  4: "high",
  5: "critical",
};

export function SeverityBadge({ value }: { value: number }) {
  const word = SEVERITY_WORDS[value] ?? "unknown";
  return (
    <span className={`badge sev-${String(value)}`}>
      {value} {word}
    </span>
  );
}

/** The workflow's own labels, made readable without inventing new vocabulary: an analyst who
 * reads "closed (false positive)" here and `closed_false_positive` in the API is looking at
 * the same status. */
const STATUS_WORDS: Record<IncidentStatus, string> = {
  new: "new",
  triaging: "triaging",
  investigating: "investigating",
  contained_recommended: "containment recommended",
  closed_true_positive: "closed (true positive)",
  closed_false_positive: "closed (false positive)",
  closed_benign: "closed (benign)",
};

export function StatusBadge({ value }: { value: IncidentStatus }) {
  return <span className="badge status">{STATUS_WORDS[value]}</span>;
}

export { SEVERITY_WORDS, STATUS_WORDS };
