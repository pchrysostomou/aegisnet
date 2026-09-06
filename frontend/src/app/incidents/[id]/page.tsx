import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";

import { SeverityBadge, StatusBadge } from "@/components/badges";
import { BriefPanel } from "@/components/brief-panel";
import { SafeMarkdown } from "@/components/safe-markdown";
import { Timestamp } from "@/components/timestamp";
import { ApiError } from "@/lib/api/client";
import { getIncident, listBriefs, listNotes } from "@/lib/api/incidents";
import type { TimelineEntry } from "@/lib/api/schemas";
import { canWrite, currentUserOrNull } from "@/lib/session";

import { BriefForm } from "./brief-form";
import { NoteForm } from "./note-form";
import { StatusControl } from "./status-control";

export const metadata: Metadata = { title: "Case — AegisNet" };
export const dynamic = "force-dynamic";

/** What a timeline entry says beyond its summary. Only keys this app understands are shown,
 * and every value is rendered as text: `detail` is a JSONB column an alert's evidence flows
 * into, so it is attacker-influenced (T-1.3). */
function entryDetail(entry: TimelineEntry): string | null {
  const detail = entry.detail;
  const parts: string[] = [];
  for (const key of ["rule_id", "from", "to", "closure_reason", "previous_case", "length"]) {
    const value = detail[key];
    if (typeof value === "string" || typeof value === "number") {
      parts.push(`${key}: ${String(value)}`);
    }
  }
  return parts.length > 0 ? parts.join(" · ") : null;
}

export default async function IncidentPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;

  let incident;
  let notes;
  let briefs;
  try {
    [incident, notes, briefs] = await Promise.all([getIncident(id), listNotes(id), listBriefs(id)]);
  } catch (error) {
    if (error instanceof ApiError && (error.isNotFound || error.status === 422)) notFound();
    if (error instanceof ApiError && error.isForbidden) {
      return (
        <main>
          <p className="error" role="alert">
            This account may not read incidents.
          </p>
        </main>
      );
    }
    throw error;
  }

  const user = await currentUserOrNull();
  const mayWrite = canWrite(user);

  return (
    <main>
      <p className="crumb">
        <Link href="/incidents">← Incidents</Link>
      </p>

      <header className="case-head">
        <h2>
          <span className="mono">{incident.case_number}</span> {incident.title}
        </h2>
        <p className="badges">
          <SeverityBadge value={incident.severity} />
          <StatusBadge value={incident.status} />
          <span className="badge status mono">{incident.correlation_key}</span>
        </p>
        <dl className="facts">
          <div>
            <dt>Activity</dt>
            <dd>
              <Timestamp value={incident.window_start} /> – <Timestamp value={incident.window_end} />
            </dd>
          </div>
          <div>
            <dt>Distinct rules</dt>
            <dd>{incident.distinct_rule_count}</dd>
          </div>
          <div>
            <dt>Opened</dt>
            <dd>
              <Timestamp value={incident.created_at} />
            </dd>
          </div>
          {incident.closed_at ? (
            <div>
              <dt>Closed</dt>
              <dd>
                <Timestamp value={incident.closed_at} />
              </dd>
            </div>
          ) : null}
        </dl>
        <p className="case-actions">
          {/* Same-origin on purpose: the browser never learns the API's address (ADR-026). */}
          <a className="button secondary" href={`/incidents/${incident.id}/report.md`}>
            Download the case as Markdown
          </a>
        </p>
        {incident.closure_reason ? (
          <p className="closure">
            <strong>Closed because:</strong> {incident.closure_reason}
          </p>
        ) : null}
      </header>

      {mayWrite ? (
        <StatusControl id={incident.id} allowed={incident.allowed_transitions} />
      ) : (
        <p className="notice">
          You are signed in as a viewer. Cases are read-only for this role.
        </p>
      )}

      <section aria-labelledby="alerts-heading">
        <h3 id="alerts-heading">Alerts in this case</h3>
        {incident.alerts.length === 0 ? (
          <p className="empty">No alert is linked to this case.</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th scope="col">Rule</th>
                <th scope="col">Severity</th>
                <th scope="col">Entity</th>
                <th scope="col">Events</th>
                <th scope="col">First seen</th>
                <th scope="col">Last seen</th>
              </tr>
            </thead>
            <tbody>
              {incident.alerts.map((alert) => (
                <tr key={alert.id}>
                  <td className="mono">{alert.rule_id}</td>
                  <td>
                    <SeverityBadge value={alert.severity} />
                  </td>
                  <td className="mono">
                    {alert.entity_type}={alert.entity_value}
                  </td>
                  <td className="numeric">{alert.event_count}</td>
                  <td>
                    <Timestamp value={alert.first_seen} />
                  </td>
                  <td>
                    <Timestamp value={alert.last_seen} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      <section aria-labelledby="timeline-heading">
        <h3 id="timeline-heading">Timeline</h3>
        {incident.timeline_truncated ? (
          <p className="notice">
            This case has more history than is shown; the most recent {incident.timeline.length}{" "}
            entries are here.
          </p>
        ) : null}
        <ol className="timeline">
          {incident.timeline.map((entry) => {
            const detail = entryDetail(entry);
            return (
              <li key={entry.id} className={`entry entry-${entry.entry_type}`}>
                <Timestamp value={entry.occurred_at} />
                <span className="badge status">{entry.entry_type.replace(/_/g, " ")}</span>
                <span className="summary">{entry.summary}</span>
                {detail ? <span className="detail mono">{detail}</span> : null}
              </li>
            );
          })}
        </ol>
      </section>

      <section aria-labelledby="brief-heading">
        <h3 id="brief-heading">Investigation brief</h3>
        {/* A viewer reads a brief; only an analyst may ask for one (ADR-031). */}
        <BriefPanel briefs={briefs} />
        {mayWrite ? <BriefForm id={incident.id} existing={briefs.length} /> : null}
      </section>

      <section aria-labelledby="notes-heading">
        <h3 id="notes-heading">Notes</h3>
        {notes.items.length === 0 ? (
          <p className="empty">Nobody has written on this case yet.</p>
        ) : (
          <ol className="notes">
            {notes.items.map((note) => (
              <li key={note.id}>
                <p className="note-meta">
                  <Timestamp value={note.created_at} />
                </p>
                {/* Analyst free text: rendered by the allow-list renderer, never as HTML. */}
                <SafeMarkdown source={note.body} />
              </li>
            ))}
          </ol>
        )}
        {mayWrite ? <NoteForm id={incident.id} /> : null}
      </section>
    </main>
  );
}
