import type { Metadata } from "next";
import Link from "next/link";

import { SeverityBadge, StatusBadge } from "@/components/badges";
import { Timestamp } from "@/components/timestamp";
import { ApiError } from "@/lib/api/client";
import { listIncidents, type IncidentFilters } from "@/lib/api/incidents";
import { incidentStatus, type IncidentStatus } from "@/lib/api/schemas";

import { Filters } from "./filters";
import { visible } from "@/lib/visible";

export const metadata: Metadata = { title: "Incidents — AegisNet" };
// The queue is a live view of what the API holds; nothing here may be pre-rendered.
export const dynamic = "force-dynamic";

type Search = Record<string, string | string[] | undefined>;

const one = (value: string | string[] | undefined): string | undefined =>
  typeof value === "string" && value !== "" ? value : undefined;

/** Anything the API would refuse is dropped here rather than sent: a filter typed into the
 * address bar is caller-controlled, and the queue should answer, not error. */
function readFilters(params: Search): IncidentFilters & { status?: IncidentStatus } {
  const status = incidentStatus.safeParse(one(params.status));
  const severity = Number(one(params.severity_min));
  return {
    status: status.success ? status.data : undefined,
    open: one(params.open) === "1",
    severityMin: Number.isInteger(severity) && severity >= 1 && severity <= 5 ? severity : undefined,
    cursor: one(params.cursor),
  };
}

export default async function IncidentsPage({ searchParams }: { searchParams: Promise<Search> }) {
  const params = await searchParams;
  const filters = readFilters(params);

  let page;
  try {
    page = await listIncidents(filters);
  } catch (error) {
    const message =
      error instanceof ApiError && error.isForbidden
        ? "This account may not read incidents."
        : "The incident queue could not be loaded. The API may be unavailable.";
    return (
      <main>
        <h2>Incidents</h2>
        <p className="error" role="alert">
          {message}
        </p>
      </main>
    );
  }

  const query = new URLSearchParams();
  if (filters.status) query.set("status", filters.status);
  if (filters.open) query.set("open", "1");
  if (filters.severityMin) query.set("severity_min", String(filters.severityMin));

  return (
    <main>
      <h2>Incidents</h2>
      <p className="lede">
        Cases correlation opened, newest first. Every alert about one entity within an hour of
        the last is one case.
      </p>

      <Filters
        status={filters.status}
        openOnly={Boolean(filters.open)}
        severityMin={filters.severityMin}
      />

      {page.items.length === 0 ? (
        <p className="empty">No case matches these filters.</p>
      ) : (
        <table>
          <caption>
            {page.items.length} case{page.items.length === 1 ? "" : "s"}
            {page.next_cursor ? " on this page" : ""}
          </caption>
          <thead>
            <tr>
              <th scope="col">Case</th>
              <th scope="col">Severity</th>
              <th scope="col">Status</th>
              <th scope="col">Title</th>
              <th scope="col">Entity</th>
              <th scope="col">Rules</th>
              <th scope="col">Last activity</th>
            </tr>
          </thead>
          <tbody>
            {page.items.map((incident) => (
              <tr key={incident.id}>
                <td>
                  <Link href={`/incidents/${incident.id}`} className="mono">
                    {incident.case_number}
                  </Link>
                </td>
                <td>
                  <SeverityBadge value={incident.severity} />
                </td>
                <td>
                  <StatusBadge value={incident.status} />
                </td>
                <td>{incident.title}</td>
                <td className="mono">{visible(incident.correlation_key)}</td>
                <td className="numeric">{incident.distinct_rule_count}</td>
                <td>
                  <Timestamp value={incident.window_end} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {page.next_cursor ? (
        <nav className="pager" aria-label="Pagination">
          <Link
            className="button secondary"
            href={`/incidents?${new URLSearchParams({ ...Object.fromEntries(query), cursor: page.next_cursor }).toString()}`}
          >
            Older cases
          </Link>
        </nav>
      ) : null}
    </main>
  );
}
