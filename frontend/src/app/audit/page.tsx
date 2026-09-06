import type { Metadata } from "next";
import { notFound } from "next/navigation";

import { Timestamp } from "@/components/timestamp";
import { ApiError } from "@/lib/api/client";
import { listAudit } from "@/lib/api/inventory";
import { currentUserOrNull } from "@/lib/session";

export const metadata: Metadata = { title: "Audit — AegisNet" };
export const dynamic = "force-dynamic";

type Search = Record<string, string | string[] | undefined>;
const one = (v: string | string[] | undefined) => (typeof v === "string" && v !== "" ? v : undefined);

const RESULTS = ["success", "denied", "error"] as const;
/** Action names are server-owned strings; only the ones this build knows are offered, so a
 * filter cannot be used to probe with arbitrary text. */
const ACTION = /^[a-z][a-z0-9_.]{0,63}$/;

export default async function AuditPage({ searchParams }: { searchParams: Promise<Search> }) {
  const user = await currentUserOrNull();
  // The API is the authority — it answers 403 to anyone but an admin. Hiding the page from
  // everybody else simply avoids drawing a door that will not open.
  if (user?.role !== "admin") notFound();

  const params = await searchParams;
  const actionRaw = one(params.action);
  const action = actionRaw && ACTION.test(actionRaw) ? actionRaw : undefined;
  const resultRaw = one(params.result);
  const result = RESULTS.find((value) => value === resultRaw);

  let page;
  try {
    page = await listAudit({ action, result });
  } catch (error) {
    return (
      <main>
        <h2>Audit</h2>
        <p className="error" role="alert">
          {error instanceof ApiError && error.isForbidden
            ? "Only an administrator may read the audit trail."
            : "The audit trail could not be loaded."}
        </p>
      </main>
    );
  }

  return (
    <main>
      <h2>Audit</h2>
      <p className="lede">
        Append-only. The runtime role may insert and read these rows and nothing else — no
        update, no delete — which is what makes them evidence rather than a log.
      </p>

      <form className="filters" method="get" action="/audit">
        <div className="field">
          <label htmlFor="action">Action</label>
          <input
            id="action"
            name="action"
            type="text"
            defaultValue={action ?? ""}
            maxLength={64}
            placeholder="incident.status_changed"
          />
        </div>
        <div className="field">
          <label htmlFor="result">Result</label>
          <select id="result" name="result" defaultValue={result ?? ""}>
            <option value="">Any</option>
            {RESULTS.map((value) => (
              <option key={value} value={value}>
                {value}
              </option>
            ))}
          </select>
        </div>
        <button type="submit">Apply</button>
        <a className="button secondary" href="/audit">
          Clear
        </a>
      </form>

      {page.items.length === 0 ? (
        <p className="empty">No audit row matches.</p>
      ) : (
        <table>
          <caption>{page.items.length} rows, newest first</caption>
          <thead>
            <tr>
              <th scope="col">When</th>
              <th scope="col">Action</th>
              <th scope="col">Result</th>
              <th scope="col">Target</th>
              <th scope="col">Actor</th>
              <th scope="col">Detail</th>
            </tr>
          </thead>
          <tbody>
            {page.items.map((row) => (
              <tr key={row.id}>
                <td>
                  <Timestamp value={row.occurred_at} />
                </td>
                <td className="mono">{row.action}</td>
                <td>
                  <span className={`badge result-${row.result}`}>{row.result}</span>
                </td>
                <td className="mono">
                  {row.target_type}
                  {row.target_id ? `:${row.target_id}` : ""}
                </td>
                <td className="mono">{row.actor_user_id ?? row.actor_token_id ?? "—"}</td>
                {/* Bounded and scrubbed by the audit writer before storage; rendered as text. */}
                <td className="detail mono">{JSON.stringify(row.detail)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </main>
  );
}
