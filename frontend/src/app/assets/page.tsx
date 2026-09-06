import type { Metadata } from "next";

import { Timestamp } from "@/components/timestamp";
import { ApiError } from "@/lib/api/client";
import { listAssets } from "@/lib/api/inventory";

export const metadata: Metadata = { title: "Assets — AegisNet" };
export const dynamic = "force-dynamic";

type Search = Record<string, string | string[] | undefined>;
const one = (v: string | string[] | undefined) => (typeof v === "string" && v !== "" ? v : undefined);

const ENVIRONMENTS = ["prod", "staging", "dev", "lab", "unknown"] as const;

export default async function AssetsPage({ searchParams }: { searchParams: Promise<Search> }) {
  const params = await searchParams;
  const q = one(params.q);
  const environmentRaw = one(params.environment);
  const environment = ENVIRONMENTS.find((value) => value === environmentRaw);

  let page;
  try {
    page = await listAssets({ q, environment });
  } catch (error) {
    return (
      <main>
        <h2>Assets</h2>
        <p className="error" role="alert">
          {error instanceof ApiError && error.isForbidden
            ? "This account may not read the asset inventory."
            : "The inventory could not be loaded."}
        </p>
      </main>
    );
  }

  return (
    <main>
      <h2>Assets</h2>
      <p className="lede">
        What the detectors attribute traffic to. An asset&rsquo;s criticality raises the severity
        of every alert about it, and its networks are how an address becomes a name.
      </p>

      <form className="filters" method="get" action="/assets">
        <div className="field grow">
          <label htmlFor="q">Hostname or owner contains</label>
          <input id="q" name="q" type="text" defaultValue={q ?? ""} maxLength={64} />
        </div>
        <div className="field">
          <label htmlFor="environment">Environment</label>
          <select id="environment" name="environment" defaultValue={environment ?? ""}>
            <option value="">Any</option>
            {ENVIRONMENTS.map((value) => (
              <option key={value} value={value}>
                {value}
              </option>
            ))}
          </select>
        </div>
        <button type="submit">Apply</button>
        <a className="button secondary" href="/assets">
          Clear
        </a>
      </form>

      {page.items.length === 0 ? (
        <p className="empty">No asset matches.</p>
      ) : (
        <table>
          <caption>
            {page.items.length} asset{page.items.length === 1 ? "" : "s"}
          </caption>
          <thead>
            <tr>
              <th scope="col">Hostname</th>
              <th scope="col">Environment</th>
              <th scope="col">Criticality</th>
              <th scope="col">Owner</th>
              <th scope="col">Networks</th>
              <th scope="col">Tags</th>
              <th scope="col">Updated</th>
            </tr>
          </thead>
          <tbody>
            {page.items.map((row) => (
              <tr key={row.id} className={row.is_active ? undefined : "inactive"}>
                <td className="mono">{row.hostname ?? "—"}</td>
                <td>{row.environment}</td>
                <td className="numeric">{row.criticality}</td>
                <td>{row.owner ?? "—"}</td>
                <td className="mono">
                  {row.networks.map((network) => network.cidr).join(", ") || "—"}
                </td>
                <td>{row.tags.join(", ") || "—"}</td>
                <td>
                  <Timestamp value={row.updated_at} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </main>
  );
}
