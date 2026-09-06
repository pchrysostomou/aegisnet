import { incidentStatuses } from "@/lib/api/schemas";
import { STATUS_WORDS } from "@/components/badges";

/** A plain GET form. The filters end up in the URL, so a case an analyst is looking at can be
 * sent to a colleague by copying the address bar, and the back button does what it says. */
export function Filters({
  status,
  openOnly,
  severityMin,
}: {
  status?: string;
  openOnly: boolean;
  severityMin?: number;
}) {
  return (
    <form className="filters" method="get" action="/incidents">
      <div className="field">
        <label htmlFor="status">Status</label>
        <select id="status" name="status" defaultValue={status ?? ""}>
          <option value="">Any</option>
          {incidentStatuses.map((value) => (
            <option key={value} value={value}>
              {STATUS_WORDS[value]}
            </option>
          ))}
        </select>
      </div>
      <div className="field">
        <label htmlFor="severity_min">Severity at least</label>
        <select id="severity_min" name="severity_min" defaultValue={severityMin?.toString() ?? ""}>
          <option value="">Any</option>
          {[1, 2, 3, 4, 5].map((value) => (
            <option key={value} value={value}>
              {value}
            </option>
          ))}
        </select>
      </div>
      <div className="field">
        <label htmlFor="open">Show</label>
        <select id="open" name="open" defaultValue={openOnly ? "1" : ""}>
          <option value="">Every case</option>
          <option value="1">Open cases only</option>
        </select>
      </div>
      <button type="submit">Apply</button>
      <a className="button secondary" href="/incidents">
        Clear
      </a>
    </form>
  );
}
