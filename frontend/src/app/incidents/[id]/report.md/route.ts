import { ApiError } from "@/lib/api/client";
import { exportReport } from "@/lib/api/incidents";

/**
 * The case as a downloadable document, served from this app's own origin.
 *
 * It has to be a route here rather than a link to the API. The browser never learns the API's
 * address and never holds a token (ADR-026): it asks Next, Next asks the API with the session
 * cookie's access token, and the bytes come back through. A link straight at `AEGISNET_API_URL`
 * would put the API's address into the HTML — the one property the whole session design exists
 * to hold.
 *
 * The body is passed through unchanged, so what an analyst downloads is byte-identical to what
 * `make export` writes.
 */
export const dynamic = "force-dynamic";

const CASE_ID = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

export async function GET(_request: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  if (!CASE_ID.test(id)) return new Response("Not found", { status: 404 });

  let document: string;
  try {
    document = await exportReport(id);
  } catch (error) {
    if (error instanceof ApiError) {
      return new Response(error.isNotFound ? "Not found" : "Unavailable", {
        status: error.isNotFound ? 404 : error.isForbidden ? 403 : 502,
      });
    }
    return new Response("Unavailable", { status: 502 });
  }

  return new Response(document, {
    headers: {
      "Content-Type": "text/markdown; charset=utf-8",
      // The id is the only thing in the name, and it was checked against a UUID above: a case
      // title is written by whoever named a rule and has no business in a header.
      "Content-Disposition": `attachment; filename="incident-${id}.md"`,
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
    },
  });
}
