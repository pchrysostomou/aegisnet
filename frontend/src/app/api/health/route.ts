import { NextResponse } from "next/server";

// Answered at request time, never pre-rendered at build, so it reflects the running
// process. The Compose healthcheck greps this exact body.
export const dynamic = "force-dynamic";

export function GET() {
  return NextResponse.json({ status: "ok" }, { headers: { "Cache-Control": "no-store" } });
}
