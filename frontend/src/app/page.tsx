// Server component. No client-side data fetching, no authentication UI, no business UI:
// this page exists so the `web` container has something to build and serve (decision F-9).
export const dynamic = "force-dynamic";

export default function HomePage() {
  const appName = process.env.NEXT_PUBLIC_APP_NAME ?? "AegisNet";
  return (
    <main>
      <h1>{appName}</h1>
      <p>Web placeholder. The analyst dashboard arrives in Milestone 4.</p>
      <p>
        Container health is reported at <code>/api/health</code>.
      </p>
    </main>
  );
}
