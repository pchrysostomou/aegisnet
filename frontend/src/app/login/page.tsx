import type { Metadata } from "next";

import { LoginForm } from "./login-form";

export const metadata: Metadata = { title: "Sign in — AegisNet" };
export const dynamic = "force-dynamic";

export default async function LoginPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const params = await searchParams;
  const next = typeof params.next === "string" ? params.next : "/incidents";
  const expired = params.expired === "1";
  return (
    <main>
      {expired ? (
        <p className="notice" role="status">
          That session had ended. Sign in again to continue.
        </p>
      ) : null}
      <LoginForm next={next} />
    </main>
  );
}
