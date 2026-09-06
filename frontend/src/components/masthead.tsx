import Link from "next/link";

import { signOut } from "@/app/login/actions";
import { currentUserOrNull } from "@/lib/session";

/** The one place that says who is signed in. It asks the API rather than trusting the cookie:
 * the role decides which controls are drawn, and a cookie is not evidence of a role. */
export async function Masthead() {
  const user = await currentUserOrNull();
  return (
    <header className="masthead">
      <h1>AegisNet</h1>
      {user ? (
        <>
          <nav aria-label="Sections">
            <Link href="/incidents">Incidents</Link>
          </nav>
          <span className="spacer" />
          <span className="who">
            {user.display_name} · {user.role}
          </span>
          <form action={signOut}>
            <button type="submit" className="secondary">
              Sign out
            </button>
          </form>
        </>
      ) : null}
    </header>
  );
}
