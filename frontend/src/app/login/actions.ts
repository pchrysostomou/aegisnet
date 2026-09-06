"use server";

import { cookies } from "next/headers";
import { redirect } from "next/navigation";

import { ApiError } from "@/lib/api/client";
import { safeNext } from "@/lib/safe-path";
import { ACCESS_COOKIE, SESSION_COOKIE, cookieOptions, login } from "@/lib/session";

export interface LoginState {
  error: string | null;
}

/** A form field, or "" when the caller sent something that is not text — a `File` here means
 * a hand-made request rather than this form. */
function text(form: FormData, name: string): string {
  const value = form.get(name);
  return typeof value === "string" ? value : "";
}

export async function signIn(_previous: LoginState, form: FormData): Promise<LoginState> {
  const email = text(form, "email").trim();
  const password = text(form, "password");
  const next = safeNext(text(form, "next"));
  if (!email || !password) return { error: "Enter an email address and a password." };

  let written;
  try {
    written = await login(email, password);
  } catch (error) {
    if (error instanceof ApiError && (error.status === 401 || error.status === 429)) {
      // The API says the same thing for a wrong password, an unknown account and a locked
      // one (T-2.1). Saying more here would undo that.
      return {
        error:
          error.status === 429
            ? "Too many attempts. Wait a moment and try again."
            : "Those credentials were not accepted.",
      };
    }
    return { error: "The API could not be reached. Try again." };
  }

  const jar = await cookies();
  for (const cookie of written) {
    jar.set(cookie.name, cookie.value, cookieOptions(cookie.maxAge));
  }
  redirect(next);
}

export async function signOut(): Promise<void> {
  const jar = await cookies();
  const { revoke } = await import("@/lib/session");
  await revoke(jar.get(ACCESS_COOKIE)?.value ?? null, jar.get(SESSION_COOKIE)?.value ?? null);
  jar.delete(ACCESS_COOKIE);
  jar.delete(SESSION_COOKIE);
  redirect("/login");
}
