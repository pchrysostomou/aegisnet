import path from "node:path";

import { test as base, type Page } from "@playwright/test";

/**
 * Signing in for real, through the form, against the running API.
 *
 * The credentials come from the environment because they belong to the operator's own stack;
 * there is no default, so a misconfigured run fails with a sentence rather than by silently
 * testing an anonymous session.
 */
export const ANALYST = {
  email: process.env.AEGISNET_E2E_ANALYST ?? "",
  password: process.env.AEGISNET_E2E_ANALYST_PASSWORD ?? "",
};
export const VIEWER = {
  email: process.env.AEGISNET_E2E_VIEWER ?? "",
  password: process.env.AEGISNET_E2E_VIEWER_PASSWORD ?? "",
};

export async function signIn(page: Page, who: { email: string; password: string }) {
  if (!who.email || !who.password) {
    throw new Error(
      "set AEGISNET_E2E_ANALYST/_PASSWORD and AEGISNET_E2E_VIEWER/_PASSWORD before running the e2e suite",
    );
  }
  await page.goto("/login");
  await page.getByLabel("Email").fill(who.email);
  await page.getByLabel("Password").fill(who.password);
  await page.getByRole("button", { name: "Sign in" }).click();
  await page.waitForURL(/\/incidents/);
}

/** Where a signed-in session is kept between tests. Gitignored: these files hold a live
 * session cookie for the operator's own stack. */
export function statePath(role: "analyst" | "viewer"): string {
  return path.join(process.cwd(), "playwright", ".auth", `${role}.json`);
}

export const test = base;
export { expect } from "@playwright/test";
