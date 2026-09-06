import { test as setup } from "@playwright/test";

import { ANALYST, signIn, statePath } from "./fixtures";

/**
 * Sign in once and keep the session.
 *
 * One file per role, not one file with two tests: the API allows five logins per account per
 * fifteen minutes and fails *closed* on that path (ADR-016), so a run must sign in only as the
 * role it is about. A suite that signed in more would be testing the rate limiter.
 */
setup("authenticate as analyst", async ({ page }) => {
  await signIn(page, ANALYST);
  await page.context().storageState({ path: statePath("analyst") });
});
