import { test as setup } from "@playwright/test";

import { VIEWER, signIn, statePath } from "./fixtures";

setup("authenticate as viewer", async ({ page }) => {
  await signIn(page, VIEWER);
  await page.context().storageState({ path: statePath("viewer") });
});
