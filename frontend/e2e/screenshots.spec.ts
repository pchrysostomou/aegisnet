import path from "node:path";

import { expect, test } from "./fixtures";

/**
 * The screenshots `docs/delivery-plan.md` M4 asks be committed.
 *
 * Run deliberately (`pnpm e2e:shots`) rather than as part of the smoke suite, because it
 * writes into the repository. Everything in them is the synthetic multi-stage scenario
 * (ADR-025) and accounts on `.test` domains — there is nothing here that is not already
 * committed as data.
 */
const SHOTS = path.join(process.cwd(), "..", "docs", "screenshots");

test.use({ viewport: { width: 1280, height: 900 } });

test("queue", async ({ page }) => {
  await page.goto("/incidents");
  await expect(page.getByRole("heading", { level: 2, name: "Incidents" })).toBeVisible();
  await page.screenshot({ path: path.join(SHOTS, "incident-queue.png"), fullPage: true });
});

test("case", async ({ page }) => {
  await page.goto("/incidents");
  await page.getByRole("link", { name: /AEG-2026-0001/ }).first().click();
  await expect(page.getByRole("heading", { level: 3, name: "Timeline" })).toBeVisible();
  await page.screenshot({ path: path.join(SHOTS, "incident-case.png"), fullPage: true });
});

test("assets", async ({ page }) => {
  await page.goto("/assets");
  await expect(page.getByRole("heading", { level: 2, name: "Assets" })).toBeVisible();
  await page.screenshot({ path: path.join(SHOTS, "assets.png"), fullPage: true });
});
