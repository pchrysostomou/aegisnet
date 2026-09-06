import { expect, test } from "./fixtures";

/** Run with the analyst's stored session (see playwright.config.ts). */

test("an analyst is offered the workflow controls", async ({ page }) => {
  await page.goto("/incidents");
  await page.getByRole("link", { name: /AEG-/ }).first().click();
  await expect(page.getByRole("heading", { name: "Move this case" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Write a note" })).toBeVisible();
});

test("an analyst is not offered the audit section", async ({ page }) => {
  await page.goto("/incidents");
  await expect(page.getByRole("link", { name: "Audit" })).toHaveCount(0);
  await expect(page.getByRole("link", { name: "Assets" })).toBeVisible();
});

test("the queue lists the cases correlation opened", async ({ page }) => {
  await page.goto("/incidents");
  await expect(page.getByRole("heading", { level: 2, name: "Incidents" })).toBeVisible();
  await expect(page.getByRole("link", { name: /AEG-/ }).first()).toBeVisible();
});

test("the asset inventory renders", async ({ page }) => {
  await page.goto("/assets");
  await expect(page.getByRole("heading", { level: 2, name: "Assets" })).toBeVisible();
});
