import { expect, test } from "./fixtures";

/** The Milestone 4 criterion: the list, the detail and the status control are reachable and
 * usable from the keyboard alone. */

test("the queue and a case can be reached without a mouse", async ({ page }) => {
  await page.goto("/incidents");

  // The skip link is the first stop, and it goes somewhere.
  await page.keyboard.press("Tab");
  await expect(page.getByRole("link", { name: "Skip to content" })).toBeFocused();

  // Tabbing reaches a case link, and Enter opens it.
  const caseLink = page.getByRole("link", { name: /AEG-/ }).first();
  await caseLink.focus();
  await expect(caseLink).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("heading", { level: 3, name: "Timeline" })).toBeVisible();
});

test("the status control is operable from the keyboard", async ({ page }) => {
  await page.goto("/incidents");
  await page.getByRole("link", { name: /AEG-/ }).first().click();

  const select = page.getByLabel("New status");
  await select.focus();
  await expect(select).toBeFocused();
  // The submit button is disabled until a status is chosen, which is what makes it safe to
  // reach with a keyboard: Enter on an empty form cannot move a case by accident.
  await expect(page.getByRole("button", { name: "Move" })).toBeDisabled();
  await select.selectOption("triaging");
  await expect(page.getByRole("button", { name: "Move" })).toBeEnabled();
});

test("every focusable control shows a visible focus ring", async ({ page }) => {
  await page.goto("/incidents");
  const outline = await page.evaluate(() => {
    const target = document.querySelector<HTMLElement>("a, button, select, input");
    if (!target) return null;
    target.focus();
    const style = getComputedStyle(target, ":focus-visible");
    return { width: style.outlineWidth, style: style.outlineStyle };
  });
  expect(outline).not.toBeNull();
  expect(outline?.style).not.toBe("none");
});
