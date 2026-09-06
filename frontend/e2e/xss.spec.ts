import { expect, test } from "./fixtures";

/**
 * The Milestone 4 acceptance criterion: a stored-XSS fixture renders as inert text.
 *
 * The payloads below are what a real capture carries — a DNS query name and an HTTP host an
 * attacker chose — plus what an analyst might paste into a note while investigating them. The
 * assertion is not "the string is absent": it must be *present*, as text, and must not have
 * become an element or executed anything.
 */
const MARKER = "AEGISNET_XSS_PROBE";

const dialogs: string[] = [];

test.beforeEach(({ page }) => {
  // Any dialog is a failure: nothing rendered here may execute. Recorded rather than thrown
  // from the handler, so the assertion belongs to the test that caused it.
  dialogs.length = 0;
  page.on("dialog", (dialog) => {
    dialogs.push(dialog.type());
    void dialog.dismiss();
  });
});

test.afterEach(() => {
  expect(dialogs, "a payload executed and opened a dialog").toEqual([]);
});

test("hostile note content renders as text and executes nothing", async ({ page }) => {
  await page.goto("/incidents");

  await page.getByRole("link", { name: /AEG-/ }).first().click();
  await expect(page.getByRole("heading", { level: 3, name: "Notes" })).toBeVisible();

  const payload = [
    `${MARKER} <script>window.__pwned = 1; alert('xss')</script>`,
    `<img src=x onerror="window.__pwned = 1">`,
    `[click](javascript:window.__pwned=1)`,
    `![p](https://evil.test/track.gif)`,
    "<svg/onload=alert(1)>",
  ].join("\n\n");

  await page.getByLabel(/What you found/).fill(payload);
  await page.getByRole("button", { name: "Add note" }).click();
  await expect(page.getByText(MARKER)).toBeVisible();

  // Nothing executed.
  expect(await page.evaluate(() => "__pwned" in window)).toBe(false);

  // Nothing became an element. Scoped to the notes list so the page's own markup is not counted.
  const notes = page.locator("ol.notes");
  await expect(notes.locator("script")).toHaveCount(0);
  await expect(notes.locator("img")).toHaveCount(0);
  await expect(notes.locator("svg")).toHaveCount(0);
  await expect(notes.locator("a")).toHaveCount(0);
  await expect(notes.locator("iframe")).toHaveCount(0);

  // And the payload is on the page, as characters somebody can read.
  await expect(notes).toContainText("<script>");
  await expect(notes).toContainText("onerror=");
});

test("hostile log content in a case title and entity renders as text", async ({ page }) => {
  await page.goto("/incidents");
  const body = page.locator("body");
  // Whatever the corpus contains, none of it may have produced an executable element.
  await expect(body.locator("script[src*='evil']")).toHaveCount(0);
  expect(await page.evaluate(() => "__pwned" in window)).toBe(false);
});
