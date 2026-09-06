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

/* This asserted nothing at all until Chunk 33. It called
 * `getComputedStyle(target, ":focus-visible")` — but `:focus-visible` is a pseudo-*class*, not a
 * pseudo-element, so CSSOM resolves the second argument to nothing and hands back an empty
 * declaration: `{width: "", style: ""}`, length 0. `"" !== "none"` passes, and it passed
 * identically with the whole focus-ring block deleted from `globals.css`. Measured in this
 * repository's own Chromium, both ways round.
 *
 * Two changes. It reads the element's *own* computed style, which is where the
 * `a|button|input|select:focus-visible` rule in `globals.css` has actually applied. And it
 * arrives by pressing Tab rather than calling `.focus()`, because `:focus-visible` is a
 * heuristic about how focus was acquired — a keyboard press is the case the rule exists for,
 * and it is also the case `docs/STATUS.md` E-68 claims to have checked. */
test("every control reached by Tab shows a visible focus ring", async ({ page }) => {
  await page.goto("/incidents");
  await page.locator("body").click(); // start from a known place, without focusing a control

  const rings: { tag: string; outlineStyle: string; outlineWidth: number }[] = [];
  for (let press = 0; press < 10; press += 1) {
    await page.keyboard.press("Tab");
    const ring = await page.evaluate(() => {
      const el = document.activeElement as HTMLElement | null;
      if (!el || el === document.body) return null;
      const style = getComputedStyle(el);
      return {
        tag: el.tagName.toLowerCase(),
        outlineStyle: style.outlineStyle,
        outlineWidth: Number.parseFloat(style.outlineWidth) || 0,
      };
    });
    if (ring) rings.push(ring);
  }

  expect(rings.length, "Tab reached no focusable control").toBeGreaterThan(2);
  for (const ring of rings) {
    expect(ring.outlineStyle, `<${ring.tag}> focused by Tab has outline-style none`).not.toBe(
      "none",
    );
    expect(ring.outlineWidth, `<${ring.tag}> outline is ${ring.outlineWidth}px`).toBeGreaterThan(1);
  }
});
