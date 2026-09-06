import type { Page } from "@playwright/test";

import { expect, test } from "./fixtures";

/**
 * The brief panel and the Markdown export, against a running stack with the analyst's stored
 * session (see playwright.config.ts). Nothing here is mocked and nothing leaves the machine:
 * the stack has no Perplexity key, so asking for a brief serves the committed offline sample —
 * which is exactly the path a reviewer's checkout takes, and therefore the one worth proving.
 */

async function openACase(page: Page) {
  await page.goto("/incidents");
  await page.getByRole("link", { name: /AEG-/ }).first().click();
  await expect(page.getByRole("heading", { level: 3, name: "Investigation brief" })).toBeVisible();
  return new URL(page.url()).pathname.split("/").pop() ?? "";
}

test("asking for a brief stores one and shows it as the sample it is", async ({ page }) => {
  await openACase(page);

  await page.getByRole("button", { name: /Generate/ }).click();
  await expect(page.getByText(/offline sample/).first()).toBeVisible();

  // ADR-031: nothing may present the committed fixture as something a model said.
  await expect(
    page.getByText(/committed to this repository, not something a model wrote/),
  ).toBeVisible();
  await expect(page.getByRole("heading", { level: 4, name: "What it says" })).toBeVisible();
  await expect(
    page.getByRole("heading", { level: 4, name: "What a person could do next" }),
  ).toBeVisible();
  await expect(page.getByText(/not things to do to a system/)).toBeVisible();
});

test("a brief's sources are https links this app set the terms for", async ({ page }) => {
  await openACase(page);
  if ((await page.getByRole("heading", { level: 4, name: "Sources" }).count()) === 0) {
    await page.getByRole("button", { name: /Generate/ }).click();
  }
  await expect(page.getByRole("heading", { level: 4, name: "Sources" })).toBeVisible();

  const links = page.locator("ol.citations a");
  expect(await links.count()).toBeGreaterThan(0);
  for (const link of await links.all()) {
    expect(await link.getAttribute("href")).toMatch(/^https:\/\//);
    expect(await link.getAttribute("rel")).toBe("noopener noreferrer nofollow");
    expect(await link.getAttribute("target")).toBe("_blank");
  }
});

test("the brief appended to the case and changed nothing about it", async ({ page }) => {
  const id = await openACase(page);
  const severity = await page.locator(".case-head .badges").first().innerText();

  await page.getByRole("button", { name: /Generate/ }).click();
  await expect(page.getByText(/offline sample/).first()).toBeVisible();

  await page.reload();
  expect(await page.locator(".case-head .badges").first().innerText()).toBe(severity);
  await expect(page.locator("li.entry-brief_generated").first()).toBeVisible();
  expect(new URL(page.url()).pathname).toContain(id);
});

test("the case downloads as Markdown, and twice gives the same bytes", async ({ page }) => {
  const id = await openACase(page);
  const link = page.getByRole("link", { name: "Download the case as Markdown" });
  await expect(link).toBeVisible();

  // Same-origin on purpose: the browser must never learn the API's address (ADR-026).
  expect(await link.getAttribute("href")).toBe(`/incidents/${id}/report.md`);

  const first = await page.request.get(`/incidents/${id}/report.md`);
  const second = await page.request.get(`/incidents/${id}/report.md`);
  expect(first.status()).toBe(200);
  expect(first.headers()["content-type"]).toContain("text/markdown");
  expect(first.headers()["content-disposition"]).toContain(`incident-${id}.md`);

  const body = await first.text();
  expect(await second.text()).toBe(body);
  expect(body).toContain("**It is not redacted.**");
  expect(body).toMatch(/^# AEG/);
});

test("nothing in a brief or a report can run in the browser", async ({ page }) => {
  const dialogs: string[] = [];
  page.on("dialog", async (dialog) => {
    dialogs.push(dialog.message());
    await dialog.dismiss();
  });

  await openACase(page);
  if ((await page.getByRole("heading", { level: 4, name: "Sources" }).count()) === 0) {
    await page.getByRole("button", { name: /Generate/ }).click();
    await expect(page.getByText(/offline sample/).first()).toBeVisible();
  }

  // Nothing in the panel may become an element that acts: no script, no image, no iframe.
  const brief = page.locator("div.brief");
  expect(await brief.locator("script, iframe, object, embed, img, svg").count()).toBe(0);
  expect(dialogs).toEqual([]);
});
