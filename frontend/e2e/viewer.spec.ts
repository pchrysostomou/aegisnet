import { VIEWER, expect, test } from "./fixtures";

/** Run with the viewer's stored session (see playwright.config.ts). The Milestone 4 criterion:
 * a viewer sees no mutation control, and a forged request is refused by the API regardless of
 * what the page drew. */

test("a viewer reads a case and is offered nothing to change", async ({ page }) => {
  await page.goto("/incidents");
  await page.getByRole("link", { name: /AEG-/ }).first().click();
  await expect(page.getByRole("heading", { level: 3, name: "Alerts in this case" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Move this case" })).toHaveCount(0);
  await expect(page.getByRole("heading", { name: "Write a note" })).toHaveCount(0);
  await expect(page.getByText(/read-only for this role/)).toBeVisible();
});

test("a viewer forging the request is refused by the API", async ({ page, request }) => {
  await page.goto("/incidents");
  await page.getByRole("link", { name: /AEG-/ }).first().click();
  const id = new URL(page.url()).pathname.split("/").pop() ?? "";

  // Straight at the API, with the viewer's own credentials, bypassing the page entirely.
  const api = process.env.AEGISNET_API_PUBLIC_URL ?? "http://localhost:8000";
  const login = await request.post(`${api}/api/v1/auth/login`, {
    data: { email: VIEWER.email, password: VIEWER.password },
  });
  const body: unknown = await login.json();
  const token =
    typeof body === "object" && body !== null && "access_token" in body
      ? String((body).access_token)
      : "";
  expect(token).not.toBe("");

  for (const [path, payload] of [
    [`/api/v1/incidents/${id}/status`, { status: "triaging" }],
    [`/api/v1/incidents/${id}/notes`, { body: "forged" }],
  ] as const) {
    const response = await request.post(`${api}${path}`, {
      data: payload,
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(response.status(), path).toBe(403);
  }
});

test("a viewer reads a brief and cannot ask for one", async ({ page }) => {
  // `briefs.read` is a viewer permission and `briefs.generate` is not: a brief is a narrative
  // about alerts a viewer may already read, and asking for one spends a budget and sends an
  // evidence packet outward (ADR-031).
  await page.goto("/incidents");
  await page.getByRole("link", { name: /AEG-/ }).first().click();
  await expect(page.getByRole("heading", { level: 3, name: "Investigation brief" })).toBeVisible();
  await expect(page.getByRole("heading", { name: /Ask for a brief|Ask again/ })).toHaveCount(0);
  await expect(page.getByRole("button", { name: /Generate/ })).toHaveCount(0);
});

test("a viewer may export the case, because the document holds nothing new to them", async ({
  page,
}) => {
  await page.goto("/incidents");
  await page.getByRole("link", { name: /AEG-/ }).first().click();
  // Wait for the case to be on screen before reading its id: reading the URL straight after a
  // click can catch the list page and ask for /incidents/incidents/report.md.
  await expect(page.getByRole("heading", { level: 3, name: "Investigation brief" })).toBeVisible();
  const id = new URL(page.url()).pathname.split("/").pop() ?? "";

  await expect(page.getByRole("link", { name: "Download the case as Markdown" })).toBeVisible();
  const exported = await page.request.get(`/incidents/${id}/report.md`);
  expect(exported.status()).toBe(200);
  expect(await exported.text()).toMatch(/^# AEG/);
});

test("a viewer is not offered the audit section", async ({ page }) => {
  await page.goto("/incidents");
  await expect(page.getByRole("link", { name: "Audit" })).toHaveCount(0);
  await expect(page.getByRole("link", { name: "Assets" })).toBeVisible();
});
