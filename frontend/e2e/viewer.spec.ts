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

test("a viewer is not offered the audit section", async ({ page }) => {
  await page.goto("/incidents");
  await expect(page.getByRole("link", { name: "Audit" })).toHaveCount(0);
  await expect(page.getByRole("link", { name: "Assets" })).toBeVisible();
});
