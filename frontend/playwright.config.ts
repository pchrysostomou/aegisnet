import { defineConfig, devices } from "@playwright/test";

/**
 * Smoke tests against a **running stack**: `make up` (api, db, redis, worker, web).
 *
 * These do not mock the API. The point of them is the part the unit tests cannot reach — that
 * a real browser, given real data the pipeline produced, renders hostile log content as inert
 * text and draws no control a role may not use.
 */
const BASE_URL = process.env.AEGISNET_WEB_URL ?? "http://localhost:3000";

export default defineConfig({
  testDir: "./e2e",
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  reporter: process.env.CI ? [["list"], ["github"]] : [["list"]],
  use: {
    baseURL: BASE_URL,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  projects: [
    { name: "setup:analyst", testMatch: /auth\.analyst\.setup\.ts/ },
    { name: "setup:viewer", testMatch: /auth\.viewer\.setup\.ts/ },
    {
      name: "analyst",
      testMatch: /\.(spec)\.ts/,
      testIgnore: /(viewer\.spec|screenshots\.spec|\.setup)\./,
      dependencies: ["setup:analyst"],
      use: {
        ...devices["Desktop Chrome"],
        storageState: "playwright/.auth/analyst.json",
      },
    },
    {
      name: "shots",
      testMatch: /screenshots\.spec\.ts/,
      dependencies: ["setup:analyst"],
      use: { ...devices["Desktop Chrome"], storageState: "playwright/.auth/analyst.json" },
    },
    {
      name: "viewer",
      testMatch: /viewer\.spec\.ts/,
      dependencies: ["setup:viewer"],
      use: {
        ...devices["Desktop Chrome"],
        storageState: "playwright/.auth/viewer.json",
      },
    },
  ],
});
