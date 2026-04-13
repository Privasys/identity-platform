import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: ".",
  timeout: 30_000,
  retries: 0,
  reporter: [["html", { open: "never" }], ["line"]],
  use: {
    baseURL: process.env.IDP_BASE_URL ?? "https://privasys.id",
    ignoreHTTPSErrors: true,
    screenshot: "only-on-failure",
    trace: "retain-on-failure",
  },
  projects: [
    {
      name: "authorize-page",
      testMatch: "authorize.spec.ts",
      use: { browserName: "chromium" },
    },
  ],
});
