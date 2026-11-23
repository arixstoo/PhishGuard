/**
 * Images des stores (étape 6.9) : `npm run store:assets`, hors des tests de la CI.
 * Mêmes fixtures que les parcours de bout en bout (`e2e/fixtures.ts`).
 */

import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: ".",
  testMatch: "capture.spec.ts",
  workers: 1,
  fullyParallel: false,
  retries: 0,
  timeout: 120_000,
  expect: { timeout: 10_000 },
  reporter: "list",
  outputDir: "../test-results/store",
});
