/**
 * Tests de bout en bout de l'extension (étape 5.10) : `npm run test:e2e`.
 *
 * Construit d'abord `dist-test/` avec le modèle de test (`node build.mjs --test --stub-model`),
 * ou avec le vrai modèle signé (`node build.mjs --test`) : les verdicts attendus sont les
 * mêmes. Chromium de Playwright : `npx playwright install chromium`.
 */

import { defineConfig } from "@playwright/test";

const ci = Boolean(process.env["CI"]);

export default defineConfig({
  testDir: "e2e",
  // Un Chromium par worker, état de l'extension partagé entre les tests d'un fichier.
  workers: 1,
  fullyParallel: false,
  forbidOnly: ci,
  // Pas de nouvel essai : un test instable doit se voir, pas se cacher.
  retries: 0,
  timeout: 30_000,
  expect: { timeout: 5_000 },
  reporter: ci ? [["github"], ["list"]] : "list",
  use: { trace: "retain-on-failure" },
  outputDir: "test-results",
});
