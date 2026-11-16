import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    include: ["test/**/*.test.ts"],
    // Les vecteurs de référence (200 URLs) et le corpus de fuzzing tiennent en quelques
    // secondes ; le délai par défaut suffit, sauf pour le chargement du vrai modèle.
    testTimeout: 30_000,
  },
});
