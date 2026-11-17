/**
 * Le modèle de test des parcours Playwright (`e2e/stub-model.mjs`, étape 5.10) passe le
 * chargement défensif et donne les verdicts du vrai modèle sur les URLs des parcours.
 * S'il dérivait, les tests de bout en bout vérifieraient autre chose qu'en production.
 */

import { describe, expect, it } from "vitest";
import { SITES } from "../e2e/cases";
import { STUB_MODEL_VERSION, stubModel } from "../e2e/stub-model.mjs";
import { decide, UrlAnalyzer } from "../src/core/analyze";
import { loadUrlModel } from "../src/core/model";
import reference from "../src/generated/reference-data.json";

describe("modèle de test des parcours", () => {
  const model = loadUrlModel(stubModel(reference.feature_extractor));
  const analyzer = new UrlAnalyzer(model);

  it("passe le chargement défensif, comme un modèle téléchargé", () => {
    expect(model.modelVersion).toBe(STUB_MODEL_VERSION);
  });

  it.each(SITES)("$url → $verdict, comme url_v2", ({ url, verdict }) => {
    expect(decide(analyzer.score(url)).verdict).toBe(verdict);
  });
});
