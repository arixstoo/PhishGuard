/**
 * Vecteurs de référence communs (`tests/golden/url_vectors.json`, étape 4.11).
 *
 * 200 URLs avec les features **et** les scores calculés par Python : l'extension doit
 * les retrouver à `tolerance` (1e-6) près. Critère de fin de l'étape 5.3.
 *
 * Le modèle exporté (`models/url_v2.json`) n'est pas versionné. Sans lui (CI), on vérifie
 * les 24 features qui ne dépendent pas du modèle ; avec lui (poste de développement,
 * build), tout : `tld_phish_rate`, score brut, probabilité et probabilité calibrée. Le
 * modèle n'est utilisé que si son empreinte est celle dont viennent les vecteurs.
 */

import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { decide, UrlAnalyzer } from "../src/core/analyze";
import { FEATURE_EXTRACTOR_VERSION, REFERENCE_DATA_SHA256, UrlFeatureExtractor } from "../src/core/features";
import { calibrate, featureVector, loadUrlModel, predictProbability, predictRaw } from "../src/core/model";
import { expectFeatures, pick } from "./helpers";

const root = new URL("../../", import.meta.url);
const golden = JSON.parse(readFileSync(new URL("tests/golden/url_vectors.json", root), "utf-8")) as {
  tolerance: number;
  model_version: string;
  model_export_sha256: string;
  feature_extractor: { version: string; reference_data_sha256: string };
  feature_names: string[];
  vectors: {
    url: string;
    features: Record<string, number>;
    raw_score: number;
    probability: number;
    calibrated_probability: number;
  }[];
};

const modelPath = new URL(`models/${golden.model_version}.json`, root);
const modelBytes = existsSync(modelPath) ? readFileSync(modelPath) : null;
const modelMatches =
  modelBytes !== null &&
  createHash("sha256").update(modelBytes).digest("hex") === golden.model_export_sha256;

const withoutTld = (features: Record<string, number>) =>
  Object.fromEntries(Object.entries(features).filter(([name]) => name !== "tld_phish_rate"));

describe("vecteurs de référence", () => {
  it("viennent du même extracteur que l'extension", () => {
    expect(golden.feature_extractor.version).toBe(FEATURE_EXTRACTOR_VERSION);
    expect(golden.feature_extractor.reference_data_sha256).toBe(REFERENCE_DATA_SHA256);
    expect(golden.vectors).toHaveLength(200);
  });

  it("donnent les mêmes features (hors table des TLD, propre au modèle)", () => {
    const extractor = new UrlFeatureExtractor();
    for (const vector of golden.vectors) {
      const label = JSON.stringify(vector.url);
      const expected = withoutTld(vector.features);
      const actual = extractor.extract(vector.url);
      expectFeatures(pick(actual, expected), expected, label);
    }
  });

  it.runIf(modelMatches)("donnent les mêmes features et scores avec le modèle exporté", () => {
    const model = loadUrlModel(JSON.parse(modelBytes!.toString("utf-8")));
    expect(model.featureNames).toEqual(golden.feature_names);
    const extractor = new UrlFeatureExtractor({ tldTable: model.tldTable });
    const analyzer = new UrlAnalyzer(model);
    const tolerance = golden.tolerance;
    for (const vector of golden.vectors) {
      const label = JSON.stringify(vector.url);
      const features = extractor.extract(vector.url);
      expectFeatures(pick(features, vector.features), vector.features, label);
      const x = featureVector(model, features);
      expect(Math.abs(predictRaw(model, x) - vector.raw_score), `${label} raw`).toBeLessThanOrEqual(tolerance);
      const probability = predictProbability(model, x);
      expect(Math.abs(probability - vector.probability), `${label} p`).toBeLessThanOrEqual(tolerance);
      expect(
        Math.abs(calibrate(model, probability) - vector.calibrated_probability),
        `${label} calibrée`,
      ).toBeLessThanOrEqual(tolerance);
      // Bout à bout : l'analyseur donne la même probabilité que la référence.
      const local = analyzer.score(vector.url);
      expect(Math.abs(local.probability - vector.calibrated_probability)).toBeLessThanOrEqual(tolerance);
      expect(decide(local).score).toBeGreaterThanOrEqual(0);
    }
  });

  it.skipIf(modelMatches)("modèle exporté absent ou différent : scores non vérifiés ici", () => {
    // Visible dans le rapport : `make export` puis relancer pour la vérification complète.
    expect(modelMatches).toBe(false);
  });
});
