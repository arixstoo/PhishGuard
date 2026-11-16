/**
 * Chargement défensif et inférence du modèle exporté.
 *
 * Les modèles synthétiques (`python-parity.json`) sont de vrais LightGBM entraînés avec
 * des valeurs manquantes (`NaN`, et `zero_as_missing`) : ils exercent les branches que
 * les features d'URL n'atteignent jamais, en CI, sans le modèle de production.
 */

import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { calibrate, interp, loadUrlModel, ModelError, predictProbability, predictRaw } from "../src/core/model";

const parity = JSON.parse(
  readFileSync(new URL("./fixtures/python-parity.json", import.meta.url), "utf-8"),
) as {
  interp: { xp: number[]; fp: number[]; x: number; output: number }[];
  synthetic_models: {
    model: Record<string, unknown>;
    vectors: { x: (number | null)[]; raw_score: number; probability: number; calibrated_probability: number }[];
  }[];
};

const clone = <T>(value: T): T => structuredClone(value);
const base = parity.synthetic_models[0]!.model;

describe("inférence", () => {
  it.each(parity.synthetic_models.map((c, i) => [i, c] as const))(
    "modèle synthétique %i : mêmes scores que Python, valeurs manquantes comprises",
    (_, c) => {
      const model = loadUrlModel(c.model);
      for (const vector of c.vectors) {
        const x = vector.x.map((v) => (v === null ? Number.NaN : v));
        expect(Math.abs(predictRaw(model, x) - vector.raw_score)).toBeLessThanOrEqual(1e-12);
        const p = predictProbability(model, x);
        expect(Math.abs(p - vector.probability)).toBeLessThanOrEqual(1e-12);
        expect(Math.abs(calibrate(model, p) - vector.calibrated_probability)).toBeLessThanOrEqual(1e-12);
      }
    },
  );

  it.each(parity.interp)("numpy.interp($x)", ({ xp, fp, x, output }) => {
    expect(interp(x, Float64Array.from(xp), Float64Array.from(fp))).toBe(output);
  });

  it("refuse un vecteur de mauvaise taille", () => {
    expect(() => predictRaw(loadUrlModel(base), [1, 2])).toThrow(ModelError);
  });
});

describe("chargement défensif", () => {
  const mutate = (change: (m: Record<string, any>) => void) => {
    const m = clone(base) as Record<string, any>;
    change(m);
    return () => loadUrlModel(m);
  };

  it("accepte le modèle tel qu'exporté", () => {
    expect(loadUrlModel(base).trees.roots.length).toBe(25);
  });

  it.each([
    ["format inconnu", (m: Record<string, any>) => (m["format"] = "onnx")],
    ["autre extracteur", (m: Record<string, any>) => (m["feature_extractor"]["version"] = "9.9.9")],
    ["autres listes de référence", (m: Record<string, any>) => (m["feature_extractor"]["reference_data_sha256"] = "0".repeat(64))],
    ["feature inconnue", (m: Record<string, any>) => (m["feature_names"][0] = "evil")],
    ["colonnes du booster dans un autre ordre", (m: Record<string, any>) => m["booster"]["feature_names"].reverse()],
    ["multiclasse", (m: Record<string, any>) => (m["booster"]["num_class"] = 3)],
    ["coupure catégorielle", (m: Record<string, any>) => (m["booster"]["tree_info"][0]["tree_structure"]["decision_type"] = "==")],
    ["feature hors limites", (m: Record<string, any>) => (m["booster"]["tree_info"][0]["tree_structure"]["split_feature"] = 99)],
    ["missing_type inconnu", (m: Record<string, any>) => (m["booster"]["tree_info"][0]["tree_structure"]["missing_type"] = "__proto__")],
    ["feuille non numérique", (m: Record<string, any>) => (m["booster"]["tree_info"][0]["tree_structure"] = { leaf_value: "1" })],
    ["nœud manquant", (m: Record<string, any>) => (m["booster"]["tree_info"][0]["tree_structure"]["left_child"] = null)],
    ["aucun arbre", (m: Record<string, any>) => (m["booster"]["tree_info"] = [])],
    ["calibration décroissante", (m: Record<string, any>) => m["calibration"]["y"].reverse()],
    ["règle de décision inconnue", (m: Record<string, any>) => (m["decision_rule"] = "score >= threshold")],
    ["sigmoïde non finie", (m: Record<string, any>) => (m["objective"]["sigmoid"] = null)],
  ])("refuse : %s", (_, change) => {
    expect(mutate(change)).toThrow(ModelError);
  });

  it("refuse tld_phish_rate sans table", () => {
    const m = clone(base) as Record<string, any>;
    m["feature_names"][0] = "tld_phish_rate";
    m["booster"]["feature_names"][0] = "tld_phish_rate";
    m["tld_table"] = null;
    expect(() => loadUrlModel(m)).toThrow(ModelError);
  });

  it("refuse un arbre démesuré sans épuiser la pile", () => {
    const m = clone(base) as Record<string, any>;
    let node: Record<string, unknown> = { leaf_value: 0 };
    for (let i = 0; i < 100_000; i++) {
      node = {
        split_feature: 0,
        threshold: 0,
        decision_type: "<=",
        default_left: true,
        missing_type: "None",
        left_child: node,
        right_child: { leaf_value: 1 },
      };
    }
    m["booster"]["tree_info"] = [{ tree_structure: node }];
    // Profondeur 100 000 : compilé sans récursion, puis évalué.
    const model = loadUrlModel(m);
    expect(predictRaw(model, [1, 0, 0, 0, 0, 0])).toBe(1);
    expect(predictRaw(model, [-1, 0, 0, 0, 0, 0])).toBe(0);
  });
});
