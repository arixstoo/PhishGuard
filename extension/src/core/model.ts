/**
 * Modèle URL exporté (`phishguard.urls.export`, étape 4.11) : chargement et inférence.
 *
 * Le fichier est du JSON pur, sans code. Il est pourtant traité comme une **entrée non
 * fiable** : il sera téléchargé au module 6, et un modèle malformé ne doit ni planter
 * l'extension ni produire un score faux. {@link loadUrlModel} vérifie donc tout ce que
 * l'inférence lit (format, extracteur, ordre des colonnes, chaque nœud de chaque arbre,
 * calibration) avant de compiler les arbres en tableaux typés.
 *
 * L'inférence reprend à l'identique `predict_raw` (référence Python, elle-même vérifiée
 * contre LightGBM) : `Tree::NumericalDecision`, valeurs manquantes comprises.
 */

import { FEATURE_EXTRACTOR_VERSION, FEATURE_NAMES, REFERENCE_DATA_SHA256, type TldTable } from "./features";
import { NORMALIZATION_VERSION } from "./normalize";

export const EXPORT_FORMAT = "phishguard-url-lightgbm";
export const EXPORT_FORMAT_VERSION = 1;
/** Seuil sous lequel LightGBM considère une valeur comme nulle (`kZeroThreshold`). */
const ZERO_THRESHOLD = 1e-35;
/** Garde-fou contre un fichier démesuré : `url_v2` compte ≈ 19 000 nœuds. */
const MAX_NODES = 2_000_000;

const Missing = { None: 0, Zero: 1, NaN: 2 } as const;
const MISSING_TYPES: Readonly<Record<string, number>> = Missing;

export class ModelError extends Error {
  override name = "ModelError";
}

export type Calibration =
  | { method: "isotonic"; x: Float64Array; y: Float64Array }
  | { method: "sigmoid"; a: number; b: number }
  | null;

/**
 * Arbres compilés : un nœud interne `i` a ses enfants en `left[i]` et `right[i]` ; un
 * enfant négatif `-1 - k` désigne la feuille `k` (`leafValue[k]`).
 */
interface CompiledTrees {
  roots: Int32Array;
  feature: Int32Array;
  threshold: Float64Array;
  missing: Uint8Array;
  defaultLeft: Uint8Array;
  left: Int32Array;
  right: Int32Array;
  leafValue: Float64Array;
}

export interface UrlModel {
  modelVersion: string;
  trainedAt: string | null;
  featureNames: readonly string[];
  sigmoid: number;
  thresholds: Readonly<Record<string, number>>;
  tldTable: TldTable | null;
  calibration: Calibration;
  trees: CompiledTrees;
}

// --------------------------------------------------------------------------- //
// Validation
// --------------------------------------------------------------------------- //

type Json = Record<string, unknown>;

const isObject = (value: unknown): value is Json =>
  typeof value === "object" && value !== null && !Array.isArray(value);
const isFiniteNumber = (value: unknown): value is number =>
  typeof value === "number" && Number.isFinite(value);

function object(value: unknown, what: string): Json {
  if (!isObject(value)) throw new ModelError(`${what} : objet attendu`);
  return value;
}

function finite(value: unknown, what: string): number {
  if (!isFiniteNumber(value)) throw new ModelError(`${what} : nombre fini attendu`);
  return value;
}

function numberArray(value: unknown, what: string): Float64Array {
  if (!Array.isArray(value) || !value.every(isFiniteNumber)) {
    throw new ModelError(`${what} : liste de nombres finis attendue`);
  }
  return Float64Array.from(value);
}

const nonDecreasing = (values: Float64Array) => values.every((v, i) => i === 0 || v >= values[i - 1]!);

function parseCalibration(value: unknown): Calibration {
  if (value === null || value === undefined) return null;
  const calibration = object(value, "calibration");
  if (calibration["format_version"] !== 1) throw new ModelError("calibration : format inconnu");
  if (calibration["method"] === "isotonic") {
    const x = numberArray(calibration["x"], "calibration.x");
    const y = numberArray(calibration["y"], "calibration.y");
    if (x.length < 2 || x.length !== y.length || !nonDecreasing(x) || !nonDecreasing(y)) {
      throw new ModelError("calibration isotone : points (x, y) croissants attendus");
    }
    return { method: "isotonic", x, y };
  }
  if (calibration["method"] === "sigmoid") {
    const params = object(calibration["params"], "calibration.params");
    const a = finite(params["a"], "calibration.params.a");
    if (a < 0) throw new ModelError("calibration sigmoïde : a ≥ 0 attendu");
    return { method: "sigmoid", a, b: finite(params["b"], "calibration.params.b") };
  }
  throw new ModelError("calibration : méthode inconnue");
}

function parseTldTable(value: unknown): TldTable {
  const table = object(value, "tld_table");
  const prior = finite(table["prior"], "tld_table.prior");
  const rates = object(table["rates"], "tld_table.rates");
  const out: Record<string, number> = Object.create(null);
  for (const [tld, rate] of Object.entries(rates)) out[tld] = finite(rate, `tld_table.rates.${tld}`);
  return { prior, rates: out };
}

function compileTrees(treeInfo: unknown, featureCount: number): CompiledTrees {
  if (!Array.isArray(treeInfo) || treeInfo.length === 0) {
    throw new ModelError("booster.tree_info : au moins un arbre attendu");
  }
  const feature: number[] = [];
  const threshold: number[] = [];
  const missing: number[] = [];
  const defaultLeft: number[] = [];
  const left: number[] = [];
  const right: number[] = [];
  const leafValue: number[] = [];
  const roots: number[] = [];
  let nodes = 0;

  // Parcours itératif (un arbre très profond ne doit pas épuiser la pile). Chaque tâche
  // porte le nœud à compiler et l'endroit où ranger sa référence : racine, ou enfant
  // gauche / droit de son parent.
  const ROOT = 0;
  const LEFT = 1;
  const RIGHT = 2;
  const compile = (root: unknown): number => {
    let rootRef = 0;
    const stack: [unknown, number, number][] = [[root, -1, ROOT]];
    while (stack.length) {
      const [raw, parent, side] = stack.pop()!;
      if (++nodes > MAX_NODES) throw new ModelError("modèle démesuré");
      const node = object(raw, "nœud");
      let ref: number;
      if ("leaf_value" in node) {
        leafValue.push(finite(node["leaf_value"], "leaf_value"));
        ref = -leafValue.length; // feuille k codée -1 - k
      } else {
        const f = node["split_feature"];
        if (typeof f !== "number" || !Number.isInteger(f) || f < 0 || f >= featureCount) {
          throw new ModelError("split_feature hors des colonnes du modèle");
        }
        if (node["decision_type"] !== "<=") {
          throw new ModelError("seules les coupures numériques « <= » sont prises en charge");
        }
        const missingName = String(node["missing_type"]);
        if (!Object.hasOwn(MISSING_TYPES, missingName)) throw new ModelError("missing_type inconnu");
        if (typeof node["default_left"] !== "boolean") {
          throw new ModelError("default_left booléen attendu");
        }
        const t = node["threshold"];
        if (typeof t !== "number" || Number.isNaN(t)) throw new ModelError("threshold numérique attendu");
        ref = feature.length;
        feature.push(f);
        threshold.push(t);
        missing.push(MISSING_TYPES[missingName]!);
        defaultLeft.push(node["default_left"] ? 1 : 0);
        left.push(0);
        right.push(0);
        stack.push([node["right_child"], ref, RIGHT], [node["left_child"], ref, LEFT]);
      }
      if (side === ROOT) rootRef = ref;
      else if (side === LEFT) left[parent] = ref;
      else right[parent] = ref;
    }
    return rootRef;
  };

  for (const tree of treeInfo) roots.push(compile(object(tree, "arbre")["tree_structure"]));
  return {
    roots: Int32Array.from(roots),
    feature: Int32Array.from(feature),
    threshold: Float64Array.from(threshold),
    missing: Uint8Array.from(missing),
    defaultLeft: Uint8Array.from(defaultLeft),
    left: Int32Array.from(left),
    right: Int32Array.from(right),
    leafValue: Float64Array.from(leafValue),
  };
}

/** Vérifie et compile un modèle exporté ; lève {@link ModelError} au moindre écart. */
export function loadUrlModel(document: unknown): UrlModel {
  const doc = object(document, "modèle");
  if (doc["format"] !== EXPORT_FORMAT || doc["format_version"] !== EXPORT_FORMAT_VERSION) {
    throw new ModelError("format de modèle non reconnu");
  }
  const extractor = object(doc["feature_extractor"], "feature_extractor");
  if (
    extractor["version"] !== FEATURE_EXTRACTOR_VERSION ||
    extractor["reference_data_sha256"] !== REFERENCE_DATA_SHA256 ||
    extractor["normalization_version"] !== NORMALIZATION_VERSION
  ) {
    // Un modèle produit par un autre extracteur donnerait des scores faux sans erreur.
    throw new ModelError("modèle produit pour un autre extracteur de features");
  }
  const names = doc["feature_names"];
  if (
    !Array.isArray(names) ||
    names.length === 0 ||
    !names.every((n) => typeof n === "string" && FEATURE_NAMES.includes(n)) ||
    new Set(names).size !== names.length
  ) {
    throw new ModelError("feature_names : features connues et distinctes attendues");
  }
  const booster = object(doc["booster"], "booster");
  const boosterNames = booster["feature_names"];
  if (!Array.isArray(boosterNames) || boosterNames.join("\0") !== names.join("\0")) {
    throw new ModelError("ordre des colonnes du booster différent de celui du modèle");
  }
  if (booster["num_class"] !== 1 || booster["num_tree_per_iteration"] !== 1) {
    throw new ModelError("classification binaire attendue");
  }
  const objective = object(doc["objective"], "objective");
  if (objective["name"] !== "binary") throw new ModelError("objectif binaire attendu");
  const sigmoid = finite(objective["sigmoid"], "objective.sigmoid");
  if (doc["decision_rule"] !== "score > threshold") throw new ModelError("règle de décision inconnue");

  const thresholdsDoc = object(doc["thresholds"], "thresholds");
  const thresholds: Record<string, number> = {};
  for (const [name, value] of Object.entries(thresholdsDoc)) thresholds[name] = finite(value, `thresholds.${name}`);

  const usesTld = names.includes("tld_phish_rate");
  if (usesTld && !isObject(doc["tld_table"])) throw new ModelError("tld_phish_rate sans table des TLD");

  return {
    modelVersion: typeof doc["model_version"] === "string" ? doc["model_version"] : "inconnu",
    trainedAt: typeof doc["trained_at"] === "string" ? doc["trained_at"] : null,
    featureNames: names as string[],
    sigmoid,
    thresholds,
    tldTable: usesTld ? parseTldTable(doc["tld_table"]) : null,
    calibration: parseCalibration(doc["calibration"]),
    trees: compileTrees(booster["tree_info"], names.length),
  };
}

// --------------------------------------------------------------------------- //
// Inférence
// --------------------------------------------------------------------------- //

/** Score brut (avant sigmoïde) : somme des feuilles atteintes, dans l'ordre des arbres. */
export function predictRaw(model: UrlModel, x: ArrayLike<number>): number {
  const t = model.trees;
  if (x.length !== model.featureNames.length) {
    throw new ModelError(`${x.length} features reçues, ${model.featureNames.length} attendues`);
  }
  let total = 0;
  for (let r = 0; r < t.roots.length; r++) {
    let node = t.roots[r]!;
    while (node >= 0) {
      let value = x[t.feature[node]!]!;
      const missing = t.missing[node]!;
      if (Number.isNaN(value) && missing !== Missing.NaN) value = 0;
      let goLeft: boolean;
      if (
        (missing === Missing.Zero && Math.abs(value) <= ZERO_THRESHOLD) ||
        (missing === Missing.NaN && Number.isNaN(value))
      ) {
        goLeft = t.defaultLeft[node] === 1;
      } else {
        goLeft = value <= t.threshold[node]!;
      }
      node = goLeft ? t.left[node]! : t.right[node]!;
    }
    total += t.leafValue[-1 - node]!;
  }
  return total;
}

/** Probabilité de phishing du modèle, avant calibration. */
export const predictProbability = (model: UrlModel, x: ArrayLike<number>): number =>
  1 / (1 + Math.exp(-model.sigmoid * predictRaw(model, x)));

/** `numpy.interp(x, xp, fp)`, à l'identique (points répétés compris). */
export function interp(x: number, xp: Float64Array, fp: Float64Array): number {
  const n = xp.length;
  if (x < xp[0]!) return fp[0]!;
  if (x > xp[n - 1]!) return fp[n - 1]!;
  // Plus grand j tel que xp[j] <= x.
  let lo = 0;
  let hi = n - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (xp[mid]! <= x) lo = mid;
    else hi = mid - 1;
  }
  const j = lo;
  if (j === n - 1 || xp[j] === x) return fp[j]!;
  const slope = (fp[j + 1]! - fp[j]!) / (xp[j + 1]! - xp[j]!);
  let result = slope * (x - xp[j]!) + fp[j]!;
  if (Number.isNaN(result)) {
    result = slope * (x - xp[j + 1]!) + fp[j + 1]!;
    if (Number.isNaN(result) && fp[j] === fp[j + 1]) result = fp[j]!;
  }
  return result;
}

const clip01 = (value: number) => Math.min(1, Math.max(0, value));

/** Probabilité calibrée (`ScoreCalibrator`, étape 2.10), celle que lit la fusion. */
export function calibrate(model: UrlModel, score: number): number {
  const c = model.calibration;
  if (c === null) return clip01(score);
  if (c.method === "isotonic") return clip01(interp(score, c.x, c.y));
  const z = Math.min(500, Math.max(-500, c.a * score + c.b));
  return clip01(1 / (1 + Math.exp(-z)));
}

/** Vecteur des features dans l'ordre des colonnes du modèle. */
export function featureVector(model: UrlModel, features: Readonly<Record<string, number>>): Float64Array {
  return Float64Array.from(model.featureNames, (name) => {
    const value = features[name];
    if (value === undefined) throw new ModelError(`feature absente : ${name}`);
    return value;
  });
}
