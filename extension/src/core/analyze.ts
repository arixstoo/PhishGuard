/**
 * Analyse locale d'une URL : extracteur + modèle + règles, puis verdict (étape 5.4).
 *
 * Même décision que l'API sans enrichissement (`UrlAnalyzer` + `fuse`, fusion 1.1.0) :
 *
 * 1. règle dure `lookalike_host` (hôte qui imite des lettres latines, étape 3.8) :
 *    phishing, **avant** la liste blanche, comme côté serveur ;
 * 2. liste blanche personnelle : sûr ;
 * 3. sinon, probabilité calibrée du modèle → score de 0 à 100 → `safe` sous 30,
 *    `suspicious` de 30 à 70, `phishing` au-delà.
 *
 * Les autres règles locales (IP en hôte, marque imitée, identifiants dans l'URL,
 * raccourcisseur) produisent des **raisons**, pas un verdict : le modèle les a déjà
 * apprises comme features, et l'extension ne doit pas contredire l'API sur la même URL.
 *
 * Tout est pur et synchrone : aucune API Chrome, aucun réseau, aucune horloge.
 */

import reference from "../generated/reference-data.json";
import { type Features, InvalidUrlError, type ParsedUrl, parseUrl, UrlFeatureExtractor } from "./features";
import { calibrate, featureVector, predictProbability, type UrlModel } from "./model";
import { type HostAlert, hostScriptAlert } from "./normalize";

export type Verdict = "safe" | "suspicious" | "phishing";
export type HardRule = "lookalike_host" | "allowlist" | "url_too_long";
export type ReasonCode =
  | "lookalike_host"
  | "host_is_ip"
  | "brand_impersonation"
  | "has_userinfo"
  | "is_shortener"
  | "url_too_long";

const THRESHOLDS: { suspicious: number; phishing: number } = reference.fusion.thresholds;
const MODEL_WEIGHT: number = reference.fusion.model_weight;
export const FUSION_VERSION: string = reference.fusion.version;

/**
 * Au-delà, l'URL n'est pas découpée (coût processeur borné) mais signalée comme suspecte.
 * Refuser de l'analyser offrirait une évasion gratuite : allonger le lien.
 */
export const MAX_ANALYZED_URL_CHARS = 65_536;

/** Résultat du calcul local, indépendant de la liste blanche : c'est lui qu'on met en cache. */
export interface LocalScore {
  /** Hôte sous la forme lue par l'utilisateur (Unicode). */
  host: string;
  registeredDomain: string;
  modelVersion: string;
  /** Score du modèle avant calibration (probabilité LightGBM). */
  rawScore: number;
  /** Probabilité calibrée du modèle (entrée de la fusion). */
  probability: number;
  hostAlert: HostAlert | null;
  reasons: ReasonCode[];
}

export interface Analysis extends LocalScore {
  verdict: Verdict;
  /** Score de 0 à 100. */
  score: number;
  hardRule: HardRule | null;
}

export { InvalidUrlError };

/** `to_score` : probabilité → entier de 0 à 100, arrondi au plus proche (0,5 vers le haut). */
export const toScore = (probability: number): number =>
  Math.min(100, Math.max(0, Math.floor(probability * 100 + 0.5)));

export function verdictFor(score: number): Verdict {
  if (score < THRESHOLDS.suspicious) return "safe";
  if (score > THRESHOLDS.phishing) return "phishing";
  return "suspicious";
}

function reasonsFor(parsed: ParsedUrl, features: Features, alert: HostAlert | null): ReasonCode[] {
  const reasons: ReasonCode[] = [];
  if (alert !== null) reasons.push("lookalike_host");
  if (features["host_is_ip"]) reasons.push("host_is_ip");
  if (features["brand_in_host"] || features["is_typosquat"] || features["homograph_brand"]) {
    reasons.push("brand_impersonation");
  }
  if (parsed.hasUserinfo) reasons.push("has_userinfo");
  if (features["is_shortener"]) reasons.push("is_shortener");
  return reasons;
}

export class UrlAnalyzer {
  private readonly extractor: UrlFeatureExtractor;

  constructor(readonly model: UrlModel) {
    this.extractor = new UrlFeatureExtractor({ tldTable: model.tldTable });
  }

  /** Calcul local ; lève {@link InvalidUrlError} pour une URL non http(s) ou invalide. */
  score(url: string): LocalScore {
    if (url.length > MAX_ANALYZED_URL_CHARS) {
      return {
        host: "",
        registeredDomain: "",
        modelVersion: this.model.modelVersion,
        rawScore: 1,
        probability: 1,
        hostAlert: null,
        reasons: ["url_too_long"],
      };
    }
    const parsed = parseUrl(url);
    const features = this.extractor.extractParsed(parsed);
    const rawScore = predictProbability(this.model, featureVector(this.model, features));
    if (!Number.isFinite(rawScore)) throw new Error("score du modèle non fini");
    const hostAlert = hostScriptAlert(parsed.host);
    return {
      host: parsed.hostUnicode,
      registeredDomain: parsed.registeredDomain,
      modelVersion: this.model.modelVersion,
      rawScore,
      probability: calibrate(this.model, rawScore),
      hostAlert,
      reasons: reasonsFor(parsed, features, hostAlert),
    };
  }
}

/** Fusion locale (`fuse` sans enrichissement) : règles dures, puis score et verdict. */
export function decide(local: LocalScore, options: { allowlisted?: boolean } = {}): Analysis {
  if (local.reasons.includes("url_too_long")) {
    return { ...local, verdict: "suspicious", score: THRESHOLDS.phishing, hardRule: "url_too_long" };
  }
  if (local.hostAlert !== null) {
    return { ...local, verdict: "phishing", score: 100, hardRule: "lookalike_host" };
  }
  if (options.allowlisted) {
    return { ...local, verdict: "safe", score: 0, hardRule: "allowlist" };
  }
  // OU probabiliste à une seule source, calculé comme Python : 1 − (1 − w·p).
  const probability = 1 - (1 - MODEL_WEIGHT * local.probability);
  const score = toScore(probability);
  return { ...local, verdict: verdictFor(score), score, hardRule: null };
}
