/**
 * Client de l'API PhishGuard (étape 5.7) : **le seul module qui parle au réseau**.
 *
 * Deux clés sont nécessaires pour qu'une requête parte, et les deux sont vérifiées à
 * chaque appel, juste avant `fetch` :
 *
 * 1. le réglage (analyse en ligne ou signalements) est activé, avec un serveur valide ;
 * 2. l'utilisateur a accordé à l'extension la permission de **cet** hôte
 *    (`chrome.permissions.request`, depuis la page d'options). Un script de contenu ne
 *    peut pas l'accorder : une page Gmail compromise qui modifierait les réglages de
 *    `storage.local` n'obtiendrait toujours aucune requête.
 *
 * La réponse du serveur est **non fiable** (un serveur auto-hébergé peut être compromis) :
 * taille bornée, schéma vérifié, seuls quelques champs gardés, et elle ne peut jamais
 * rendre un verdict plus rassurant que l'analyse locale (voir `strictest`).
 */

import type { Verdict } from "./core/analyze";
import type { Language } from "./i18n";
import { type Settings, serverPermissionPattern } from "./settings";

export class NetworkDisabledError extends Error {
  override name = "NetworkDisabledError";
}
export class RemoteError extends Error {
  override name = "RemoteError";
  constructor(readonly code: "timeout" | "network" | "http" | "invalid-response" | "too-long") {
    super(code);
  }
}

/** Longueur maximale d'une URL acceptée par l'API (`MAX_URL_CHARS`, étape 4.2). */
export const API_MAX_URL_CHARS = 2048;
const TIMEOUT_MS = 8000;
const MAX_RESPONSE_BYTES = 256 * 1024;
const VERDICTS: readonly Verdict[] = ["safe", "suspicious", "phishing"];
const RANK: Readonly<Record<Verdict, number>> = { safe: 0, suspicious: 1, phishing: 2 };

export interface RemoteReason {
  code: string;
  message: string;
}

/** Sous-ensemble vérifié d'une `AnalysisResponse` (schéma 1.x, docs/response-schema.md). */
export interface RemoteAnalysis {
  verdict: Verdict;
  score: number;
  reasons: RemoteReason[];
  advice: string;
  enrichment: "used" | "skipped";
  modelVersion: string;
}

export type Judgement = "false_positive" | "false_negative";

/** Le plus prudent de deux verdicts : un serveur ne peut pas innocenter ce que l'appareil soupçonne. */
export const strictest = (a: Verdict, b: Verdict): Verdict => (RANK[a] >= RANK[b] ? a : b);

/** L'URL telle qu'elle sera envoyée : sans fragment (`#…`), qui peut porter un jeton (OAuth). */
export function urlForServer(url: string): string {
  const hash = url.indexOf("#");
  return hash < 0 ? url : url.slice(0, hash);
}

/** Vérifie les deux clés ; lève {@link NetworkDisabledError} si l'une manque. */
async function requireNetwork(settings: Settings, purpose: "enrichment" | "feedback"): Promise<URL> {
  if (!settings[purpose] || !settings.serverUrl) throw new NetworkDisabledError(purpose);
  const granted = await chrome.permissions.contains({ origins: [serverPermissionPattern(settings.serverUrl)] });
  if (!granted) throw new NetworkDisabledError("permission");
  return new URL(settings.serverUrl);
}

async function post(settings: Settings, base: URL, path: string, body: unknown): Promise<unknown> {
  const headers: Record<string, string> = { "Content-Type": "application/json", Accept: "application/json" };
  if (settings.apiKey) headers["X-API-Key"] = settings.apiKey;
  let response: Response;
  try {
    response = await fetch(`${base.href.replace(/\/$/, "")}${path}`, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
      credentials: "omit", // aucun cookie : l'API n'en connaît pas
      redirect: "error", // une redirection pourrait mener la clé d'API vers un autre hôte
      referrerPolicy: "no-referrer",
      cache: "no-store",
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
  } catch (error) {
    throw new RemoteError(error instanceof DOMException && error.name === "TimeoutError" ? "timeout" : "network");
  }
  if (!response.ok) throw new RemoteError("http");
  const length = Number(response.headers.get("content-length") ?? 0);
  if (length > MAX_RESPONSE_BYTES) throw new RemoteError("invalid-response");
  const text = await response.text();
  if (text.length > MAX_RESPONSE_BYTES) throw new RemoteError("invalid-response");
  try {
    return JSON.parse(text);
  } catch {
    throw new RemoteError("invalid-response");
  }
}

const isText = (value: unknown, max: number): value is string => typeof value === "string" && value.length <= max;

/** Valide une réponse d'analyse ; lève {@link RemoteError} au moindre écart. */
export function parseRemoteAnalysis(value: unknown): RemoteAnalysis {
  const invalid = () => new RemoteError("invalid-response");
  if (typeof value !== "object" || value === null) throw invalid();
  const r = value as Record<string, unknown>;
  const verdict = r["verdict"];
  const score = r["score"];
  if (!VERDICTS.includes(verdict as Verdict)) throw invalid();
  if (typeof score !== "number" || !Number.isInteger(score) || score < 0 || score > 100) throw invalid();
  if (!Array.isArray(r["reasons"]) || r["reasons"].length > 3) throw invalid();
  const reasons = r["reasons"].map((reason: unknown): RemoteReason => {
    const x = (typeof reason === "object" && reason !== null ? reason : {}) as Record<string, unknown>;
    if (!isText(x["code"], 64) || !isText(x["message"], 400)) throw invalid();
    return { code: x["code"], message: x["message"] };
  });
  if (!isText(r["advice"], 600)) throw invalid();
  if (r["enrichment"] !== "used" && r["enrichment"] !== "skipped") throw invalid();
  if (!isText(r["model_version"], 64)) throw invalid();
  return {
    verdict: verdict as Verdict,
    score,
    reasons,
    advice: r["advice"],
    enrichment: r["enrichment"],
    modelVersion: r["model_version"],
  };
}

/** `POST /v1/analyze/url` avec enrichissement : l'URL (sans fragment) part vers le serveur. */
export async function analyzeOnline(settings: Settings, url: string, language: Language): Promise<RemoteAnalysis> {
  const base = await requireNetwork(settings, "enrichment");
  const sent = urlForServer(url);
  if (sent.length > API_MAX_URL_CHARS) throw new RemoteError("too-long");
  const body = { url: sent, language, use_threat_intel: true, analyst: false };
  return parseRemoteAnalysis(await post(settings, base, "/v1/analyze/url", body));
}

/** Cohérence exigée par l'API : un faux positif porte sur un verdict suspect ou phishing. */
export function isCoherentJudgement(verdict: Verdict, judgement: Judgement): boolean {
  return judgement === "false_positive" ? verdict !== "safe" : verdict !== "phishing";
}

/** `POST /v1/feedback` : **le domaine seulement**, le verdict reçu et le jugement. */
export async function sendFeedback(
  settings: Settings,
  domain: string,
  verdict: Verdict,
  judgement: Judgement,
): Promise<void> {
  const base = await requireNetwork(settings, "feedback");
  if (!isCoherentJudgement(verdict, judgement)) throw new RemoteError("invalid-response");
  await post(settings, base, "/v1/feedback", { domain, verdict, judgement });
}
