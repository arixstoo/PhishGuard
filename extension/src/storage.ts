/**
 * État persistant et cache, hors du service worker (étape 5.4).
 *
 * MV3 arrête le service worker après ~30 s d'inactivité : rien d'important ne vit dans une
 * variable globale.
 *
 * - **Liste blanche** (`chrome.storage.local`) : domaines enregistrés auxquels
 *   l'utilisateur fait confiance. Seule donnée persistée ; elle ne quitte pas l'appareil
 *   (`storage.local`, jamais `storage.sync`).
 * - **Cache des analyses** (`chrome.storage.session`) : en mémoire seulement, effacé à la
 *   fermeture du navigateur, inaccessible aux scripts de contenu. Les clés sont des
 *   empreintes SHA-256 d'URL, les entrées sont bornées : ce n'est pas un historique.
 */

import type { LocalScore } from "./core/analyze";
import { parseUrl } from "./core/features";

const ALLOWLIST_KEY = "allowlist";
const CACHE_KEY = "analysisCache";
/** Analyses gardées en cache (les plus récentes). */
export const CACHE_SIZE = 100;
const MAX_ALLOWLIST = 1000;

// --------------------------------------------------------------------------- //
// Liste blanche
// --------------------------------------------------------------------------- //

/**
 * Domaine enregistré (forme ASCII) d'une saisie : `https://www.Exemple.fr/x` → `exemple.fr`.
 * La confiance porte sur le domaine enregistré, comme la liste blanche de l'API.
 */
export function allowlistKey(input: string): string {
  return parseUrl(input).registeredDomain;
}

export async function getAllowlist(): Promise<string[]> {
  const stored = await chrome.storage.local.get(ALLOWLIST_KEY);
  const value = stored[ALLOWLIST_KEY];
  return Array.isArray(value) ? value.filter((d): d is string => typeof d === "string") : [];
}

export async function isAllowlisted(registeredDomain: string): Promise<boolean> {
  return registeredDomain !== "" && (await getAllowlist()).includes(registeredDomain);
}

export async function addToAllowlist(input: string): Promise<string> {
  const domain = allowlistKey(input);
  const current = await getAllowlist();
  if (!current.includes(domain)) {
    if (current.length >= MAX_ALLOWLIST) throw new Error("liste blanche pleine");
    await chrome.storage.local.set({ [ALLOWLIST_KEY]: [...current, domain].sort() });
  }
  return domain;
}

export async function removeFromAllowlist(domain: string): Promise<void> {
  const current = await getAllowlist();
  await chrome.storage.local.set({ [ALLOWLIST_KEY]: current.filter((d) => d !== domain) });
}

// --------------------------------------------------------------------------- //
// Cache des analyses (mémoire de session)
// --------------------------------------------------------------------------- //

async function sha256Hex(text: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
}

type CacheEntry = [key: string, score: LocalScore];

/** Clé de cache : empreinte de l'URL **et** de la version du modèle (un nouveau modèle invalide tout). */
export const cacheKey = (url: string, modelVersion: string): Promise<string> =>
  sha256Hex(`${modelVersion}\n${url}`);

async function readCache(): Promise<CacheEntry[]> {
  const stored = await chrome.storage.session.get(CACHE_KEY);
  const value = stored[CACHE_KEY];
  return Array.isArray(value) ? (value as CacheEntry[]) : [];
}

export async function getCached(key: string): Promise<LocalScore | null> {
  const entry = (await readCache()).find(([k]) => k === key);
  return entry ? entry[1] : null;
}

export async function putCached(key: string, score: LocalScore): Promise<void> {
  // Deux analyses simultanées peuvent perdre une entrée : sans gravité pour un cache.
  const entries = (await readCache()).filter(([k]) => k !== key);
  entries.push([key, score]);
  await chrome.storage.session.set({ [CACHE_KEY]: entries.slice(-CACHE_SIZE) });
}
