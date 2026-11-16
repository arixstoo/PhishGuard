/**
 * Réglages (étape 5.7), dans `chrome.storage.local` : sur cet appareil seulement, jamais
 * `storage.sync`.
 *
 * Par défaut, **rien ne sort de l'appareil** : analyse en ligne et signalements désactivés,
 * aucun serveur. Ce qui est relu est validé champ par champ : `storage.local` est aussi
 * lisible et modifiable par les scripts de contenu, donc par une page Gmail compromise.
 * Une valeur invalide revient à son défaut, c'est-à-dire au plus prudent.
 */

import { isLanguage, type LanguageSetting } from "./i18n";

export interface Settings {
  language: LanguageSetting;
  /** Analyse du message ouvert dans Gmail (sur l'appareil). */
  gmail: boolean;
  /** Analyse de chaque page visitée ; exige la permission optionnelle `tabs`. */
  autoAnalyze: boolean;
  /** Analyse en ligne par `serverUrl` ; exige la permission de cet hôte. */
  enrichment: boolean;
  /** Serveur PhishGuard (API du module 4), forme canonique de {@link parseServerUrl}. */
  serverUrl: string;
  /** Clé personnelle de ce serveur (`X-API-Key`), facultative. */
  apiKey: string;
  /** Signalements d'erreur envoyés à `serverUrl` (domaine seulement). */
  feedback: boolean;
}

export const DEFAULT_SETTINGS: Readonly<Settings> = Object.freeze({
  language: "auto",
  gmail: true,
  autoAnalyze: false,
  enrichment: false,
  serverUrl: "",
  apiKey: "",
  feedback: false,
});

const SETTINGS_KEY = "settings";

/** Format des clés de l'API (étape 4.4) : `pg_` et 256 bits en base64url. */
export const API_KEY_RE = /^pg_[A-Za-z0-9_-]{43}$/;
const LOOPBACK_HOSTS: ReadonlySet<string> = new Set(["localhost", "127.0.0.1"]);
const MAX_SERVER_URL = 512;

/**
 * Adresse d'un serveur, sous forme canonique (`https://hote[:port][/chemin]`, sans barre
 * finale), ou `null` si elle est refusée :
 *
 * - `https` obligatoire ; `http` seulement pour la boucle locale (`make api`) ;
 * - ni identifiants (`user:pass@`), ni paramètres, ni fragment : l'adresse ne doit rien
 *   transporter d'autre qu'un emplacement.
 *
 * Ici, la classe `URL` du navigateur convient : c'est elle que `fetch` utilisera.
 */
export function parseServerUrl(input: string): string | null {
  const text = input.trim();
  if (!text || text.length > MAX_SERVER_URL) return null;
  let url: URL;
  try {
    url = new URL(text);
  } catch {
    return null;
  }
  const loopback = LOOPBACK_HOSTS.has(url.hostname);
  if (url.protocol !== "https:" && !(url.protocol === "http:" && loopback)) return null;
  if (url.username || url.password || url.search || url.hash || text.includes("#") || text.includes("?")) {
    return null;
  }
  return `${url.origin}${url.pathname.replace(/\/+$/, "")}`;
}

/** Motif de permission d'hôte du serveur (`https://hote/*` ; le port est ignoré par Chrome). */
export function serverPermissionPattern(serverUrl: string): string {
  const url = new URL(serverUrl);
  return `${url.protocol}//${url.hostname}/*`;
}

/** Réglages lus et validés ; tout champ invalide prend sa valeur par défaut. */
export function parseSettings(value: unknown): Settings {
  const raw = typeof value === "object" && value !== null ? (value as Record<string, unknown>) : {};
  const bool = (key: keyof Settings) =>
    typeof raw[key] === "boolean" ? (raw[key] as boolean) : (DEFAULT_SETTINGS[key] as boolean);
  const language = raw["language"];
  const serverUrl = typeof raw["serverUrl"] === "string" ? parseServerUrl(raw["serverUrl"]) : null;
  const apiKey = typeof raw["apiKey"] === "string" && API_KEY_RE.test(raw["apiKey"]) ? raw["apiKey"] : "";
  const settings: Settings = {
    language: language === "auto" || isLanguage(language) ? language : DEFAULT_SETTINGS.language,
    gmail: bool("gmail"),
    autoAnalyze: bool("autoAnalyze"),
    enrichment: bool("enrichment"),
    serverUrl: serverUrl ?? "",
    apiKey,
    feedback: bool("feedback"),
  };
  // Sans serveur valide, rien ne peut partir : les deux options réseau sont éteintes.
  if (!settings.serverUrl) {
    settings.enrichment = false;
    settings.feedback = false;
    settings.apiKey = "";
  }
  return settings;
}

export async function getSettings(): Promise<Settings> {
  const stored = await chrome.storage.local.get(SETTINGS_KEY);
  return parseSettings(stored[SETTINGS_KEY]);
}

export async function updateSettings(patch: Partial<Settings>): Promise<Settings> {
  const next = parseSettings({ ...(await getSettings()), ...patch });
  await chrome.storage.local.set({ [SETTINGS_KEY]: next });
  return next;
}

export const isSettingsChange = (changes: Record<string, chrome.storage.StorageChange>): boolean =>
  SETTINGS_KEY in changes;
