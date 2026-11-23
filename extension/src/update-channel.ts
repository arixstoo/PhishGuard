/**
 * Canal de publication des modèles (étape 6.8). Module sans réseau : la page d'options
 * l'importe pour demander les permissions, sans embarquer `fetch` (interdit hors du
 * service worker par `build.mjs`).
 */

/** Release GitHub « models-stable », réécrite à chaque publication signée. */
export const UPDATE_CHANNEL = "https://github.com/arixstoo/PhishGuard/releases/download/models-stable/";
export const MANIFEST_FILE = "manifest.json";
export const SIGNATURE_FILE = "manifest.json.sig";

/**
 * GitHub sert les fichiers d'une release par une redirection vers son stockage. Seuls ces
 * hôtes sont demandés, et une réponse finale venue d'ailleurs est refusée.
 */
export const UPDATE_ORIGINS: readonly string[] = [
  "https://github.com/*",
  "https://release-assets.githubusercontent.com/*",
  "https://objects.githubusercontent.com/*",
];
