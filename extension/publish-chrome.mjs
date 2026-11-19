/**
 * Envoi d'une version au Chrome Web Store (étape 6.9), par l'API v2.
 *
 *   node publish-chrome.mjs release/phishguard-extension-1.0.0.zip              # envoi seul
 *   node publish-chrome.mjs release/phishguard-extension-1.0.0.zip --publish    # + soumission
 *   node publish-chrome.mjs … --publish --staged   # publiée seulement quand l'auteur clique
 *
 * Variables d'environnement (secrets de l'environnement GitHub « chrome-web-store ») :
 *   CWS_CLIENT_ID, CWS_CLIENT_SECRET, CWS_REFRESH_TOKEN : client OAuth et jeton de
 *     rafraîchissement, portée https://www.googleapis.com/auth/chromewebstore ;
 *   CWS_PUBLISHER_ID, CWS_EXTENSION_ID : identifiants publics de l'éditeur et de l'élément.
 *
 * Ce que l'API ne fait pas : créer l'élément, remplir la fiche ou les pratiques de
 * confidentialité. Le premier envoi se fait à la main dans le tableau de bord
 * (docs/store.md) ; ce script ne sert qu'aux versions suivantes.
 *
 * Garde-fous :
 * - la version du manifeste **dans l'archive** doit être celle annoncée par le store après
 *   l'envoi (`crxVersion`) : une archive périmée ou le mauvais fichier sont refusés ;
 * - le jeton d'accès n'est jamais écrit dans un journal, ni dans un message d'erreur ;
 * - aucune requête ailleurs que vers oauth2.googleapis.com et chromewebstore.googleapis.com ;
 * - `--publish` soumet à la revue de Google : rien n'est publié sans elle (`skipReview`
 *   n'est jamais demandé).
 */

import { readFileSync } from "node:fs";
import { inflateRawSync } from "node:zlib";
import { fileURLToPath } from "node:url";

const TOKEN_URL = "https://oauth2.googleapis.com/token";
const API = "https://chromewebstore.googleapis.com";
const ID_PATTERN = /^[a-p]{32}$/; // identifiant d'extension Chrome : 32 lettres de a à p
const PUBLISHER_PATTERN = /^[\w.-]{1,128}$/;

export class PublishError extends Error {}

/** `manifest.json` d'une archive ZIP (méthode « stored » ou « deflate »), sans dépendance. */
export function manifestFromZip(zip) {
  let offset = zip.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
  if (offset < 0) throw new PublishError("archive ZIP illisible (fin de répertoire absente)");
  const count = zip.readUInt16LE(offset + 10);
  offset = zip.readUInt32LE(offset + 16);
  for (let i = 0; i < count; i++) {
    if (zip.readUInt32LE(offset) !== 0x02014b50) throw new PublishError("répertoire central corrompu");
    const method = zip.readUInt16LE(offset + 10);
    const size = zip.readUInt32LE(offset + 20);
    const nameLength = zip.readUInt16LE(offset + 28);
    const extra = zip.readUInt16LE(offset + 30);
    const comment = zip.readUInt16LE(offset + 32);
    const local = zip.readUInt32LE(offset + 42);
    const name = zip.toString("utf-8", offset + 46, offset + 46 + nameLength);
    if (name === "manifest.json") {
      const start = local + 30 + zip.readUInt16LE(local + 26) + zip.readUInt16LE(local + 28);
      const data = zip.subarray(start, start + size);
      if (method === 0) return JSON.parse(data.toString("utf-8"));
      if (method === 8) return JSON.parse(inflateRawSync(data).toString("utf-8"));
      throw new PublishError(`méthode de compression ${method} non prise en charge`);
    }
    offset += 46 + nameLength + extra + comment;
  }
  throw new PublishError("manifest.json absent de l'archive");
}

const VARIABLES = {
  clientId: "CWS_CLIENT_ID",
  clientSecret: "CWS_CLIENT_SECRET",
  refreshToken: "CWS_REFRESH_TOKEN",
  publisherId: "CWS_PUBLISHER_ID",
  extensionId: "CWS_EXTENSION_ID",
};

export function readConfig(env) {
  const config = Object.fromEntries(Object.entries(VARIABLES).map(([key, name]) => [key, env[name] ?? ""]));
  const missing = Object.entries(VARIABLES)
    .filter(([key]) => !config[key])
    .map(([, name]) => name);
  if (missing.length > 0) throw new PublishError(`configuration incomplète : ${missing.join(", ")}`);
  if (!ID_PATTERN.test(config.extensionId)) throw new PublishError("CWS_EXTENSION_ID : 32 lettres de a à p attendues");
  if (!PUBLISHER_PATTERN.test(config.publisherId)) throw new PublishError("CWS_PUBLISHER_ID invalide");
  return config;
}

/** Réponse JSON, ou erreur qui cite le statut et le message de l'API, jamais la requête. */
async function json(response, step) {
  const text = await response.text();
  let body = {};
  try {
    body = text ? JSON.parse(text) : {};
  } catch {
    body = {};
  }
  if (!response.ok) {
    const detail = body?.error?.message ?? body?.error_description ?? response.statusText;
    throw new PublishError(`${step} : HTTP ${response.status} ${String(detail).slice(0, 300)}`);
  }
  return body;
}

export async function accessToken(config, fetchImpl = fetch) {
  const response = await fetchImpl(TOKEN_URL, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: config.clientId,
      client_secret: config.clientSecret,
      refresh_token: config.refreshToken,
      grant_type: "refresh_token",
    }),
    redirect: "error",
  });
  const body = await json(response, "jeton OAuth");
  if (typeof body.access_token !== "string" || body.access_token.length < 10) {
    throw new PublishError("jeton OAuth : réponse sans access_token");
  }
  return body.access_token;
}

const itemPath = (config) => `publishers/${config.publisherId}/items/${config.extensionId}`;

/**
 * Envoie l'archive, attend la fin du traitement, vérifie la version.
 * `sleep` et `fetchImpl` sont injectables pour les tests.
 */
export async function upload(config, token, zip, expectedVersion, { fetchImpl = fetch, sleep = (ms) => new Promise((r) => setTimeout(r, ms)), attempts = 20 } = {}) {
  const auth = { Authorization: `Bearer ${token}` };
  const response = await fetchImpl(`${API}/upload/v2/${itemPath(config)}:upload`, {
    method: "POST",
    headers: { ...auth, "Content-Type": "application/zip" },
    body: zip,
    redirect: "error",
  });
  let state = await json(response, "envoi");
  let version = state.crxVersion;
  let uploadState = state.uploadState;
  for (let i = 0; uploadState === "IN_PROGRESS" && i < attempts; i++) {
    await sleep(Math.min(30_000, 2_000 * 2 ** i));
    state = await json(await fetchImpl(`${API}/v2/${itemPath(config)}:fetchStatus`, { headers: auth, redirect: "error" }), "état");
    uploadState = state.lastAsyncUploadState;
    version = state.submittedItemRevisionStatus?.distributionChannels?.[0]?.crxVersion ?? version;
  }
  if (uploadState !== "SUCCEEDED") throw new PublishError(`envoi : état ${uploadState ?? "inconnu"}`);
  if (version && version !== expectedVersion) {
    throw new PublishError(`le store annonce la version ${version}, l'archive porte ${expectedVersion}`);
  }
  return { version: version ?? expectedVersion };
}

export async function publish(config, token, { staged = false, fetchImpl = fetch } = {}) {
  const response = await fetchImpl(`${API}/v2/${itemPath(config)}:publish`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify({ publishType: staged ? "STAGED_PUBLISH" : "DEFAULT_PUBLISH", blockOnWarnings: true }),
    redirect: "error",
  });
  const body = await json(response, "soumission");
  return { state: body.state ?? "inconnu", warnings: (body.warningInfo?.warnings ?? []).map((w) => w.description ?? w.reason) };
}

async function main(argv) {
  const [path] = argv.filter((a) => !a.startsWith("--"));
  if (!path) throw new PublishError("usage : node publish-chrome.mjs <archive.zip> [--publish [--staged]]");
  const zip = readFileSync(path);
  const manifest = manifestFromZip(zip);
  if (manifest.browser_specific_settings) throw new PublishError("archive Firefox : envoyer l'archive Chrome");
  const config = readConfig(process.env);
  const token = await accessToken(config);
  const { version } = await upload(config, token, zip, manifest.version);
  console.log(`chrome web store : version ${version} envoyée (${manifest.version_name ?? manifest.version})`);
  if (!argv.includes("--publish")) return;
  const staged = argv.includes("--staged");
  const result = await publish(config, token, { staged });
  console.log(`chrome web store : soumise à la revue (${staged ? "publication manuelle après accord" : "publication dès l'accord"}), état ${result.state}`);
  for (const warning of result.warnings) console.warn(`chrome web store : avertissement : ${warning}`);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main(process.argv.slice(2)).catch((error) => {
    console.error(`publish-chrome : ${error instanceof PublishError ? error.message : "erreur inattendue"}`);
    if (!(error instanceof PublishError)) console.error(error?.stack?.split("\n")[0]);
    process.exit(1);
  });
}
