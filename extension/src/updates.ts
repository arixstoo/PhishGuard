/**
 * Mises à jour du modèle (étape 6.8) : téléchargement, vérification, stockage.
 *
 * **Désactivées par défaut.** Comme l'analyse en ligne, elles exigent deux gestes :
 * cocher l'option **et** accepter la permission des hôtes de GitHub. Sans les deux,
 * aucune requête ne part (vérifié par `test/updates.test.ts`).
 *
 * Ce qui part : trois requêtes `GET` anonymes vers les publications GitHub du projet
 * (signature, manifeste, modèle), sans cookie ni `Referer`, au plus une fois par jour.
 * Aucune donnée de l'utilisateur, aucune URL analysée, aucun identifiant.
 *
 * Ce qui est cru : **rien sans la signature** (`core/signed-model.ts`). Le modèle reçu est
 * gardé dans `storage.local` avec son manifeste et sa signature, et **revérifié en entier à
 * chaque chargement** : `storage.local` est modifiable par le script de contenu Gmail, donc
 * par une page Gmail compromise (docs/extension-privacy.md, section 6). Un modèle stocké
 * qui ne passe plus la vérification est effacé ; l'extension revient au modèle du paquet.
 */

import {
  isNewerRelease,
  MAX_MANIFEST_BYTES,
  MAX_SIGNATURE_BYTES,
  ModelReleaseError,
  type RejectionCode,
  type TrustAnchor,
  verifyModelRelease,
  verifySignedManifest,
  type VerifiedModelRelease,
} from "./core/signed-model";
import type { Settings } from "./settings";
import { MANIFEST_FILE, SIGNATURE_FILE, UPDATE_CHANNEL, UPDATE_ORIGINS } from "./update-channel";

export { UPDATE_ORIGINS } from "./update-channel";

const ALLOWED_RESPONSE_ORIGINS: ReadonlySet<string> = new Set(UPDATE_ORIGINS.map((p) => p.slice(0, -2)));

export const CHECK_INTERVAL_MS = 24 * 60 * 60 * 1000;
const REQUEST_TIMEOUT_MS = 60_000;

const STORED_RELEASE_KEY = "modelRelease";
const STATE_KEY = "modelUpdateState";

export type UpdateResult = "updated" | "up-to-date" | "rejected" | "failed" | "disabled" | "skipped";

/** Dernier essai, affiché dans les options. Purement informatif : jamais une preuve. */
export interface UpdateState {
  checkedAt: number;
  result: Exclude<UpdateResult, "disabled" | "skipped">;
  code: RejectionCode | "network" | "invalid-model" | null;
  release: string | null;
}

export interface UpdateOutcome {
  result: UpdateResult;
  release: string | null;
  modelVersion: string | null;
  code: UpdateState["code"];
}

/** Ce que le service worker fournit : constantes du build et validation du contenu. */
export interface UpdateContext {
  anchor: TrustAnchor | null;
  /** Publication du modèle embarqué ; un modèle reçu doit être strictement plus récent. */
  bundledRelease: string;
  /** Vérifie que le modèle se charge réellement (`loadUrlModel`) ; lève sinon. */
  validateModel: (model: Uint8Array) => void;
  now?: () => number;
}

class DownloadError extends Error {
  override name = "DownloadError";
}

/** Copie stockée : textes UTF-8 exacts (vérifiés `fatal` avant d'être stockés). */
interface StoredRelease {
  manifest: string;
  signature: string;
  model: string;
}

const encoder = new TextEncoder();
const strictDecoder = new TextDecoder("utf-8", { fatal: true });

/** Les deux clés réunies : réglage **et** permission de chaque hôte de GitHub. */
export async function updatesAllowed(settings: Settings): Promise<boolean> {
  if (!settings.modelUpdates) return false;
  return chrome.permissions.contains({ origins: [...UPDATE_ORIGINS] });
}

/** Lit au plus `maxBytes` octets ; refuse une réponse plus longue sans la lire en entier. */
async function download(url: string, maxBytes: number): Promise<Uint8Array> {
  let response: Response;
  try {
    response = await fetch(url, {
      method: "GET",
      credentials: "omit",
      referrerPolicy: "no-referrer",
      cache: "no-store",
      redirect: "follow",
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
  } catch {
    throw new DownloadError("réseau indisponible");
  }
  // Après redirection, la réponse doit encore venir de GitHub (et de rien d'autre).
  const finalUrl = response.url || url;
  if (!ALLOWED_RESPONSE_ORIGINS.has(new URL(finalUrl).origin)) throw new DownloadError("hôte inattendu");
  if (!response.ok) throw new DownloadError(`HTTP ${response.status}`);
  const declared = Number(response.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > maxBytes) throw new ModelReleaseError("too-large", "fichier trop volumineux");
  if (!response.body) {
    const bytes = new Uint8Array(await response.arrayBuffer());
    if (bytes.length > maxBytes) throw new ModelReleaseError("too-large", "fichier trop volumineux");
    return bytes;
  }

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > maxBytes) {
      await reader.cancel().catch(() => undefined);
      throw new ModelReleaseError("too-large", "fichier trop volumineux");
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.length;
  }
  return bytes;
}

async function readStored(): Promise<StoredRelease | null> {
  const value = (await chrome.storage.local.get(STORED_RELEASE_KEY))[STORED_RELEASE_KEY] as unknown;
  if (typeof value !== "object" || value === null) return null;
  const { manifest, signature, model } = value as Record<string, unknown>;
  return typeof manifest === "string" && typeof signature === "string" && typeof model === "string"
    ? { manifest, signature, model }
    : null;
}

export async function clearStoredModel(): Promise<void> {
  await chrome.storage.local.remove([STORED_RELEASE_KEY, STATE_KEY]);
}

export async function getUpdateState(): Promise<UpdateState | null> {
  const value = (await chrome.storage.local.get(STATE_KEY))[STATE_KEY] as unknown;
  if (typeof value !== "object" || value === null) return null;
  const v = value as Record<string, unknown>;
  const results: readonly unknown[] = ["updated", "up-to-date", "rejected", "failed"];
  if (typeof v["checkedAt"] !== "number" || !results.includes(v["result"])) return null;
  return {
    checkedAt: v["checkedAt"],
    result: v["result"] as UpdateState["result"],
    code: typeof v["code"] === "string" ? (v["code"] as UpdateState["code"]) : null,
    release: typeof v["release"] === "string" ? v["release"] : null,
  };
}

async function saveState(state: UpdateState): Promise<void> {
  await chrome.storage.local.set({ [STATE_KEY]: state });
}

/**
 * Modèle reçu précédemment, **revérifié en entier** (signature, manifeste, empreinte,
 * plus récent que le paquet). `null` s'il n'y en a pas ou s'il ne passe plus : il est
 * alors effacé, et l'extension utilise le modèle de son paquet.
 */
export async function loadStoredModel(context: UpdateContext): Promise<VerifiedModelRelease | null> {
  const stored = await readStored();
  if (stored === null || context.anchor === null) return null;
  try {
    const verified = await verifyModelRelease(
      { manifest: encoder.encode(stored.manifest), signature: encoder.encode(stored.signature), model: encoder.encode(stored.model) },
      context.anchor,
      { notOlderThan: context.bundledRelease || null },
    );
    context.validateModel(verified.model);
    return verified;
  } catch {
    // Falsifié, ou dépassé par le modèle d'une nouvelle version de l'extension.
    await chrome.storage.local.remove(STORED_RELEASE_KEY);
    return null;
  }
}

/** Publication la plus récente déjà en place : celle du paquet ou celle stockée. */
async function currentRelease(context: UpdateContext): Promise<string> {
  const stored = await readStored();
  let release = context.bundledRelease;
  if (stored !== null) {
    try {
      const parsed = JSON.parse(stored.manifest) as { release?: unknown };
      if (typeof parsed.release === "string" && isNewerRelease(parsed.release, release)) release = parsed.release;
    } catch {
      // Copie illisible : elle sera effacée au prochain chargement.
    }
  }
  return release;
}

/**
 * Cherche une publication plus récente et la garde si elle passe toutes les vérifications.
 *
 * `force` (bouton « Vérifier maintenant ») ignore l'intervalle d'un jour, jamais le réglage
 * ni la permission.
 */
export async function checkForModelUpdate(
  settings: Settings,
  context: UpdateContext,
  { force = false }: { force?: boolean } = {},
): Promise<UpdateOutcome> {
  const none = { release: null, modelVersion: null, code: null };
  if (context.anchor === null || !(await updatesAllowed(settings))) return { result: "disabled", ...none };
  const now = (context.now ?? Date.now)();
  const previous = await getUpdateState();
  if (!force && previous !== null && now - previous.checkedAt < CHECK_INTERVAL_MS && now >= previous.checkedAt) {
    return { result: "skipped", ...none };
  }

  const current = await currentRelease(context);
  const finish = async (outcome: UpdateOutcome): Promise<UpdateOutcome> => {
    if (outcome.result !== "disabled" && outcome.result !== "skipped") {
      await saveState({ checkedAt: now, result: outcome.result, code: outcome.code, release: outcome.release });
    }
    return outcome;
  };

  try {
    const signature = await download(UPDATE_CHANNEL + SIGNATURE_FILE, MAX_SIGNATURE_BYTES);
    const manifest = await download(UPDATE_CHANNEL + MANIFEST_FILE, MAX_MANIFEST_BYTES);
    let header: Awaited<ReturnType<typeof verifySignedManifest>>;
    try {
      header = await verifySignedManifest({ manifest, signature }, context.anchor, { notOlderThan: current });
    } catch (error) {
      // Publication déjà en place (ou plus ancienne) mais correctement signée : rien à faire.
      if (error instanceof ModelReleaseError && error.code === "rollback") {
        return await finish({ result: "up-to-date", release: current || null, modelVersion: null, code: null });
      }
      throw error;
    }
    // Le modèle n'est téléchargé qu'une fois le manifeste signé vérifié, à sa taille exacte.
    const model = await download(UPDATE_CHANNEL + header.artifact.name, header.artifact.size);
    const verified = await verifyModelRelease({ manifest, signature, model }, context.anchor, { notOlderThan: current });
    let stored: StoredRelease;
    try {
      // Signé ne veut pas dire chargeable : le modèle doit aussi passer `loadUrlModel`, et
      // les trois fichiers être de l'UTF-8 exact (ils sont stockés en texte).
      context.validateModel(verified.model);
      stored = {
        manifest: strictDecoder.decode(manifest),
        signature: strictDecoder.decode(signature),
        model: strictDecoder.decode(verified.model),
      };
    } catch {
      return await finish({ result: "rejected", release: verified.release, modelVersion: null, code: "invalid-model" });
    }
    await chrome.storage.local.set({ [STORED_RELEASE_KEY]: stored });
    return await finish({ result: "updated", release: verified.release, modelVersion: verified.modelVersion, code: null });
  } catch (error) {
    if (error instanceof ModelReleaseError) {
      return finish({ result: "rejected", release: null, modelVersion: null, code: error.code });
    }
    if (error instanceof DownloadError) {
      return finish({ result: "failed", release: null, modelVersion: null, code: "network" });
    }
    throw error;
  }
}
