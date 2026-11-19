/**
 * Mises à jour du modèle (étape 6.8) : réseau et stockage.
 *
 * `fetch`, `chrome.storage.local` et `chrome.permissions` sont simulés. On vérifie la règle
 * des deux clés (réglage **et** permission, sinon aucune requête), la forme exacte des
 * requêtes, l'intervalle d'un jour, le refus d'un modèle falsifié **sans rien stocker**, et
 * la revérification du modèle stocké à chaque chargement (storage.local est modifiable par
 * le script de contenu Gmail).
 */

import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import type { TrustAnchor } from "../src/core/signed-model";
import { DEFAULT_SETTINGS, parseSettings, type Settings } from "../src/settings";
import { MANIFEST_FILE, SIGNATURE_FILE, UPDATE_CHANNEL, UPDATE_ORIGINS } from "../src/update-channel";
import {
  CHECK_INTERVAL_MS,
  checkForModelUpdate,
  clearStoredModel,
  getUpdateState,
  loadStoredModel,
  type UpdateContext,
} from "../src/updates";
import { newSigner, signedRelease, type SignedRelease, type TestSigner } from "./release-fixture";

const encoder = new TextEncoder();
const MODEL = encoder.encode(JSON.stringify({ format: "phishguard-url-lightgbm", model_version: "url_v3", pad: "y".repeat(2000) }));
const BUNDLED = "2026.11.15";
const NOW = Date.UTC(2026, 11, 2, 9, 0, 0);

let signer: TestSigner;
let anchor: TrustAnchor;
let release: SignedRelease;

let store: Record<string, unknown>;
let granted: string[];
let served: Map<string, { body: Uint8Array; url?: string; status?: number; headers?: Record<string, string> }>;
let fetchMock: ReturnType<typeof vi.fn>;

beforeAll(async () => {
  signer = await newSigner();
  anchor = { publicKey: signer.publicKey };
  release = await signedRelease(signer, MODEL);
});

function serve(files: SignedRelease): void {
  served = new Map([
    [UPDATE_CHANNEL + SIGNATURE_FILE, { body: files.signature }],
    [UPDATE_CHANNEL + MANIFEST_FILE, { body: files.manifest }],
    [`${UPDATE_CHANNEL}url_v3.json`, { body: files.model }],
  ]);
}

beforeEach(() => {
  store = {};
  granted = [];
  serve(release);
  fetchMock = vi.fn(async (url: string) => {
    const file = served.get(url);
    if (!file) return new Response("introuvable", { status: 404 });
    const response = new Response(file.body.slice(), { status: file.status ?? 200, headers: file.headers ?? {} });
    // GitHub redirige vers son stockage : la réponse finale porte une autre URL.
    Object.defineProperty(response, "url", {
      value: file.url ?? `https://release-assets.githubusercontent.com/${url.split("/").at(-1)}`,
    });
    return response;
  });
  vi.stubGlobal("fetch", fetchMock);
  vi.stubGlobal("chrome", {
    permissions: { contains: vi.fn(async ({ origins }: { origins: string[] }) => origins.every((o) => granted.includes(o))) },
    storage: {
      local: {
        get: vi.fn(async (key: string) => (key in store ? { [key]: structuredClone(store[key]) } : {})),
        set: vi.fn(async (items: Record<string, unknown>) => Object.assign(store, structuredClone(items))),
        remove: vi.fn(async (keys: string | string[]) => {
          for (const key of Array.isArray(keys) ? keys : [keys]) delete store[key];
        }),
      },
    },
  });
});

afterEach(() => vi.unstubAllGlobals());

const enabled = (overrides: Partial<Settings> = {}): Settings => parseSettings({ ...DEFAULT_SETTINGS, modelUpdates: true, ...overrides });
const grantAll = () => void (granted = [...UPDATE_ORIGINS]);

function context(overrides: Partial<UpdateContext> = {}): UpdateContext {
  return { anchor, bundledRelease: BUNDLED, validateModel: () => undefined, now: () => NOW, ...overrides };
}

describe("règle des deux clés : sinon, aucune requête", () => {
  it("désactivées par défaut", async () => {
    expect(DEFAULT_SETTINGS.modelUpdates).toBe(false);
    grantAll();
    expect((await checkForModelUpdate(parseSettings(undefined), context(), { force: true })).result).toBe("disabled");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("réglage sans permission des hôtes de GitHub", async () => {
    granted = ["https://github.com/*"]; // une seule des trois
    expect((await checkForModelUpdate(enabled(), context(), { force: true })).result).toBe("disabled");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("extension construite sans clé publique : jamais de téléchargement", async () => {
    grantAll();
    expect((await checkForModelUpdate(enabled(), context({ anchor: null }), { force: true })).result).toBe("disabled");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("une valeur stockée invalide revient au défaut (désactivé)", () => {
    expect(parseSettings({ modelUpdates: "oui" }).modelUpdates).toBe(false);
  });
});

describe("mise à jour", () => {
  it("télécharge signature, manifeste puis modèle, anonymement, et garde la publication", async () => {
    grantAll();
    const outcome = await checkForModelUpdate(enabled(), context());
    expect(outcome).toEqual({ result: "updated", release: "2026.12.01", modelVersion: "url_v3", code: null });
    expect(fetchMock.mock.calls.map((c) => c[0])).toEqual([
      UPDATE_CHANNEL + SIGNATURE_FILE,
      UPDATE_CHANNEL + MANIFEST_FILE,
      `${UPDATE_CHANNEL}url_v3.json`,
    ]);
    for (const [, init] of fetchMock.mock.calls) {
      expect(init).toMatchObject({ method: "GET", credentials: "omit", referrerPolicy: "no-referrer", cache: "no-store" });
      expect(init.body).toBeUndefined(); // rien n'est envoyé
      expect(init.headers).toBeUndefined(); // ni clé, ni identifiant
    }
    const loaded = await loadStoredModel(context());
    expect(loaded?.release).toBe("2026.12.01");
    expect(loaded?.model).toEqual(MODEL);
    expect(await getUpdateState()).toMatchObject({ result: "updated", release: "2026.12.01", checkedAt: NOW });
  });

  it("au plus une vérification par jour, sauf « Vérifier maintenant »", async () => {
    grantAll();
    await checkForModelUpdate(enabled(), context());
    fetchMock.mockClear();
    const later = context({ now: () => NOW + CHECK_INTERVAL_MS - 1 });
    expect((await checkForModelUpdate(enabled(), later)).result).toBe("skipped");
    expect(fetchMock).not.toHaveBeenCalled();
    expect((await checkForModelUpdate(enabled(), later, { force: true })).result).toBe("up-to-date");
  });

  it("publication déjà en place : à jour, et le modèle n'est pas retéléchargé", async () => {
    grantAll();
    await checkForModelUpdate(enabled(), context());
    fetchMock.mockClear();
    const outcome = await checkForModelUpdate(enabled(), context(), { force: true });
    expect(outcome.result).toBe("up-to-date");
    expect(fetchMock).toHaveBeenCalledTimes(2); // signature et manifeste seulement
  });

  it("modèle du paquet plus récent que la publication : à jour, rien de stocké", async () => {
    grantAll();
    const outcome = await checkForModelUpdate(enabled(), context({ bundledRelease: "2027.01.01" }), { force: true });
    expect(outcome.result).toBe("up-to-date");
    expect(store["modelRelease"]).toBeUndefined();
  });
});

describe("refus : rien n'est stocké", () => {
  it("un octet modifié dans le modèle servi (hébergement compromis)", async () => {
    grantAll();
    const tampered = release.model.slice();
    tampered[123] = tampered[123]! ^ 0x01;
    serve({ ...release, model: tampered });
    const outcome = await checkForModelUpdate(enabled(), context(), { force: true });
    expect(outcome).toMatchObject({ result: "rejected", code: "artifact-mismatch" });
    expect(store["modelRelease"]).toBeUndefined();
    expect(await loadStoredModel(context())).toBeNull();
  });

  it("une publication signée par une autre clé", async () => {
    grantAll();
    serve(await signedRelease(await newSigner(), MODEL));
    expect(await checkForModelUpdate(enabled(), context(), { force: true })).toMatchObject({ result: "rejected", code: "unknown-key" });
    expect(store["modelRelease"]).toBeUndefined();
  });

  it("un modèle signé mais que l'extension ne sait pas charger", async () => {
    grantAll();
    const invalid = context({
      validateModel: () => {
        throw new Error("format de modèle non reconnu");
      },
    });
    expect(await checkForModelUpdate(enabled(), invalid, { force: true })).toMatchObject({ result: "rejected", code: "invalid-model" });
    expect(store["modelRelease"]).toBeUndefined();
  });

  it("une redirection hors de GitHub", async () => {
    grantAll();
    served.get(UPDATE_CHANNEL + SIGNATURE_FILE)!.url = "https://attaquant.example/manifest.json.sig";
    expect(await checkForModelUpdate(enabled(), context(), { force: true })).toMatchObject({ result: "failed", code: "network" });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("un fichier annoncé démesuré n'est pas lu", async () => {
    grantAll();
    served.get(UPDATE_CHANNEL + MANIFEST_FILE)!.headers = { "content-length": String(64 * 1024 * 1024) };
    expect(await checkForModelUpdate(enabled(), context(), { force: true })).toMatchObject({ result: "rejected", code: "too-large" });
  });

  it("une erreur HTTP", async () => {
    grantAll();
    served.get(UPDATE_CHANNEL + SIGNATURE_FILE)!.status = 503;
    expect(await checkForModelUpdate(enabled(), context(), { force: true })).toMatchObject({ result: "failed", code: "network" });
  });
});

describe("modèle stocké, revérifié à chaque chargement", () => {
  it("modifié dans storage.local (page Gmail compromise) : effacé, retour au modèle du paquet", async () => {
    grantAll();
    await checkForModelUpdate(enabled(), context());
    const stored = store["modelRelease"] as { model: string };
    stored.model = stored.model.replace("yyyy", "yyyz");
    expect(await loadStoredModel(context())).toBeNull();
    expect(store["modelRelease"]).toBeUndefined();
  });

  it("dépassé par le modèle d'une nouvelle version de l'extension : ignoré et effacé", async () => {
    grantAll();
    await checkForModelUpdate(enabled(), context());
    expect(await loadStoredModel(context({ bundledRelease: "2026.12.01" }))).toBeNull();
    expect(store["modelRelease"]).toBeUndefined();
  });

  it("clearStoredModel efface le modèle et l'état", async () => {
    grantAll();
    await checkForModelUpdate(enabled(), context());
    await clearStoredModel();
    expect(store).toEqual({});
  });
});
