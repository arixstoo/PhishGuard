/**
 * Service worker (étape 5.4) : analyse locale, badge et menu contextuel.
 *
 * - **Aucune requête réseau.** Le modèle est lu dans le paquet de l'extension
 *   (`chrome.runtime.getURL`), et la CSP (`connect-src 'self'`) interdit tout autre
 *   `fetch` : même un bogue ne pourrait pas envoyer une URL.
 * - **Aucun état important en mémoire** : MV3 arrête le service worker à tout moment.
 *   Le modèle est rechargé à la demande ; les analyses vont dans `storage.session`.
 * - **Le badge ne ment pas.** Il décrit une URL précise ; dès que l'onglet navigue, il
 *   est effacé, pour qu'un « ✓ » laissé par une page sûre ne couvre pas la suivante.
 * - Les écouteurs sont enregistrés au premier niveau, de façon synchrone : c'est ce qui
 *   permet à Chrome de réveiller le service worker pour les traiter.
 */

import { type Analysis, decide, InvalidUrlError, type LocalScore, UrlAnalyzer, type Verdict } from "./core/analyze";
import { loadUrlModel } from "./core/model";
import { type ErrorCode, parseRequest, type Request, type Response } from "./messages";
import {
  addToAllowlist,
  cacheKey,
  getCached,
  isAllowlisted,
  putCached,
  removeFromAllowlist,
} from "./storage";
import { setLastLink } from "./link";

// Injectés par build.mjs : chemin du modèle dans le paquet et empreinte vérifiée au build.
declare const __MODEL_PATH__: string;
declare const __MODEL_SHA256__: string;

const CONTEXT_MENU_ID = "phishguard-analyze-link";
const MEMORY_CACHE_SIZE = 50;

class ModelUnavailableError extends Error {
  override name = "ModelUnavailableError";
}

// --------------------------------------------------------------------------- //
// Modèle et analyse
// --------------------------------------------------------------------------- //

let analyzerPromise: Promise<UrlAnalyzer> | null = null;
// Cache mémoire en plus de storage.session : évite un aller-retour asynchrone tant que
// le service worker reste éveillé. Perdu à l'arrêt, sans conséquence.
const memoryCache = new Map<string, LocalScore>();

async function sha256Hex(bytes: ArrayBuffer): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
}

async function loadAnalyzer(): Promise<UrlAnalyzer> {
  if (!__MODEL_SHA256__) throw new ModelUnavailableError("extension construite sans modèle");
  const response = await fetch(chrome.runtime.getURL(__MODEL_PATH__));
  if (!response.ok) throw new ModelUnavailableError("modèle introuvable dans le paquet");
  const bytes = await response.arrayBuffer();
  // Défense en profondeur : le build a vérifié la signature du manifeste ; ici, on
  // vérifie que le fichier lu est bien celui-là (dossier non empaqueté modifié, etc.).
  if ((await sha256Hex(bytes)) !== __MODEL_SHA256__) {
    throw new ModelUnavailableError("empreinte du modèle inattendue");
  }
  return new UrlAnalyzer(loadUrlModel(JSON.parse(new TextDecoder().decode(bytes))));
}

function getAnalyzer(): Promise<UrlAnalyzer> {
  analyzerPromise ??= loadAnalyzer().catch((error: unknown) => {
    analyzerPromise = null; // nouvel essai au prochain appel
    throw error;
  });
  return analyzerPromise;
}

function remember(key: string, score: LocalScore): void {
  memoryCache.delete(key);
  memoryCache.set(key, score);
  if (memoryCache.size > MEMORY_CACHE_SIZE) memoryCache.delete(memoryCache.keys().next().value!);
}

/** Analyse une URL (cache compris) puis applique la liste blanche. */
export async function analyzeUrl(url: string): Promise<Analysis> {
  const analyzer = await getAnalyzer();
  const key = await cacheKey(url, analyzer.model.modelVersion);
  let local = memoryCache.get(key) ?? (await getCached(key));
  if (local === null || local === undefined) {
    local = analyzer.score(url); // lève InvalidUrlError pour chrome://, file://…
    await putCached(key, local);
  }
  remember(key, local);
  // La liste blanche est relue à chaque fois : elle peut avoir changé depuis le cache.
  return decide(local, { allowlisted: await isAllowlisted(local.registeredDomain) });
}

// --------------------------------------------------------------------------- //
// Badge : icône + couleur + texte (jamais la couleur seule)
// --------------------------------------------------------------------------- //

const BADGE: Readonly<Record<Verdict, { text: string; color: string; title: string }>> = {
  // Contraste du texte blanc sur ces fonds : 5,3 / 4,6 / 5,6 (WCAG AA ≥ 4,5).
  safe: { text: "✓", color: "#1e7b34", title: "badgeTitleSafe" },
  suspicious: { text: "?", color: "#a35400", title: "badgeTitleSuspicious" },
  phishing: { text: "!", color: "#c62828", title: "badgeTitlePhishing" },
};

export async function showVerdict(tabId: number, analysis: Analysis): Promise<void> {
  const badge = BADGE[analysis.verdict];
  const title = chrome.i18n.getMessage(badge.title, [analysis.host || "?"]);
  await Promise.all([
    chrome.action.setBadgeText({ tabId, text: badge.text }),
    chrome.action.setBadgeBackgroundColor({ tabId, color: badge.color }),
    chrome.action.setBadgeTextColor({ tabId, color: "#ffffff" }),
    chrome.action.setTitle({ tabId, title }),
  ]);
}

async function clearVerdict(tabId: number): Promise<void> {
  try {
    await Promise.all([
      chrome.action.setBadgeText({ tabId, text: "" }),
      chrome.action.setTitle({ tabId, title: chrome.i18n.getMessage("actionTitle") }),
    ]);
  } catch {
    // Onglet fermé entre-temps : rien à effacer.
  }
}

// Champs de changeInfo qui ne signalent pas une navigation. Sans la permission « tabs »,
// Chrome retire `url` et `title` : un événement vide ou inconnu est donc traité comme
// une navigation possible, et le badge est effacé (prudence plutôt que verdict périmé).
const NOT_A_NAVIGATION = new Set([
  "audible",
  "autoDiscardable",
  "discarded",
  "frozen",
  "groupId",
  "mutedInfo",
  "pinned",
]);

chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === "complete") return; // fin du chargement analysé
  const keys = Object.keys(changeInfo);
  if (keys.length > 0 && keys.every((key) => NOT_A_NAVIGATION.has(key))) return;
  void clearVerdict(tabId);
});

// --------------------------------------------------------------------------- //
// Messages des pages de l'extension
// --------------------------------------------------------------------------- //

function errorCode(error: unknown): ErrorCode {
  if (error instanceof InvalidUrlError) return "not-analyzable";
  if (error instanceof ModelUnavailableError) return "model-unavailable";
  return "internal";
}

/** URL d'un onglet, lisible seulement si l'utilisateur a cliqué sur l'icône (`activeTab`). */
async function tabUrl(tabId: number): Promise<string | null> {
  try {
    return (await chrome.tabs.get(tabId)).url ?? null;
  } catch {
    return null;
  }
}

async function handle(request: Request): Promise<Response> {
  switch (request.type) {
    case "analyze-tab": {
      const url = await tabUrl(request.tabId);
      if (url === null) return { ok: false, error: "no-access" };
      const start = performance.now();
      try {
        const analysis = await analyzeUrl(url);
        const elapsedMs = performance.now() - start;
        await showVerdict(request.tabId, analysis);
        return { ok: true, analysis, elapsedMs };
      } catch (error) {
        await clearVerdict(request.tabId);
        return { ok: false, error: errorCode(error) };
      }
    }
    case "allowlist-add-tab": {
      const url = await tabUrl(request.tabId);
      if (url === null) return { ok: false, error: "no-access" };
      try {
        return { ok: true, domain: await addToAllowlist(url) };
      } catch (error) {
        return { ok: false, error: errorCode(error) };
      }
    }
    case "allowlist-remove":
      await removeFromAllowlist(request.domain);
      return { ok: true };
  }
}

const EXTENSION_ORIGIN = new URL(chrome.runtime.getURL("")).origin;

/**
 * Vrai pour une page de l'extension elle-même (fenêtre contextuelle, page d'options, même
 * ouverte dans un onglet). Un script de contenu a le même `sender.id` que l'extension mais
 * l'origine de la page web où il tourne : c'est l'origine qui les distingue.
 */
function fromExtensionPage(sender: chrome.runtime.MessageSender): boolean {
  if (sender.id !== chrome.runtime.id) return false;
  const origin = sender.origin ?? (sender.url ? new URL(sender.url).origin : null);
  return origin === EXTENSION_ORIGIN;
}

chrome.runtime.onMessage.addListener((message: unknown, sender, sendResponse) => {
  const request = parseRequest(message);
  if (!fromExtensionPage(sender) || request === null) {
    sendResponse({ ok: false, error: "bad-request" } satisfies Response);
    return false;
  }
  handle(request).then(sendResponse, () => sendResponse({ ok: false, error: "internal" } satisfies Response));
  return true; // réponse asynchrone
});

// --------------------------------------------------------------------------- //
// Menu contextuel : « Analyser ce lien avec PhishGuard »
// --------------------------------------------------------------------------- //

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({
      id: CONTEXT_MENU_ID,
      title: chrome.i18n.getMessage("contextMenuAnalyzeLink"),
      contexts: ["link"],
    });
  });
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId !== CONTEXT_MENU_ID || !info.linkUrl) return;
  const linkUrl = info.linkUrl;
  void (async () => {
    let result;
    try {
      const analysis = await analyzeUrl(linkUrl);
      result = {
        host: analysis.host,
        verdict: analysis.verdict,
        score: analysis.score,
        reasons: analysis.reasons,
        hardRule: analysis.hardRule,
      };
    } catch (error) {
      result = { host: "", verdict: errorCode(error), score: 0, reasons: [], hardRule: null };
    }
    await setLastLink({ at: Date.now(), ...result });
    // Le résultat s'affiche dans la fenêtre contextuelle (aucune permission en plus).
    try {
      await chrome.action.openPopup(tab?.windowId !== undefined ? { windowId: tab.windowId } : {});
    } catch {
      // Fenêtre sans focus : le résultat attend la prochaine ouverture (2 min).
    }
  })();
});
