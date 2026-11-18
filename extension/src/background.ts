/**
 * Service worker (étapes 5.4 à 5.7) : analyse locale, badge, menu contextuel, Gmail,
 * analyse automatique et analyse en ligne optionnelles.
 *
 * - **Aucune requête réseau par défaut.** Le modèle est lu dans le paquet ; seul `api.ts`
 *   appelle un serveur, et seulement si l'utilisateur a activé l'option **et** accordé la
 *   permission de cet hôte (étape 5.7). Les mises à jour signées du modèle (`updates.ts`,
 *   étape 6.8) obéissent à la même règle des deux clés.
 * - **Aucun état important en mémoire** : MV3 arrête le service worker à tout moment.
 *   Le modèle est rechargé à la demande ; les analyses demandées vont dans
 *   `storage.session`. L'analyse automatique et Gmail ne gardent rien : pas de trace de
 *   navigation, même en mémoire de session.
 * - **Le badge ne ment pas.** Il décrit une URL précise ; dès que l'onglet navigue, il
 *   est effacé, pour qu'un « ✓ » laissé par une page sûre ne couvre pas la suivante.
 * - Les écouteurs sont enregistrés au premier niveau, de façon synchrone : c'est ce qui
 *   permet à Chrome de réveiller le service worker pour les traiter.
 */

import { analyzeOnline, NetworkDisabledError, RemoteError, sendFeedback, strictest } from "./api";
import { type Analysis, decide, InvalidUrlError, type LocalScore, UrlAnalyzer, type Verdict } from "./core/analyze";
import { inspectMail } from "./core/inspect";
import { ipVersion } from "./core/ip";
import { loadUrlModel, type UrlModel } from "./core/model";
import { trustAnchorFromBase64 } from "./core/signed-model";
import { resolveLanguage, translator, type Translate } from "./i18n";
import { setLastLink } from "./link";
import {
  type ErrorCode,
  type MailRequest,
  type MailResponse,
  type ModelStatus,
  parseMailRequest,
  parseRequest,
  type Request,
  type Response,
} from "./messages";
import { getSettings, isSettingsChange, type Settings, serverPermissionPattern, updateSettings } from "./settings";
import {
  addToAllowlist,
  allowlistKey,
  cacheKey,
  getAllowlist,
  getCached,
  isAllowlisted,
  putCached,
  removeFromAllowlist,
} from "./storage";
import {
  checkForModelUpdate,
  clearStoredModel,
  getUpdateState,
  loadStoredModel,
  UPDATE_ORIGINS,
  type UpdateContext,
  updatesAllowed,
} from "./updates";

// Injectés par build.mjs : chemin du modèle dans le paquet et empreinte vérifiée au build ;
// publication signée de ce modèle et clé publique Ed25519 de confiance (étape 6.8).
declare const __MODEL_PATH__: string;
declare const __MODEL_SHA256__: string;
declare const __MODEL_RELEASE__: string;
declare const __MODEL_PUBLIC_KEY__: string;

const CONTEXT_MENU_ID = "phishguard-analyze-link";
const MEMORY_CACHE_SIZE = 50;
const GMAIL_ORIGIN = "https://mail.google.com";

class ModelUnavailableError extends Error {
  override name = "ModelUnavailableError";
}

const currentTranslator = async (): Promise<Translate> =>
  translator(resolveLanguage((await getSettings()).language));

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

const parseModel = (bytes: Uint8Array | ArrayBuffer): UrlModel =>
  loadUrlModel(JSON.parse(new TextDecoder().decode(bytes)));

const updateContext: UpdateContext = {
  anchor: trustAnchorFromBase64(__MODEL_PUBLIC_KEY__),
  bundledRelease: __MODEL_RELEASE__,
  validateModel: (bytes) => void parseModel(bytes),
};

/** Origine du modèle en service, pour la page d'options. */
let modelSource: { source: "bundled" | "update"; release: string } | null = null;

async function loadAnalyzer(): Promise<UrlAnalyzer> {
  // Modèle reçu par mise à jour, revérifié en entier à chaque chargement (étape 6.8).
  // Seulement si l'option est toujours active : la désactiver revient au modèle du paquet.
  if ((await getSettings()).modelUpdates) {
    const update = await loadStoredModel(updateContext);
    if (update !== null) {
      const analyzer = new UrlAnalyzer(parseModel(update.model));
      modelSource = { source: "update", release: update.release };
      return analyzer;
    }
  }
  if (!__MODEL_SHA256__) throw new ModelUnavailableError("extension construite sans modèle");
  const response = await fetch(chrome.runtime.getURL(__MODEL_PATH__));
  if (!response.ok) throw new ModelUnavailableError("modèle introuvable dans le paquet");
  const bytes = await response.arrayBuffer();
  // Défense en profondeur : le build a vérifié la signature du manifeste ; ici, on
  // vérifie que le fichier lu est bien celui-là (dossier non empaqueté modifié, etc.).
  if ((await sha256Hex(bytes)) !== __MODEL_SHA256__) {
    throw new ModelUnavailableError("empreinte du modèle inattendue");
  }
  const analyzer = new UrlAnalyzer(parseModel(bytes));
  modelSource = { source: "bundled", release: __MODEL_RELEASE__ };
  return analyzer;
}

/** Le prochain appel recharge le modèle (nouvelle publication, option désactivée). */
function resetAnalyzer(): void {
  analyzerPromise = null;
  modelSource = null;
  memoryCache.clear();
}

async function modelStatus(settings: Settings): Promise<ModelStatus> {
  let modelVersion: string | null = null;
  try {
    modelVersion = (await getAnalyzer()).model.modelVersion;
  } catch {
    // Aucun modèle utilisable : l'état le dit (source « none »).
  }
  return {
    modelVersion,
    release: modelSource?.release ?? "",
    source: modelSource?.source ?? "none",
    updatesAvailable: updateContext.anchor !== null,
    lastCheck: settings.modelUpdates ? await getUpdateState() : null,
  };
}

/** Vérification planifiée (démarrage du navigateur, installation) : au plus une par jour. */
async function scheduledUpdateCheck(): Promise<void> {
  const settings = await getSettings();
  if (!(await updatesAllowed(settings))) return;
  const outcome = await checkForModelUpdate(settings, updateContext);
  if (outcome.result === "updated") resetAnalyzer();
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

/**
 * Analyse une URL puis applique la liste blanche.
 *
 * `persist: false` (analyse automatique) : ni cache de session ni cache mémoire, pour ne
 * garder aucune trace des pages visitées sans que l'utilisateur l'ait demandé.
 */
export async function analyzeUrl(url: string, { persist = true } = {}): Promise<Analysis> {
  const analyzer = await getAnalyzer();
  let local: LocalScore | null | undefined;
  if (persist) {
    const key = await cacheKey(url, analyzer.model.modelVersion);
    local = memoryCache.get(key) ?? (await getCached(key));
    if (local === null || local === undefined) {
      local = analyzer.score(url); // lève InvalidUrlError pour chrome://, file://…
      await putCached(key, local);
    }
    remember(key, local);
  } else {
    local = analyzer.score(url);
  }
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

export async function showVerdict(tabId: number, analysis: Analysis, verdict: Verdict = analysis.verdict): Promise<void> {
  const badge = BADGE[verdict];
  const t = await currentTranslator();
  await Promise.all([
    chrome.action.setBadgeText({ tabId, text: badge.text }),
    chrome.action.setBadgeBackgroundColor({ tabId, color: badge.color }),
    chrome.action.setBadgeTextColor({ tabId, color: "#ffffff" }),
    chrome.action.setTitle({ tabId, title: t(badge.title, analysis.host || "?") }),
  ]);
}

async function clearVerdict(tabId: number): Promise<void> {
  try {
    const t = await currentTranslator();
    await Promise.all([
      chrome.action.setBadgeText({ tabId, text: "" }),
      chrome.action.setTitle({ tabId, title: t("actionTitle") }),
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

/**
 * Analyse automatique (option, étape 5.7) : seulement si l'utilisateur l'a activée **et**
 * a accordé la permission `tabs` (sans elle, Chrome ne donne pas `tab.url`). Toujours
 * locale : jamais d'analyse en ligne pour une page que l'utilisateur n'a pas désignée.
 */
async function autoAnalyze(tabId: number, url: string | undefined): Promise<void> {
  if (!url) return;
  const settings = await getSettings();
  if (!settings.autoAnalyze || !(await chrome.permissions.contains({ permissions: ["tabs"] }))) return;
  try {
    await showVerdict(tabId, await analyzeUrl(url, { persist: false }));
  } catch {
    // chrome://, modèle absent… : le badge reste vide.
  }
}

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete") {
    void autoAnalyze(tabId, tab.url);
    return;
  }
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
  if (error instanceof NetworkDisabledError) return "network-disabled";
  if (error instanceof RemoteError) return "remote-failed";
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

/** Domaine qu'on peut signaler à l'API : un nom de domaine enregistré, ni IP ni URL. */
function reportableDomain(domain: string): string | null {
  try {
    const registered = allowlistKey(domain);
    return registered === domain && ipVersion(domain) === null && domain.includes(".") ? domain : null;
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
        const settings = await getSettings();
        return { ok: true, analysis, elapsedMs, online: settings.enrichment };
      } catch (error) {
        await clearVerdict(request.tabId);
        return { ok: false, error: errorCode(error) };
      }
    }
    case "analyze-tab-online": {
      const url = await tabUrl(request.tabId);
      if (url === null) return { ok: false, error: "no-access" };
      try {
        const settings = await getSettings();
        const local = await analyzeUrl(url);
        const remote = await analyzeOnline(settings, url, resolveLanguage(settings.language));
        // Le serveur peut alerter davantage, jamais rassurer davantage.
        const verdict = strictest(local.verdict, remote.verdict);
        await showVerdict(request.tabId, local, verdict);
        return { ok: true, remote, verdict };
      } catch (error) {
        return { ok: false, error: errorCode(error) };
      }
    }
    case "allowlist-add-tab": {
      const url = await tabUrl(request.tabId);
      if (url === null) return { ok: false, error: "no-access" };
      return addDomain(url);
    }
    case "allowlist-add-domain":
      return addDomain(request.domain);
    case "allowlist-remove":
      await removeFromAllowlist(request.domain);
      return { ok: true };
    case "allowlist-get":
      return { ok: true, domains: await getAllowlist() };
    case "model-status":
      return { ok: true, model: await modelStatus(await getSettings()) };
    case "model-update-check": {
      const settings = await getSettings();
      const outcome = await checkForModelUpdate(settings, updateContext, { force: true });
      if (outcome.result === "updated") resetAnalyzer();
      return { ok: true, model: await modelStatus(settings), outcome };
    }
    case "feedback": {
      const domain = reportableDomain(request.domain);
      if (domain === null) return { ok: false, error: "not-reportable" };
      try {
        await sendFeedback(await getSettings(), domain, request.verdict, request.judgement);
        return { ok: true, domain };
      } catch (error) {
        return { ok: false, error: errorCode(error) };
      }
    }
  }
}

async function addDomain(input: string): Promise<Response> {
  try {
    return { ok: true, domain: await addToAllowlist(input) };
  } catch (error) {
    if (error instanceof InvalidUrlError) return { ok: false, error: "invalid-domain" };
    if (error instanceof RangeError) return { ok: false, error: "allowlist-full" };
    return { ok: false, error: errorCode(error) };
  }
}

// --------------------------------------------------------------------------- //
// Message ouvert dans Gmail (étape 5.6)
// --------------------------------------------------------------------------- //

/**
 * Liens du message ouvert. Rien n'est mis en cache ni conservé ; aucune analyse en ligne,
 * quel que soit le réglage : le contenu d'un email ne quitte jamais l'appareil.
 */
async function handleMail(request: MailRequest): Promise<MailResponse> {
  const settings = await getSettings();
  if (!settings.gmail) return { ok: false, error: "disabled" };
  try {
    const analyzer = await getAnalyzer();
    const allowlist = new Set(await getAllowlist());
    const result = inspectMail(analyzer, request.links, request.sender, (d) => allowlist.has(d));
    return { ok: true, language: resolveLanguage(settings.language), ...result };
  } catch (error) {
    return { ok: false, error: errorCode(error) };
  }
}

const EXTENSION_ORIGIN = new URL(chrome.runtime.getURL("")).origin;

function senderOrigin(sender: chrome.runtime.MessageSender): string | null {
  if (sender.origin) return sender.origin;
  try {
    return sender.url ? new URL(sender.url).origin : null;
  } catch {
    return null;
  }
}

/**
 * Vrai pour une page de l'extension elle-même (fenêtre contextuelle, page d'options, même
 * ouverte dans un onglet). Un script de contenu a le même `sender.id` que l'extension mais
 * l'origine de la page web où il tourne : c'est l'origine qui les distingue.
 */
function fromExtensionPage(sender: chrome.runtime.MessageSender): boolean {
  return sender.id === chrome.runtime.id && senderOrigin(sender) === EXTENSION_ORIGIN;
}

/** Vrai pour notre script de contenu, dans le cadre principal d'un onglet Gmail. */
function fromGmail(sender: chrome.runtime.MessageSender): boolean {
  return (
    sender.id === chrome.runtime.id &&
    sender.tab !== undefined &&
    sender.frameId === 0 &&
    senderOrigin(sender) === GMAIL_ORIGIN
  );
}

chrome.runtime.onMessage.addListener((message: unknown, sender, sendResponse) => {
  const fail = () => sendResponse({ ok: false, error: "internal" } satisfies Response);
  if (fromExtensionPage(sender)) {
    const request = parseRequest(message);
    if (request !== null) {
      handle(request).then(sendResponse, fail);
      return true; // réponse asynchrone
    }
  } else if (fromGmail(sender)) {
    const request = parseMailRequest(message);
    if (request !== null) {
      handleMail(request).then(sendResponse, fail);
      return true;
    }
  }
  sendResponse({ ok: false, error: "bad-request" } satisfies Response);
  return false;
});

// --------------------------------------------------------------------------- //
// Permissions retirées par l'utilisateur (chrome://extensions) : réglages alignés
// --------------------------------------------------------------------------- //

chrome.permissions.onRemoved.addListener((removed) => {
  void (async () => {
    const settings = await getSettings();
    const patch: Parameters<typeof updateSettings>[0] = {};
    if (removed.permissions?.includes("tabs")) patch.autoAnalyze = false;
    if (settings.serverUrl && removed.origins?.includes(serverPermissionPattern(settings.serverUrl))) {
      patch.enrichment = false;
      patch.feedback = false;
    }
    if (settings.modelUpdates && removed.origins?.some((origin) => UPDATE_ORIGINS.includes(origin))) {
      patch.modelUpdates = false;
    }
    if (Object.keys(patch).length > 0) await updateSettings(patch);
  })();
});

// --------------------------------------------------------------------------- //
// Menu contextuel : « Analyser ce lien avec PhishGuard »
// --------------------------------------------------------------------------- //

async function createContextMenu(): Promise<void> {
  const t = await currentTranslator();
  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({ id: CONTEXT_MENU_ID, title: t("contextMenuAnalyzeLink"), contexts: ["link"] });
  });
}

chrome.runtime.onInstalled.addListener(() => {
  void createContextMenu();
  void scheduledUpdateCheck();
});

chrome.runtime.onStartup.addListener(() => {
  void scheduledUpdateCheck();
});

// Langue changée dans les options : le menu suit. Mises à jour désactivées : le modèle
// reçu est effacé et l'extension revient à celui de son paquet.
chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== "local" || !isSettingsChange(changes)) return;
  void createContextMenu();
  void (async () => {
    if (!(await getSettings()).modelUpdates && modelSource?.source !== "bundled") {
      await clearStoredModel();
      resetAnalyzer();
    }
  })();
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
        registeredDomain: analysis.registeredDomain,
        verdict: analysis.verdict,
        score: analysis.score,
        reasons: analysis.reasons,
        hardRule: analysis.hardRule,
      };
    } catch (error) {
      result = { host: "", registeredDomain: "", verdict: errorCode(error), score: 0, reasons: [], hardRule: null };
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
