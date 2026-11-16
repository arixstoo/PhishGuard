/**
 * Page d'options (étape 5.7).
 *
 * Chaque réglage dit **quelles données partent où**. Ceux qui élargissent l'accès de
 * l'extension demandent la permission au moment du clic (`chrome.permissions.request`,
 * qui exige un geste de l'utilisateur) et la rendent quand on les désactive :
 *
 * | Réglage               | Permission demandée          | Par défaut |
 * |-----------------------|------------------------------|------------|
 * | analyse automatique   | `tabs`                       | non        |
 * | analyse en ligne      | hôte du serveur choisi       | non        |
 * | signalements          | hôte du serveur choisi       | non        |
 *
 * Règle de sécurité : tout texte est inséré avec `textContent`.
 */

import { localizePage, resolveLanguage, type Translate, translator } from "../i18n";
import type { Response } from "../messages";
import {
  API_KEY_RE,
  getSettings,
  parseServerUrl,
  serverPermissionPattern,
  type Settings,
  updateSettings,
} from "../settings";

let settings: Settings;
let t: Translate;

const $ = <T extends HTMLElement = HTMLElement>(id: string) => document.getElementById(id) as T;
const checkbox = (id: string) => $<HTMLInputElement>(id);

function say(id: string, text: string): void {
  const region = $(id);
  region.textContent = "";
  requestAnimationFrame(() => {
    region.textContent = text;
  });
}

function fieldError(input: HTMLInputElement, errorId: string, message: string | null): void {
  const error = $(errorId);
  error.textContent = message ?? "";
  error.hidden = message === null;
  input.setAttribute("aria-invalid", String(message !== null));
}

const send = (request: unknown) => chrome.runtime.sendMessage(request) as Promise<Response>;
const serverHost = () => (settings.serverUrl ? new URL(settings.serverUrl).host : t("optYourServer"));

// --------------------------------------------------------------------------- //
// Affichage
// --------------------------------------------------------------------------- //

function renderSettings(): void {
  ($<HTMLSelectElement>("language")).value = settings.language;
  checkbox("gmail").checked = settings.gmail;
  checkbox("auto").checked = settings.autoAnalyze;
  checkbox("enrichment").checked = settings.enrichment;
  checkbox("feedback").checked = settings.feedback;
  $<HTMLInputElement>("server").value = settings.serverUrl;
  $<HTMLInputElement>("api-key").value = settings.apiKey;
  // Sans serveur enregistré, rien ne peut partir : les deux cases sont inactives.
  checkbox("enrichment").disabled = !settings.serverUrl;
  checkbox("feedback").disabled = !settings.serverUrl;
  $("enrichment-help").textContent = t("optEnrichmentHelp", serverHost());
  $("feedback-help").textContent = t("optFeedbackHelp", serverHost());
}

async function renderAllowlist(): Promise<void> {
  const response = await send({ type: "allowlist-get" });
  const list = $("allowlist");
  const domains = response.ok && "domains" in response ? response.domains : [];
  if (domains.length === 0) {
    const empty = document.createElement("li");
    empty.className = "empty";
    empty.textContent = t("optAllowlistEmpty");
    list.replaceChildren(empty);
    return;
  }
  list.replaceChildren(
    ...domains.map((domain) => {
      const item = document.createElement("li");
      const name = document.createElement("span");
      name.className = "bidi";
      name.textContent = domain;
      const remove = document.createElement("button");
      remove.type = "button";
      remove.textContent = t("optAllowlistRemove");
      remove.setAttribute("aria-label", t("optAllowlistRemoveLabel", domain));
      remove.addEventListener("click", () => void removeDomain(domain, item));
      item.append(name, remove);
      return item;
    }),
  );
}

function localize(): void {
  t = translator(resolveLanguage(settings.language));
  localizePage(t);
  renderSettings();
  void renderAllowlist();
}

// --------------------------------------------------------------------------- //
// Réglages
// --------------------------------------------------------------------------- //

async function setLanguage(value: string): Promise<void> {
  settings = await updateSettings({ language: value as Settings["language"] });
  localize();
  say("local-status", t("optSaved"));
}

async function setGmail(enabled: boolean): Promise<void> {
  settings = await updateSettings({ gmail: enabled });
  say("local-status", t(enabled ? "optGmailOn" : "optGmailOff"));
}

/** Analyse automatique : la permission `tabs` est demandée ici, rendue à la désactivation. */
function setAuto(input: HTMLInputElement): void {
  if (input.checked) {
    // Appel direct dans le gestionnaire du clic : Chrome exige un geste de l'utilisateur.
    chrome.permissions.request({ permissions: ["tabs"] }).then(
      async (granted) => {
        input.checked = granted;
        settings = await updateSettings({ autoAnalyze: granted });
        say("local-status", t(granted ? "optAutoOn" : "optPermissionDenied"));
      },
      () => {
        input.checked = false;
        say("local-status", t("optPermissionDenied"));
      },
    );
    return;
  }
  void (async () => {
    settings = await updateSettings({ autoAnalyze: false });
    await chrome.permissions.remove({ permissions: ["tabs"] }).catch(() => false);
    say("local-status", t("optAutoOff"));
  })();
}

/** Analyse en ligne ou signalements : permission de l'hôte du serveur, et de lui seul. */
function setNetwork(input: HTMLInputElement, key: "enrichment" | "feedback"): void {
  if (!settings.serverUrl) {
    input.checked = false;
    say("online-status", t("optNeedServer"));
    return;
  }
  const origins = [serverPermissionPattern(settings.serverUrl)];
  if (input.checked) {
    chrome.permissions.request({ origins }).then(
      async (granted) => {
        input.checked = granted;
        settings = await updateSettings({ [key]: granted });
        say("online-status", granted ? t(`opt_${key}_on`, serverHost()) : t("optPermissionDenied"));
      },
      () => {
        input.checked = false;
        say("online-status", t("optPermissionDenied"));
      },
    );
    return;
  }
  void (async () => {
    settings = await updateSettings({ [key]: false });
    // Plus aucun usage de ce serveur : la permission est rendue.
    if (!settings.enrichment && !settings.feedback) await chrome.permissions.remove({ origins }).catch(() => false);
    say("online-status", t(`opt_${key}_off`));
  })();
}

async function saveServer(event: SubmitEvent): Promise<void> {
  event.preventDefault();
  const serverInput = $<HTMLInputElement>("server");
  const keyInput = $<HTMLInputElement>("api-key");
  const raw = serverInput.value.trim();
  const serverUrl = raw === "" ? "" : parseServerUrl(raw);
  const apiKey = keyInput.value.trim();
  fieldError(serverInput, "server-error", serverUrl === null ? t("optServerInvalid") : null);
  const keyValid = apiKey === "" || API_KEY_RE.test(apiKey);
  fieldError(keyInput, "api-key-error", keyValid ? null : t("optApiKeyInvalid"));
  if (serverUrl === null) {
    serverInput.focus();
    return;
  }
  if (!keyValid) {
    keyInput.focus();
    return;
  }
  const previous = settings.serverUrl;
  const changed = serverUrl !== previous;
  if (changed && previous) {
    // Nouveau serveur : l'ancien perd sa permission, et les envois repartent désactivés.
    const old = serverPermissionPattern(previous);
    if (!serverUrl || serverPermissionPattern(serverUrl) !== old) {
      await chrome.permissions.remove({ origins: [old] }).catch(() => false);
    }
  }
  settings = await updateSettings({
    serverUrl,
    apiKey,
    ...(changed ? { enrichment: false, feedback: false } : {}),
  });
  renderSettings();
  say("online-status", t(serverUrl ? (changed ? "optServerSavedOff" : "optSaved") : "optServerCleared"));
}

// --------------------------------------------------------------------------- //
// Liste blanche
// --------------------------------------------------------------------------- //

async function addDomain(event: SubmitEvent): Promise<void> {
  event.preventDefault();
  const input = $<HTMLInputElement>("allowlist-input");
  const value = input.value.trim();
  if (!value) return;
  const response = await send({ type: "allowlist-add-domain", domain: value });
  if (!response.ok) {
    const key = response.error === "allowlist-full" ? "errorAllowlistFull" : "optAllowlistInvalid";
    fieldError(input, "allowlist-error", t(key));
    input.focus();
    return;
  }
  fieldError(input, "allowlist-error", null);
  input.value = "";
  await renderAllowlist();
  if ("domain" in response) say("allowlist-status", t("optAllowlistAdded", response.domain));
}

async function removeDomain(domain: string, item: HTMLElement): Promise<void> {
  // Le focus va à l'élément suivant (ou au champ) : il ne se perd pas avec la ligne retirée.
  const next = (item.nextElementSibling ?? item.previousElementSibling)?.querySelector("button");
  await send({ type: "allowlist-remove", domain });
  await renderAllowlist();
  const target = next && document.contains(next) ? next : $("allowlist-input");
  target.focus();
  say("allowlist-status", t("optAllowlistRemoved", domain));
}

// --------------------------------------------------------------------------- //

async function main(): Promise<void> {
  settings = await getSettings();
  // Permissions retirées depuis chrome://extensions : la page reflète l'état réel.
  const [tabs, host] = await Promise.all([
    chrome.permissions.contains({ permissions: ["tabs"] }),
    settings.serverUrl ? chrome.permissions.contains({ origins: [serverPermissionPattern(settings.serverUrl)] }) : false,
  ]);
  if ((settings.autoAnalyze && !tabs) || ((settings.enrichment || settings.feedback) && !host)) {
    settings = await updateSettings({
      autoAnalyze: settings.autoAnalyze && tabs,
      enrichment: settings.enrichment && host,
      feedback: settings.feedback && host,
    });
  }
  localize();

  $<HTMLSelectElement>("language").addEventListener("change", (e) => void setLanguage((e.target as HTMLSelectElement).value));
  checkbox("gmail").addEventListener("change", (e) => void setGmail((e.target as HTMLInputElement).checked));
  checkbox("auto").addEventListener("change", (e) => setAuto(e.target as HTMLInputElement));
  checkbox("enrichment").addEventListener("change", (e) => setNetwork(e.target as HTMLInputElement, "enrichment"));
  checkbox("feedback").addEventListener("change", (e) => setNetwork(e.target as HTMLInputElement, "feedback"));
  $("server-form").addEventListener("submit", (e) => void saveServer(e as SubmitEvent));
  $("allowlist-form").addEventListener("submit", (e) => void addDomain(e as SubmitEvent));
}

void main();
