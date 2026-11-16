/**
 * Fenêtre contextuelle (étape 5.5) : verdict de l'onglet actif, ou du dernier lien analysé
 * par le menu contextuel.
 *
 * - Verdict par **icône, couleur et texte**, une phrase d'explication, un conseil d'action
 *   (les conseils de l'API), les raisons ; « Détails techniques » replié par défaut.
 * - « Toujours faire confiance à ce site » (avec confirmation, plus appuyée si le verdict
 *   est phishing ; impossible si l'hôte imite des lettres latines : la règle passe avant
 *   la liste blanche) et « Signaler une erreur » (domaine seulement, si l'utilisateur a
 *   activé l'envoi dans les options).
 * - Clavier : boutons natifs, ordre naturel, Échap ferme un panneau et rend le focus au
 *   bouton qui l'a ouvert ; les résultats sont annoncés par une zone `role="status"`.
 *
 * Règle de sécurité : tout texte est inséré avec `textContent`, jamais `innerHTML`. Un
 * nom d'hôte est une donnée contrôlée par l'attaquant.
 */

import type { RemoteAnalysis } from "../api";
import type { Analysis, Verdict } from "../core/analyze";
import { localizePage, resolveLanguage, type Translate, translator } from "../i18n";
import { type LinkAnalysis, takeLastLink } from "../link";
import type { ErrorCode, Request, Response } from "../messages";
import { getSettings, type Settings } from "../settings";

const ICONS: Readonly<Record<Verdict, string>> = { safe: "✓", suspicious: "⚠", phishing: "⛔" };
const VERDICTS: readonly string[] = ["safe", "suspicious", "phishing"];

/** Ce que la fenêtre affiche : une page (onglet) ou un lien (menu contextuel). */
interface View {
  subject: { kind: "tab"; tabId: number } | { kind: "link" };
  verdict: Verdict;
  host: string;
  registeredDomain: string;
  score: number;
  reasons: string[];
  hardRule: string | null;
  analysis: Analysis | null;
  elapsedMs: number | null;
  online: "off" | "pending" | "failed" | RemoteAnalysis;
  /** Verdict après analyse en ligne (le plus prudent des deux). */
  combined: Verdict;
  /** Verdict d'origine d'un lien, pour revenir en arrière après « Ne plus faire confiance ». */
  original: { verdict: Verdict; score: number; hardRule: string | null };
}

let t: Translate;
let settings: Settings;
let view: View | null = null;
let detailsOpen = false;

// --------------------------------------------------------------------------- //
// Utilitaires DOM
// --------------------------------------------------------------------------- //

function el<K extends keyof HTMLElementTagNameMap>(tag: K, text?: string, className?: string) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className !== undefined) node.className = className;
  return node;
}

function button(label: string, onClick: () => void, className?: string): HTMLButtonElement {
  const b = el("button", label, className);
  b.type = "button";
  b.addEventListener("click", onClick);
  return b;
}

const result = () => document.getElementById("result")!;

function announce(text: string): void {
  const region = document.getElementById("announce")!;
  region.textContent = "";
  // Vider puis remplir au tour suivant : un même message est annoncé de nouveau.
  requestAnimationFrame(() => {
    region.textContent = text;
  });
}

const send = (request: Request) => chrome.runtime.sendMessage(request) as Promise<Response>;

function errorText(code: ErrorCode | string): string {
  const keys: Record<string, string> = {
    "not-analyzable": "errorNotAnalyzable",
    "no-access": "errorNoAccess",
    "model-unavailable": "errorModelUnavailable",
    "invalid-domain": "errorInvalidDomain",
    "allowlist-full": "errorAllowlistFull",
  };
  return t(keys[code] ?? "errorInternal");
}

const percent = (value: number) =>
  new Intl.NumberFormat(t.language, { style: "percent", maximumFractionDigits: 1 }).format(value);
const decimal = (value: number, digits: number) =>
  new Intl.NumberFormat(t.language, { maximumFractionDigits: digits }).format(value);

// --------------------------------------------------------------------------- //
// Rendu
// --------------------------------------------------------------------------- //

function explanation(v: View): string {
  if (v.hardRule === "allowlist") return t("explain_allowlist");
  if (v.hardRule === "lookalike_host") return t("explain_lookalike");
  if (v.hardRule === "url_too_long") return t("explain_url_too_long");
  return t(`explain_${v.verdict}`);
}

function renderCard(v: View): HTMLElement {
  const card = el("div", undefined, `card ${v.combined}`);
  if (v.subject.kind === "link") card.append(el("p", t("popupLinkResult"), "kicker"));
  const heading = el("h2", undefined, "verdict");
  heading.id = "verdict-title";
  heading.tabIndex = -1; // reçoit le focus après une action, sans entrer dans l'ordre de tabulation
  const icon = el("span", ICONS[v.combined], "icon");
  icon.setAttribute("aria-hidden", "true"); // le texte du verdict suffit au lecteur d'écran
  heading.append(icon, el("span", t(`verdict_${v.combined}`)));
  card.append(heading);
  if (v.host) {
    const host = el("p", v.host, "host bidi");
    host.lang = ""; // nom d'hôte : aucune langue
    card.append(host);
  }
  card.append(el("p", explanation(v)), el("p", t(`advice_url_${v.combined}`), "advice"));
  // Site de confiance : les raisons du modèle ne s'appliquent plus.
  if (v.reasons.length > 0 && v.hardRule !== "allowlist") {
    card.append(el("h3", t("popupReasonsTitle")));
    const list = el("ul");
    for (const reason of v.reasons) list.append(el("li", t(`reason_${reason}`)));
    card.append(list);
  }
  return card;
}

function renderOnline(v: View): HTMLElement | null {
  if (v.online === "off") return null;
  const box = el("section", undefined, "online");
  box.setAttribute("aria-labelledby", "online-title");
  const title = el("h2", t("popupOnlineTitle"));
  title.id = "online-title";
  box.append(title);
  if (v.online === "pending") box.append(el("p", t("popupOnlinePending")));
  else if (v.online === "failed") box.append(el("p", t("popupOnlineFailed")));
  else {
    const remote = v.online;
    box.append(el("p", t("popupOnlineResult", t(`verdict_${remote.verdict}`), remote.score)));
    if (remote.reasons.length > 0) {
      const list = el("ul");
      // Messages du serveur : texte brut, jamais interprété (textContent).
      for (const reason of remote.reasons) list.append(el("li", reason.message));
      box.append(list);
    }
    if (remote.verdict !== v.verdict) box.append(el("p", t("popupOnlineStrictest"), "meta"));
  }
  return box;
}

function detailRows(v: View): [string, string, boolean?][] {
  const rows: [string, string, boolean?][] = [[t("detailScore"), t("detailScoreValue", v.score)]];
  if (v.registeredDomain) rows.push([t("detailDomain"), v.registeredDomain, true]);
  const a = v.analysis;
  if (a !== null) {
    rows.push([t("detailProbability"), percent(a.probability)]);
    rows.push([t("detailRawScore"), decimal(a.rawScore, 4)]);
  }
  rows.push([t("detailRule"), v.hardRule ? t(`rule_${v.hardRule}`) : t("detailNone")]);
  if (a !== null) rows.push([t("detailModel"), a.modelVersion, true]);
  if (v.elapsedMs !== null) rows.push([t("detailDuration"), t("detailDurationValue", decimal(v.elapsedMs, 1))]);
  if (typeof v.online === "object") {
    rows.push([t("detailOnline"), t("popupOnlineResult", t(`verdict_${v.online.verdict}`), v.online.score)]);
    rows.push([t("detailOnlineModel"), v.online.modelVersion, true]);
  }
  return rows;
}

function renderDetails(v: View): HTMLElement {
  const wrap = el("div", undefined, "disclosure");
  const toggle = button(t("popupDetails"), () => {
    detailsOpen = !detailsOpen;
    toggle.setAttribute("aria-expanded", String(detailsOpen));
    panel.hidden = !detailsOpen;
  }, "link");
  toggle.setAttribute("aria-expanded", String(detailsOpen));
  toggle.setAttribute("aria-controls", "details");
  const panel = el("dl");
  panel.id = "details";
  panel.hidden = !detailsOpen;
  for (const [label, value, technical] of detailRows(v)) {
    const dd = el("dd", value, technical ? "bidi" : undefined);
    panel.append(el("dt", label), dd);
  }
  wrap.append(toggle, panel);
  return wrap;
}

function canTrust(v: View): boolean {
  return v.registeredDomain !== "" && v.hardRule !== "lookalike_host" && v.hardRule !== "allowlist" && v.hardRule !== "url_too_long";
}

function renderActions(v: View): HTMLElement {
  const actions = el("div", undefined, "actions");
  if (canTrust(v)) {
    const trust = button(t("popupTrust"), () => openTrustPanel(trust));
    actions.append(trust);
  } else if (v.hardRule === "allowlist") {
    actions.append(button(t("popupUntrust"), () => void untrust()));
  }
  if (v.hardRule !== "allowlist" && v.registeredDomain) {
    const report = button(t("popupReport"), () => openReportPanel(report));
    actions.append(report);
  }
  return actions;
}

function render(focusHeading = false): void {
  if (view === null) return;
  const nodes: Node[] = [renderCard(view)];
  const online = renderOnline(view);
  if (online) nodes.push(online);
  nodes.push(renderDetails(view), renderActions(view));
  result().replaceChildren(...nodes);
  if (focusHeading) document.getElementById("verdict-title")?.focus();
}

function renderError(code: ErrorCode | string, linkHeading = false): void {
  const nodes: Node[] = [];
  if (linkHeading) nodes.push(el("p", t("popupLinkResult"), "kicker"));
  nodes.push(el("p", errorText(code)));
  result().replaceChildren(...nodes);
  announce(errorText(code));
}

// --------------------------------------------------------------------------- //
// Panneaux : confiance et signalement
// --------------------------------------------------------------------------- //

/** Panneau à la place des actions ; Échap ou « Annuler » le referment et rendent le focus. */
function showPanel(panel: HTMLElement, opener: HTMLElement, initialFocus: HTMLElement): void {
  const actions = result().querySelector(".actions");
  if (!actions) return;
  panel.classList.add("panel");
  panel.setAttribute("role", "group");
  const close = () => {
    panel.replaceWith(actions);
    opener.focus();
  };
  panel.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      event.preventDefault();
      event.stopPropagation(); // ne pas fermer la fenêtre contextuelle elle-même
      close();
    }
  });
  panel.querySelectorAll<HTMLElement>("[data-cancel]").forEach((b) => b.addEventListener("click", close));
  actions.replaceWith(panel);
  initialFocus.focus();
}

function openTrustPanel(opener: HTMLElement): void {
  const v = view!;
  const panel = el("section");
  const title = el("h2", t("popupTrustConfirmTitle", v.registeredDomain));
  title.id = "trust-title";
  panel.setAttribute("aria-labelledby", "trust-title");
  panel.append(title, el("p", t("popupTrustConfirmBody")));
  if (v.combined !== "safe") panel.append(el("p", t(`popupTrustWarning_${v.combined}`), "warning"));
  const row = el("div", undefined, "actions");
  const confirm = button(t("popupConfirm"), () => void trust(), v.combined === "safe" ? "primary" : undefined);
  const cancel = button(t("popupCancel"), () => undefined, v.combined === "safe" ? undefined : "primary");
  cancel.dataset["cancel"] = "";
  row.append(confirm, cancel);
  panel.append(row);
  // Verdict inquiétant : le focus va sur « Annuler », pas sur la confirmation.
  showPanel(panel, opener, v.combined === "safe" ? confirm : cancel);
}

function openReportPanel(opener: HTMLElement): void {
  const v = view!;
  const panel = el("section");
  const title = el("h2", t("popupReportTitle"));
  title.id = "report-title";
  panel.setAttribute("aria-labelledby", "report-title");
  panel.append(title);
  const row = el("div", undefined, "actions");
  let first: HTMLElement;
  if (!settings.feedback) {
    panel.append(el("p", t("popupReportDisabled")));
    first = button(t("popupOpenOptions"), () => void chrome.runtime.openOptionsPage(), "primary");
    row.append(first);
  } else {
    const choices: ["false_positive" | "false_negative", string][] = [];
    if (v.verdict !== "safe") choices.push(["false_positive", t("popupReportFalsePositive")]);
    if (v.verdict !== "phishing") choices.push(["false_negative", t("popupReportFalseNegative")]);
    panel.append(el("p", t("popupReportPrivacy", v.registeredDomain)));
    const buttons = choices.map(([judgement, label]) => button(label, () => void report(judgement, panel)));
    row.append(...buttons);
    first = buttons[0]!;
  }
  const cancel = button(t("popupCancel"), () => undefined);
  cancel.dataset["cancel"] = "";
  row.append(cancel);
  panel.append(row);
  showPanel(panel, opener, first);
}

async function trust(): Promise<void> {
  const v = view!;
  const response =
    v.subject.kind === "tab"
      ? await send({ type: "allowlist-add-tab", tabId: v.subject.tabId })
      : await send({ type: "allowlist-add-domain", domain: v.registeredDomain });
  if (!response.ok) {
    announce(errorText(response.error));
    render(true);
    return;
  }
  await refresh();
  announce(t("popupTrusted", v.registeredDomain));
}

async function untrust(): Promise<void> {
  const v = view!;
  await send({ type: "allowlist-remove", domain: v.registeredDomain });
  await refresh();
  announce(t("popupUntrusted", v.registeredDomain));
}

async function report(judgement: "false_positive" | "false_negative", panel: HTMLElement): Promise<void> {
  const v = view!;
  const status = el("p", t("popupReportSending"));
  panel.querySelectorAll("button").forEach((b) => (b.disabled = true));
  panel.append(status);
  const response = await send({ type: "feedback", domain: v.registeredDomain, verdict: v.verdict, judgement });
  let message: string;
  if (response.ok) message = t("popupReportSent", v.registeredDomain, new URL(settings.serverUrl).host);
  else if (response.error === "not-reportable") message = t("popupReportNotReportable");
  else if (response.error === "network-disabled") message = t("popupReportDisabled");
  else message = t("popupReportFailed");
  status.textContent = message;
  panel.querySelectorAll<HTMLButtonElement>("[data-cancel]").forEach((b) => {
    b.disabled = false;
    b.textContent = t("popupClose");
    b.focus();
  });
  announce(message);
}

// --------------------------------------------------------------------------- //
// Analyse
// --------------------------------------------------------------------------- //

async function analyzeTab(tabId: number): Promise<View | null> {
  const response = await send({ type: "analyze-tab", tabId });
  if (!response.ok) {
    renderError(response.error);
    return null;
  }
  if (!("analysis" in response)) return null;
  const a = response.analysis;
  return {
    subject: { kind: "tab", tabId },
    verdict: a.verdict,
    combined: a.verdict,
    host: a.host,
    registeredDomain: a.registeredDomain,
    score: a.score,
    reasons: a.reasons,
    hardRule: a.hardRule,
    analysis: a,
    elapsedMs: response.elapsedMs,
    online: response.online ? "pending" : "off",
    original: { verdict: a.verdict, score: a.score, hardRule: a.hardRule },
  };
}

async function runOnline(v: View): Promise<void> {
  if (v.subject.kind !== "tab" || v.online !== "pending") return;
  const response = await send({ type: "analyze-tab-online", tabId: v.subject.tabId });
  if (view !== v) return; // une autre analyse a remplacé celle-ci
  if (response.ok && "remote" in response) {
    v.online = response.remote;
    v.combined = response.verdict;
  } else {
    v.online = "failed";
  }
  render();
  announce(typeof v.online === "object" ? t("popupOnlineAnnounce", t(`verdict_${v.combined}`)) : t("popupOnlineFailed"));
}

function linkView(link: LinkAnalysis): View | null {
  if (!VERDICTS.includes(link.verdict)) {
    renderError(link.verdict, true);
    return null;
  }
  return {
    subject: { kind: "link" },
    verdict: link.verdict as Verdict,
    combined: link.verdict as Verdict,
    host: link.host,
    registeredDomain: link.registeredDomain,
    score: link.score,
    reasons: link.reasons,
    hardRule: link.hardRule,
    analysis: null,
    elapsedMs: null,
    online: "off",
    original: { verdict: link.verdict as Verdict, score: link.score, hardRule: link.hardRule },
  };
}

/** Après un changement de liste blanche : nouvelle analyse (onglet) ou verdict local (lien). */
async function refresh(): Promise<void> {
  const v = view!;
  if (v.subject.kind === "tab") {
    const next = await analyzeTab(v.subject.tabId);
    if (next === null) return;
    view = next;
    render(true);
    void runOnline(next);
    return;
  }
  const domains = await send({ type: "allowlist-get" });
  const trusted = domains.ok && "domains" in domains && domains.domains.includes(v.registeredDomain);
  if (trusted) {
    view = { ...v, verdict: "safe", combined: "safe", score: 0, hardRule: "allowlist" };
  } else if (v.original.hardRule !== "allowlist") {
    view = { ...v, ...v.original, combined: v.original.verdict };
  } else {
    // Lien jugé sous la liste blanche : son verdict propre n'est pas connu, et l'URL n'est
    // pas conservée. Plutôt qu'un verdict inventé, on invite à l'analyser de nouveau.
    view = null;
    result().replaceChildren(el("p", t("popupLinkReanalyze")));
    return;
  }
  render(true);
}

async function main(): Promise<void> {
  settings = await getSettings();
  t = translator(resolveLanguage(settings.language));
  localizePage(t);
  document.getElementById("open-options")!.addEventListener("click", () => void chrome.runtime.openOptionsPage());

  const link = await takeLastLink();
  if (link !== null) {
    view = linkView(link);
  } else {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab?.id === undefined) {
      renderError("no-access");
      return;
    }
    view = await analyzeTab(tab.id);
  }
  if (view === null) return;
  render();
  announce(`${t(`verdict_${view.combined}`)}${view.host ? ` : ${view.host}` : ""}`);
  void runOnline(view);
}

main().catch(() => {
  t ??= translator(resolveLanguage("auto"));
  renderError("internal");
});
