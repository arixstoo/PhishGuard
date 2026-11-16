/**
 * Fenêtre contextuelle minimale (étapes 5.2 et 5.4) : verdict de l'onglet actif ou du
 * dernier lien analysé par le menu contextuel. L'interface complète (conseil d'action,
 * détails techniques, signalement, liste blanche) est l'étape 5.5.
 *
 * Règle de sécurité : tout texte est inséré avec `textContent`, jamais `innerHTML`. Un
 * nom d'hôte est une donnée contrôlée par l'attaquant.
 */

import type { Analysis, ReasonCode, Verdict } from "../core/analyze";
import type { Response } from "../messages";
import { type LinkAnalysis, takeLastLink } from "../link";

const t = (key: string, substitutions?: string | string[]) =>
  chrome.i18n.getMessage(key, substitutions) || key;

const ICONS: Readonly<Record<Verdict, string>> = { safe: "✓", suspicious: "⚠", phishing: "⛔" };
const VERDICT_KEYS: Readonly<Record<Verdict, string>> = {
  safe: "verdictSafe",
  suspicious: "verdictSuspicious",
  phishing: "verdictPhishing",
};
const ERROR_KEYS: Readonly<Record<string, string>> = {
  "not-analyzable": "errorNotAnalyzable",
  "no-access": "errorNoAccess",
  "model-unavailable": "errorModelUnavailable",
};

function el<K extends keyof HTMLElementTagNameMap>(tag: K, text?: string, className?: string) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className !== undefined) node.className = className;
  return node;
}

function localize(): void {
  document.documentElement.lang = chrome.i18n.getUILanguage();
  document.documentElement.dir = chrome.i18n.getMessage("@@bidi_dir") || "ltr";
  for (const node of document.querySelectorAll<HTMLElement>("[data-i18n]")) {
    node.textContent = t(node.dataset["i18n"]!);
  }
}

function render(nodes: Node[]): void {
  document.getElementById("result")!.replaceChildren(...nodes);
}

function renderVerdict(
  verdict: Verdict,
  host: string,
  reasons: readonly string[],
  heading?: string,
): Node[] {
  const nodes: Node[] = [];
  if (heading) nodes.push(el("p", heading, "meta"));
  const line = el("p", undefined, `verdict verdict-${verdict}`);
  const icon = el("span", ICONS[verdict], "icon");
  icon.setAttribute("aria-hidden", "true"); // le texte du verdict suffit au lecteur d'écran
  line.append(icon, el("span", t(VERDICT_KEYS[verdict])));
  nodes.push(line);
  if (host) nodes.push(el("p", host, "host"));
  if (reasons.length) {
    const list = el("ul");
    for (const reason of reasons) list.append(el("li", t(`reason_${reason as ReasonCode}`)));
    nodes.push(list);
  }
  return nodes;
}

const renderError = (code: string) => [el("p", t(ERROR_KEYS[code] ?? "errorInternal"))];

function renderLink(link: LinkAnalysis): Node[] {
  if (!(link.verdict in VERDICT_KEYS)) return [el("p", t("popupLinkResult"), "meta"), ...renderError(link.verdict)];
  return renderVerdict(link.verdict as Verdict, link.host, link.reasons, t("popupLinkResult"));
}

function renderAnalysis(analysis: Analysis, elapsedMs: number): Node[] {
  const nodes = renderVerdict(analysis.verdict, analysis.host, analysis.reasons);
  nodes.push(el("p", t("popupMeta", [String(analysis.score), elapsedMs.toFixed(1), analysis.modelVersion]), "meta"));
  return nodes;
}

async function main(): Promise<void> {
  localize();
  const link = await takeLastLink();
  if (link !== null) {
    render(renderLink(link));
    return;
  }
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tab?.id === undefined) {
    render(renderError("no-access"));
    return;
  }
  const response = (await chrome.runtime.sendMessage({ type: "analyze-tab", tabId: tab.id })) as Response;
  if (!response.ok) render(renderError(response.error));
  else if ("analysis" in response) render(renderAnalysis(response.analysis, response.elapsedMs));
}

main().catch(() => render(renderError("internal")));
