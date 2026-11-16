/**
 * Bannière et marques de liens dans Gmail (étape 5.6), dans un **Shadow DOM fermé** :
 *
 * - le style de Gmail ne s'applique pas à la bannière, ni le nôtre à Gmail ;
 * - les scripts de la page ne peuvent pas atteindre son contenu par `shadowRoot`.
 *
 * Règle de sécurité : tout texte (texte des liens, hôtes, venus de l'email, donc de
 * l'attaquant) est inséré avec `textContent`, jamais `innerHTML`. Rien ici ne lit le
 * contenu de l'email : on reçoit des verdicts déjà calculés.
 *
 * La bannière est dans le flux de la page (pas de calque) et se masque d'un clic : elle
 * ne bloque jamais l'interface.
 */

import type { Verdict } from "../core/analyze";
import type { LinkReason, SenderReason } from "../core/inspect";
import type { Translate } from "../i18n";

/** Palette fixe (les thèmes de Gmail ne suivent pas le système) ; contrastes testés (WCAG AA). */
export const BANNER_COLORS = {
  suspicious: { background: "#fff4e5", border: "#a35400", text: "#3d1f00", accent: "#7a3e00" },
  phishing: { background: "#fdecea", border: "#c62828", text: "#3f0909", accent: "#8e1b1b" },
  button: { background: "#ffffff", text: "#1b1b1f", border: "#55555f" },
  focus: "#1f4fd1",
} as const;

const C = BANNER_COLORS;

const CSS = `
:host { all: initial; display: block; }
.banner {
  box-sizing: border-box;
  margin: 8px 0 12px;
  padding: 10px 14px;
  border-inline-start: 5px solid var(--border);
  border-radius: 6px;
  background: var(--background);
  color: var(--text);
  font: 14px/1.45 system-ui, -apple-system, "Segoe UI", Roboto, "Noto Sans Arabic", sans-serif;
}
.suspicious { --background: ${C.suspicious.background}; --border: ${C.suspicious.border}; --text: ${C.suspicious.text}; --accent: ${C.suspicious.accent}; }
.phishing { --background: ${C.phishing.background}; --border: ${C.phishing.border}; --text: ${C.phishing.text}; --accent: ${C.phishing.accent}; }
.head { display: flex; gap: 8px; align-items: flex-start; }
.icon { font-size: 18px; line-height: 1.2; }
.title { flex: 1; margin: 0; font-size: 15px; font-weight: 650; color: var(--accent); }
ul { margin: 6px 0 0; padding-inline-start: 22px; }
li { margin: 3px 0; overflow-wrap: anywhere; }
.shown { font-style: italic; unicode-bidi: plaintext; }
.host { font-weight: 600; unicode-bidi: plaintext; }
.why { display: block; font-size: 13px; }
.advice, .note { margin: 8px 0 0; }
.note { font-size: 13px; }
button {
  font: inherit; font-size: 13px; cursor: pointer;
  padding: 3px 10px; border-radius: 4px;
  border: 1px solid ${C.button.border}; background: ${C.button.background}; color: ${C.button.text};
}
button:focus-visible { outline: 3px solid ${C.focus}; outline-offset: 2px; }
@media (forced-colors: active) { .banner { border: 2px solid CanvasText; } }
`;

const MARK_CSS = `
:host { all: initial; display: inline; }
span { font: 13px/1 system-ui, sans-serif; margin-inline-start: 3px; cursor: help; }
.suspicious { color: ${C.suspicious.border}; }
.phishing { color: ${C.phishing.border}; }
`;

let sheets: { banner: CSSStyleSheet; mark: CSSStyleSheet } | null = null;
function styles() {
  // Feuilles construites : non soumises à la CSP de Gmail, partagées par tous les ombres.
  if (sheets === null) {
    const banner = new CSSStyleSheet();
    banner.replaceSync(CSS);
    const mark = new CSSStyleSheet();
    mark.replaceSync(MARK_CSS);
    sheets = { banner, mark };
  }
  return sheets;
}

const ICONS: Readonly<Record<Verdict, string>> = { safe: "✓", suspicious: "⚠", phishing: "⛔" };
const MAX_LISTED_LINKS = 5;
const MAX_SHOWN_CHARS = 80;

function el<K extends keyof HTMLElementTagNameMap>(tag: K, text?: string, className?: string) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className !== undefined) node.className = className;
  return node;
}

const shorten = (text: string) => (text.length > MAX_SHOWN_CHARS ? `${text.slice(0, MAX_SHOWN_CHARS - 1)}…` : text);

export interface FlaggedLink {
  text: string;
  host: string;
  verdict: Verdict;
  reasons: LinkReason[];
}

export interface BannerContent {
  verdict: Exclude<Verdict, "safe">;
  flagged: FlaggedLink[];
  sender: SenderReason[];
  truncated: boolean;
}

/** Hôte de la bannière, à insérer juste avant le corps du message. */
export function createBanner(content: BannerContent, t: Translate, onDismiss: () => void): HTMLElement {
  const host = document.createElement("phishguard-banner");
  const root = host.attachShadow({ mode: "closed" });
  root.adoptedStyleSheets = [styles().banner];

  const banner = el("div", undefined, `banner ${content.verdict}`);
  banner.dir = t.dir;
  banner.lang = t.language;
  // Phishing : annoncé immédiatement ; suspect : annoncé sans interrompre.
  banner.setAttribute("role", content.verdict === "phishing" ? "alert" : "status");

  const head = el("div", undefined, "head");
  const icon = el("span", ICONS[content.verdict], "icon");
  icon.setAttribute("aria-hidden", "true");
  const n = content.flagged.length;
  const title =
    n > 0
      ? t.plural(content.verdict === "phishing" ? "gmailTitlePhishing" : "gmailTitleSuspicious", n)
      : t(content.verdict === "phishing" ? "gmailTitleSenderPhishing" : "gmailTitleSenderSuspicious");
  const heading = el("p", title, "title");
  const dismiss = el("button", t("gmailDismiss"));
  dismiss.type = "button";
  dismiss.setAttribute("aria-label", t("gmailDismissLabel"));
  dismiss.addEventListener("click", () => {
    host.remove();
    onDismiss();
  });
  head.append(icon, heading, dismiss);
  banner.append(head);

  if (content.sender.length > 0) {
    const list = el("ul");
    for (const reason of content.sender) list.append(el("li", t(`reason_${reason}`)));
    banner.append(list);
  }

  if (n > 0) {
    const list = el("ul");
    for (const link of content.flagged.slice(0, MAX_LISTED_LINKS)) {
      const item = el("li");
      if (link.text) item.append(el("span", `« ${shorten(link.text)} »`, "shown"), " ");
      if (link.host) item.append(t("gmailLeadsTo"), " ", el("span", link.host, "host"));
      const why = link.reasons.map((r) => t(`reason_${r}`)).join(" ");
      if (why) item.append(el("span", why, "why"));
      list.append(item);
    }
    if (n > MAX_LISTED_LINKS) list.append(el("li", t.plural("gmailMoreLinks", n - MAX_LISTED_LINKS)));
    banner.append(list);
  }

  banner.append(el("p", t(`advice_email_${content.verdict}`), "advice"));
  if (content.truncated) banner.append(el("p", t("gmailTruncated"), "note"));
  root.append(banner);
  return host;
}

/** Marque placée juste après un lien suspect (icône + texte pour les lecteurs d'écran). */
export function createMark(verdict: Exclude<Verdict, "safe">, reasons: readonly LinkReason[], t: Translate): HTMLElement {
  const host = document.createElement("phishguard-mark");
  const root = host.attachShadow({ mode: "closed" });
  root.adoptedStyleSheets = [styles().mark];
  const mark = el("span", ICONS[verdict], verdict);
  const label = t(verdict === "phishing" ? "gmailMarkPhishing" : "gmailMarkSuspicious");
  mark.setAttribute("role", "img");
  mark.setAttribute("aria-label", label);
  mark.title = [label, ...reasons.map((r) => t(`reason_${r}`))].join("\n");
  mark.lang = t.language;
  root.append(mark);
  return host;
}
