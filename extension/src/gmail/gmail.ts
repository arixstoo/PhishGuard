/**
 * Script de contenu Gmail (étape 5.6) : analyse des liens **du message ouvert**.
 *
 * 1. Un `MutationObserver` signale les changements de la page ; on cherche alors les
 *    corps de message dépliés (`selectors.ts`). Gmail n'en crée que pour les messages
 *    ouverts : la liste des messages, les messages repliés et le reste de la boîte ne sont
 *    jamais lus.
 * 2. Pour chaque corps : liens (cible `href` et texte **tel qu'affiché**, `innerText`) et
 *    expéditeur, envoyés au service worker de l'extension. L'analyse se fait sur
 *    l'appareil ; rien n'est stocké ni envoyé ailleurs.
 * 3. Si un lien ou l'expéditeur est douteux : bannière avant le message et marque après
 *    chaque lien suspect (`banner.ts`, Shadow DOM, `textContent` seulement).
 *
 * Ce script tourne dans la page de Gmail : il ne fait confiance à rien de ce qu'il y lit
 * et n'a accès à rien d'autre qu'à cette analyse (voir `messages.ts`).
 */

import type { Verdict } from "../core/analyze";
import type { LinkInput } from "../core/inspect";
import { MAX_LINK_HREF_CHARS, MAX_LINK_TEXT_CHARS, MAX_MAIL_LINKS } from "../limits";
import { translator } from "../i18n";
import type { MailResponse } from "../messages";
import { type BannerContent, createBanner, createMark, type FlaggedLink } from "./banner";
import { GMAIL } from "./selectors";

const SCAN_DELAY_MS = 300;

interface Rendered {
  signature: string;
  nodes: Element[];
  dismissed: boolean;
}

/** État par corps de message ; disparaît avec lui (WeakMap). */
const rendered = new WeakMap<Element, Rendered>();
const pending = new WeakSet<Element>();
let stopped = false;
let rescan = false;
let timer: ReturnType<typeof setTimeout> | null = null;

/** Texte visible d'un lien : ce que l'utilisateur lit, pas le texte masqué par CSS. */
const shownText = (anchor: HTMLElement) => (anchor.innerText ?? anchor.textContent ?? "").slice(0, MAX_LINK_TEXT_CHARS);

function collect(body: Element) {
  const anchors = Array.from(body.querySelectorAll<HTMLAnchorElement>(GMAIL.link));
  // Liens identiques regroupés : une analyse par couple (cible, texte).
  const groups = new Map<string, { input: LinkInput; anchors: HTMLAnchorElement[] }>();
  for (const anchor of anchors) {
    const input = {
      href: (anchor.getAttribute("href") ?? "").slice(0, MAX_LINK_HREF_CHARS),
      text: shownText(anchor),
    };
    const key = `${input.href}\u0000${input.text}`;
    const group = groups.get(key);
    if (group) group.anchors.push(anchor);
    else groups.set(key, { input, anchors: [anchor] });
  }
  const all = Array.from(groups.values());
  return { groups: all.slice(0, MAX_MAIL_LINKS), truncated: all.length > MAX_MAIL_LINKS, count: anchors.length };
}

function senderOf(body: Element) {
  const message = body.closest(GMAIL.message);
  const sender = message?.querySelector<HTMLElement>(GMAIL.sender);
  if (!sender) return null;
  return {
    email: (sender.getAttribute("email") ?? "").slice(0, 320),
    name: (sender.getAttribute("name") ?? sender.textContent ?? "").slice(0, 256),
  };
}

function clear(state: Rendered | undefined): void {
  for (const node of state?.nodes ?? []) node.remove();
}

function stop(): void {
  stopped = true;
  observer.disconnect();
}

async function inspect(body: Element): Promise<void> {
  const { groups, truncated, count } = collect(body);
  const sender = senderOf(body);
  const signature = `${count}|${groups.map((g) => g.input.href).join("\n")}|${sender?.email ?? ""}`;
  const previous = rendered.get(body);
  if (previous?.signature === signature) return;
  clear(previous);
  rendered.set(body, { signature, nodes: [], dismissed: false });

  let response: MailResponse;
  try {
    response = await chrome.runtime.sendMessage({
      type: "mail-inspect",
      links: groups.map((g) => g.input),
      sender,
    });
  } catch {
    stop(); // extension rechargée ou désinstallée : ce script n'a plus de service worker
    return;
  }
  if (!response?.ok) {
    if (response?.error === "disabled") stop(); // analyse Gmail désactivée dans les options
    return;
  }
  const state = rendered.get(body);
  if (state?.signature !== signature || !body.isConnected) return; // message changé entre-temps

  const t = translator(response.language);
  const flagged: FlaggedLink[] = [];
  response.links.forEach((verdict, i) => {
    if (verdict.verdict !== "suspicious" && verdict.verdict !== "phishing") return;
    const group = groups[i]!;
    flagged.push({ text: group.input.text.trim(), host: verdict.host, verdict: verdict.verdict, reasons: verdict.reasons });
    for (const anchor of group.anchors) {
      const mark = createMark(verdict.verdict, verdict.reasons, t);
      anchor.after(mark);
      state.nodes.push(mark);
    }
  });
  if (response.verdict === "safe") return;
  const content: BannerContent = {
    verdict: response.verdict as Exclude<Verdict, "safe">,
    flagged: flagged.sort((a, b) => (a.verdict === b.verdict ? 0 : a.verdict === "phishing" ? -1 : 1)),
    sender: response.sender,
    truncated,
  };
  const banner = createBanner(content, t, () => {
    state.dismissed = true;
  });
  body.before(banner);
  state.nodes.push(banner);
}

function scan(): void {
  timer = null;
  if (stopped) return;
  const main = document.querySelector(GMAIL.main);
  if (main === null) return;
  for (const body of main.querySelectorAll(GMAIL.body)) {
    if (rendered.get(body)?.dismissed) continue;
    if (pending.has(body)) {
      rescan = true; // modifié pendant son analyse : revu une fois celle-ci terminée
      continue;
    }
    pending.add(body);
    void inspect(body).finally(() => {
      pending.delete(body);
      if (rescan) {
        rescan = false;
        schedule();
      }
    });
  }
}

function schedule(): void {
  if (timer === null && !stopped) timer = setTimeout(scan, SCAN_DELAY_MS);
}

const observer = new MutationObserver((mutations) => {
  // Nos propres insertions (bannière, marques) ne relancent pas d'analyse.
  const ours = (node: Node) => node.nodeName === "PHISHGUARD-BANNER" || node.nodeName === "PHISHGUARD-MARK";
  if (mutations.every((m) => [...m.addedNodes, ...m.removedNodes].every(ours))) return;
  schedule();
});

observer.observe(document.body, { childList: true, subtree: true });
schedule();
