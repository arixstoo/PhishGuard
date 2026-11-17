/**
 * Script de contenu Gmail (étape 5.6) sur la maquette servie sous `https://mail.google.com/`.
 *
 * La bannière et les marques vivent dans un Shadow DOM **fermé** : ni Gmail ni Playwright
 * n'y entrent par le DOM. On les lit par le protocole de débogage de Chromium
 * (`DOM.getDocument` avec `pierce`), qui voit aussi le type de chaque racine : la
 * fermeture elle-même est donc vérifiée.
 */

import type { CDPSession, Page } from "@playwright/test";
import { GMAIL_MESSAGES } from "./cases";
import { expect, test } from "./fixtures";

interface DomNode {
  backendNodeId: number;
  nodeName: string;
  nodeType: number;
  nodeValue?: string;
  attributes?: string[];
  children?: DomNode[];
  shadowRoots?: (DomNode & { shadowRootType?: string })[];
}

const kids = (node: DomNode) => [...(node.shadowRoots ?? []), ...(node.children ?? [])];
const textOf = (node: DomNode): string => (node.nodeType === 3 ? (node.nodeValue ?? "") : kids(node).map(textOf).join(" "));
const findAll = (node: DomNode, name: string, out: DomNode[] = []): DomNode[] => {
  if (node.nodeName === name) out.push(node);
  for (const child of kids(node)) findAll(child, name, out);
  return out;
};
const attribute = (node: DomNode, name: string) => {
  const attrs = node.attributes ?? [];
  const i = attrs.indexOf(name);
  return i >= 0 && i % 2 === 0 ? attrs[i + 1] : undefined;
};
/** Premier élément porteur de `role`, sous `node`. */
const roleOf = (node: DomNode): string | undefined => {
  const own = attribute(node, "role");
  if (own) return own;
  for (const child of kids(node)) {
    const found = roleOf(child);
    if (found) return found;
  }
  return undefined;
};

async function snapshot(cdp: CDPSession) {
  const { root } = (await cdp.send("DOM.getDocument", { depth: -1, pierce: true })) as { root: DomNode };
  const banners = findAll(root, "PHISHGUARD-BANNER");
  const marks = findAll(root, "PHISHGUARD-MARK");
  return {
    banners: banners.map((b) => ({
      text: textOf(b).replace(/\s+/g, " ").trim(),
      role: roleOf(b),
      closed: b.shadowRoots?.length === 1 && b.shadowRoots[0]!.shadowRootType === "closed",
    })),
    marks: marks.map((m) => ({
      label: m.shadowRoots?.[0] ? attributeDeep(m.shadowRoots[0], "aria-label") : undefined,
      closed: m.shadowRoots?.[0]?.shadowRootType === "closed",
    })),
  };
}
const attributeDeep = (node: DomNode, name: string): string | undefined =>
  attribute(node, name) ?? kids(node).map((c) => attributeDeep(c, name)).find((v) => v !== undefined);

async function openMessage(gmail: Page, id: number) {
  await gmail.evaluate((n) => (location.hash = `#inbox/${n}`), id);
  await gmail.locator("div.a3s").waitFor(); // le corps arrive après 150 ms, comme dans Gmail
}

test("la liste des messages n'est jamais lue", async ({ openGmail }) => {
  const gmail = await openGmail();
  const cdp = await gmail.context().newCDPSession(gmail);
  await gmail.locator("tr[data-open]").first().waitFor();
  await gmail.waitForTimeout(800); // anti-rebond de 300 ms, largement
  const state = await snapshot(cdp);
  expect(state.banners).toEqual([]);
  expect(state.marks).toEqual([]);
});

test("les 10 messages de test : bannière à bon escient, liens intacts", async ({ openGmail }) => {
  const gmail = await openGmail();
  const cdp = await gmail.context().newCDPSession(gmail);
  for (const message of GMAIL_MESSAGES) {
    await openMessage(gmail, message.id);
    const hrefs = await gmail.locator("div.a3s a").evaluateAll((as) => as.map((a) => a.getAttribute("href")));
    let state = await snapshot(cdp);
    if (message.banner === null) {
      // Absence : attendre plus longtemps que l'anti-rebond et l'analyse avant de conclure.
      await gmail.waitForTimeout(900);
      state = await snapshot(cdp);
      expect(state.banners, `message ${message.id}`).toEqual([]);
    } else {
      await expect.poll(async () => (state = await snapshot(cdp)).banners.length, { message: `message ${message.id}` }).toBe(1);
      const [banner] = state.banners;
      expect(banner!.closed, "ombre fermée").toBe(true);
      // Phishing : alerte annoncée tout de suite ; suspect : simple statut.
      expect(banner!.role, `message ${message.id}`).toBe(message.banner === "phishing" ? "alert" : "status");
      expect(banner!.text).toContain("PhishGuard");
    }
    expect(state.marks, `marques du message ${message.id}`).toHaveLength(message.marks);
    for (const mark of state.marks) {
      expect(mark.closed).toBe(true);
      expect(mark.label, "marque lisible par un lecteur d'écran").toBeTruthy();
    }
    // Le script ajoute ses marques à côté des liens, sans jamais les modifier.
    expect(await gmail.locator("div.a3s a").evaluateAll((as) => as.map((a) => a.getAttribute("href")))).toEqual(hrefs);
  }
});

test("bannière avant le corps du message, dans le flux, et « Masquer » la retire", async ({ openGmail }) => {
  const gmail = await openGmail();
  const cdp = await gmail.context().newCDPSession(gmail);
  await openMessage(gmail, 6);
  await expect.poll(async () => (await snapshot(cdp)).banners.length).toBe(1);
  const position = await gmail.evaluate(() => {
    const banner = document.querySelector("phishguard-banner")!;
    return banner.nextElementSibling?.classList.contains("a3s");
  });
  expect(position).toBe(true);

  // Le bouton est dans l'ombre fermée : position lue par CDP, puis vrai clic de souris.
  const { root } = (await cdp.send("DOM.getDocument", { depth: -1, pierce: true })) as { root: DomNode };
  const button = findFirst(root, (n) => n.nodeName === "BUTTON" && attribute(n, "aria-label") === "Masquer l'alerte PhishGuard");
  expect(button, "bouton « Masquer » nommé pour les lecteurs d'écran").toBeDefined();
  const { model } = (await cdp.send("DOM.getBoxModel", { backendNodeId: button!.backendNodeId })) as {
    model: { content: number[] };
  };
  const [x1, y1, , , x3, y3] = model.content;
  await gmail.mouse.click((x1! + x3!) / 2, (y1! + y3!) / 2);
  await expect.poll(async () => (await snapshot(cdp)).banners.length).toBe(0);
  // Masquée pour ce message : elle ne revient pas au prochain passage de l'observateur.
  await gmail.evaluate(() => document.querySelector("div.a3s")!.append(document.createElement("span")));
  await gmail.waitForTimeout(900);
  expect((await snapshot(cdp)).banners).toEqual([]);
});

const findFirst = (node: DomNode, predicate: (n: DomNode) => boolean): DomNode | undefined =>
  predicate(node) ? node : kids(node).map((c) => findFirst(c, predicate)).find((n) => n !== undefined);

test("analyse Gmail désactivée dans les options : plus rien n'est lu", async ({ sw, openGmail }) => {
  await sw.evaluate(() => chrome.storage.local.set({ settings: { gmail: false } }));
  const gmail = await openGmail();
  const cdp = await gmail.context().newCDPSession(gmail);
  await openMessage(gmail, 6);
  await gmail.waitForTimeout(900);
  expect((await snapshot(cdp)).banners).toEqual([]);
});

test("rien n'est gardé de Gmail, même en mémoire de session", async ({ sw, openGmail }) => {
  const gmail = await openGmail();
  const cdp = await gmail.context().newCDPSession(gmail);
  await openMessage(gmail, 7);
  await expect.poll(async () => (await snapshot(cdp)).banners.length).toBe(1);
  expect(await sw.evaluate(() => chrome.storage.session.get(null))).toEqual({});
  expect(await sw.evaluate(() => chrome.storage.local.get(null))).toEqual({});
});
