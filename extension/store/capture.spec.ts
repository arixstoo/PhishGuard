/**
 * Images des stores (étape 6.9) : `npm run store:assets`.
 *
 * Construit d'abord `dist-test/` avec le **vrai modèle signé** (`node build.mjs --test`) :
 * les verdicts montrés sont ceux que verront les utilisateurs, pas ceux du modèle de test.
 * Le script refuse de tourner sinon.
 *
 * Pour chaque langue de la fiche (`store/listing.json`), dans `release/store/assets/<langue>/` :
 *
 * - `screenshot-<scène>.png`, 1280 × 800 : l'interface **réelle** de l'extension (fenêtre,
 *   options, bannière dans la maquette Gmail des tests), capturée en densité 2, posée dans
 *   un cadre avec la légende de la fiche ;
 * - `promo-small.png` (440 × 280) et `promo-marquee.png` (1400 × 560) ;
 * - `store-icon.png` (128 × 128) : l'icône du paquet sur 96 × 96 px, marge transparente de
 *   16 px, comme le demande le Chrome Web Store.
 *
 * Mêmes garanties que les parcours de bout en bout (`e2e/fixtures.ts`) : aucune page réelle,
 * aucune URL de phishing réelle, aucune requête hors du paquet. Les cadres sont composés
 * en HTML local (`setContent`), sans police ni image distante.
 */

import { createHash } from "node:crypto";
import { mkdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { Page } from "@playwright/test";
import { PHISHING_URL, SAFE_URL } from "../e2e/cases";
import { analyzeLink, DIST, expect, test } from "../e2e/fixtures";

const ROOT = join(DIST, "..");
const OUT = join(ROOT, "release", "store", "assets");
const listing = JSON.parse(readFileSync(join(ROOT, "store", "listing.json"), "utf-8")) as {
  locales: Locale[];
  screenshots: { id: string; caption: Record<Locale, string>; subtitle: Record<Locale, string> }[];
  promo: { tagline: Record<Locale, string> };
};
type Locale = "fr" | "en" | "ar";

const sha256 = (path: string) => createHash("sha256").update(readFileSync(path)).digest("hex");
const png = (bytes: Buffer) => `data:image/png;base64,${bytes.toString("base64")}`;
const ICON = png(readFileSync(join(DIST, "icons", "icon-128.png")));

test.describe.configure({ mode: "serial" });

test.beforeAll(() => {
  // Le modèle embarqué doit être le modèle signé du dépôt, pas le modèle de test.
  const embedded = sha256(join(DIST, "model", "url-model.json"));
  const signed = sha256(join(ROOT, "..", "models", "url_v2.json"));
  expect(embedded, "dist-test/ construit avec --stub-model : relancer node build.mjs --test").toBe(signed);
});

/**
 * Capture nette, en densité 2 : la page est agrandie par `zoom` CSS dans une fenêtre deux
 * fois plus grande (le contexte persistant des extensions a une densité fixe de 1).
 *
 * - `height` : hauteur CSS maximale ;
 * - `fit` : la capture s'arrête sous le dernier élément de ce sélecteur ;
 * - `from` : elle commence au-dessus de cet élément (sinon, en haut de la page).
 */
async function capture(page: Page, width: number, height: number, fit?: string, from?: string) {
  await page.emulateMedia({ colorScheme: "light", reducedMotion: "reduce" });
  await page.setViewportSize({ width, height: 2000 });
  const box = await page.evaluate(
    ([fitSelector, fromSelector]) => {
      const bottom = (sel: string) => Math.max(0, ...[...document.querySelectorAll(sel)].map((n) => n.getBoundingClientRect().bottom));
      const start = fromSelector ? document.querySelector(fromSelector)!.getBoundingClientRect().top - 16 : 0;
      return { top: Math.max(0, Math.floor(start)), bottom: fitSelector ? Math.ceil(bottom(fitSelector)) + 16 : Infinity };
    },
    [fit ?? "", from ?? ""] as const,
  );
  height = Math.min(height, box.bottom - box.top);
  await page.setViewportSize({ width: width * 2, height: height * 2 });
  await page.evaluate((top) => {
    document.documentElement.style.zoom = "2";
    window.scrollTo(0, top * 2);
    return document.fonts.ready;
  }, box.top);
  const bytes = await page.screenshot({ animations: "disabled" });
  await page.evaluate(() => {
    document.documentElement.style.zoom = "";
    window.scrollTo(0, 0);
  });
  return { bytes, width, height };
}

const popupShot = (page: Page) => capture(page, 380, 760, "main");

const ESCAPE: Record<string, string> = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" };
const esc = (text: string) => text.replace(/[&<>"]/g, (c) => ESCAPE[c]!);

/** Cadre 1280 × 800 : légende d'un côté, interface de l'autre (inversé en arabe). */
function frame(locale: Locale, caption: string, subtitle: string, shot: { bytes: Buffer; width: number; height: number }, window: boolean) {
  const maxW = window ? 760 : 520;
  const maxH = 680;
  const scale = Math.min(maxW / shot.width, maxH / shot.height, window ? 1 : 1.4);
  const w = Math.round(shot.width * scale);
  const h = Math.round(shot.height * scale);
  return `<!doctype html><html lang="${locale}" dir="${locale === "ar" ? "rtl" : "ltr"}"><head><meta charset="utf-8"><style>
    * { box-sizing: border-box; margin: 0; }
    html, body { width: 1280px; height: 800px; overflow: hidden; }
    body { font: 16px/1.4 system-ui, "Segoe UI", Roboto, "Noto Sans", "Noto Sans Arabic", sans-serif; color: #1b1b1f;
      background: linear-gradient(135deg, #eef2fd 0%, #dfe6fb 100%); display: flex; align-items: center; gap: 56px; padding: 0 72px; }
    .text { flex: 1; min-width: 0; }
    .brand { display: flex; align-items: center; gap: 12px; font-weight: 700; font-size: 22px; color: #1f4fd1; margin-bottom: 28px; }
    .brand img { width: 40px; height: 40px; }
    h1 { font-size: 46px; line-height: 1.15; letter-spacing: -0.01em; margin-bottom: 20px; }
    p { font-size: 22px; color: #45454f; }
    .shot { flex: none; width: ${w}px; height: ${h}px; border-radius: ${window ? 10 : 14}px; overflow: hidden; background: #fff;
      box-shadow: 0 24px 60px rgba(20, 35, 90, 0.22), 0 2px 6px rgba(20, 35, 90, 0.12); }
    .shot img { width: 100%; height: 100%; display: block; }
  </style></head><body>
    <div class="text"><div class="brand"><img src="${ICON}" alt="">PhishGuard</div><h1>${esc(caption)}</h1><p>${esc(subtitle)}</p></div>
    <div class="shot"><img src="${png(shot.bytes)}" alt=""></div>
  </body></html>`;
}

function promo(locale: Locale, tagline: string, width: number, height: number) {
  const big = width > 1000;
  return `<!doctype html><html lang="${locale}" dir="${locale === "ar" ? "rtl" : "ltr"}"><head><meta charset="utf-8"><style>
    * { box-sizing: border-box; margin: 0; }
    html, body { width: ${width}px; height: ${height}px; overflow: hidden; }
    body { font: 16px/1.2 system-ui, "Segoe UI", Roboto, "Noto Sans", "Noto Sans Arabic", sans-serif; color: #fff;
      background: linear-gradient(135deg, #1f4fd1 0%, #15338a 100%); display: flex; align-items: center; justify-content: center;
      gap: ${big ? 48 : 20}px; padding: 0 ${big ? 96 : 28}px; }
    .mark { flex: none; display: grid; place-items: center; width: ${big ? 240 : 104}px; height: ${big ? 240 : 104}px;
      border-radius: 28%; background: #fff; box-shadow: 0 10px 30px rgba(0, 0, 0, .25); }
    .mark img { width: 72%; height: 72%; }
    h1 { font-size: ${big ? 76 : 30}px; font-weight: 700; }
    p { font-size: ${big ? 38 : 17}px; margin-top: ${big ? 20 : 8}px; opacity: .92; }
  </style></head><body><div class="mark"><img src="${ICON}" alt=""></div><div><h1>PhishGuard</h1><p>${esc(tagline)}</p></div></body></html>`;
}

async function compose(page: Page, html: string, width: number, height: number, path: string, transparent = false) {
  await page.setViewportSize({ width, height });
  await page.emulateMedia({ colorScheme: "light" });
  await page.setContent(html);
  await page.evaluate(() => document.fonts.ready);
  await page.screenshot({ path, omitBackground: transparent, animations: "disabled" });
}

const shotsOf = (id: string) => listing.screenshots.find((s) => s.id === id)!;

for (const locale of listing.locales) {
  test(`images du store : ${locale}`, async ({ sw, context, openExtensionPage, openGmail }) => {
    test.setTimeout(120_000);
    const dir = join(OUT, locale);
    mkdirSync(dir, { recursive: true });
    await sw.evaluate((language) => chrome.storage.local.set({ settings: { language } }), locale);
    const canvas = await context.newPage();
    const save = async (id: string, shot: { bytes: Buffer; width: number; height: number }, window = false) => {
      const { caption, subtitle } = shotsOf(id);
      await compose(canvas, frame(locale, caption[locale], subtitle[locale], shot, window), 1280, 800, join(dir, `screenshot-${id}.png`));
    };

    // 1. Lien de phishing analysé, 3. le même avec les détails techniques dépliés.
    await analyzeLink(sw, PHISHING_URL);
    let popup = await openExtensionPage("popup.html");
    await expect(popup.locator("#result .card").first()).toBeVisible();
    await save("1-phishing", await popupShot(popup));
    await popup.locator('[aria-controls="details"]').click();
    await expect(popup.locator("#details")).toBeVisible();
    await save("3-details", await popupShot(popup));
    await popup.close();

    // 4. Site légitime.
    await analyzeLink(sw, SAFE_URL);
    popup = await openExtensionPage("popup.html");
    await expect(popup.locator("#result .card").first()).toBeVisible();
    await save("4-safe", await popupShot(popup));
    await popup.close();

    // 2. Bannière au-dessus d'un message piégé (maquette Gmail des tests, message 6).
    const gmail = await openGmail();
    await gmail.evaluate(() => (location.hash = "#inbox/6"));
    await gmail.locator("div.a3s").waitFor();
    await expect.poll(() => gmail.locator("phishguard-banner").count()).toBe(1);
    // Le bandeau de navigation de la maquette n'est pas l'objet de l'image.
    await gmail.evaluate(() => document.querySelector<HTMLElement>('[role="navigation"]')?.remove());
    await save("2-gmail", await capture(gmail, 900, 560, "div.adn"), true);
    await gmail.close();

    // 5. Options : tout ce qui part en ligne est désactivé.
    const options = await openExtensionPage("options.html");
    await expect(options.locator("#enrichment")).not.toBeChecked();
    await save("5-options", await capture(options, 760, 680, '[aria-labelledby="updates-title"]', '[aria-labelledby="online-title"]'), true);
    await options.close();

    await compose(canvas, promo(locale, listing.promo.tagline[locale], 440, 280), 440, 280, join(dir, "promo-small.png"));
    await compose(canvas, promo(locale, listing.promo.tagline[locale], 1400, 560), 1400, 560, join(dir, "promo-marquee.png"));
    await compose(
      canvas,
      `<!doctype html><style>html,body{margin:0;width:128px;height:128px;background:transparent}img{margin:16px;width:96px;height:96px;display:block}</style><img src="${ICON}" alt="">`,
      128,
      128,
      join(dir, "store-icon.png"),
      true,
    );
    await canvas.close();
  });
}
