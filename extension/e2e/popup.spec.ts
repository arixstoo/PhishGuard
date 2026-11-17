/**
 * Fenêtre contextuelle (étapes 5.5 et 5.8) : verdict en texte, conseil, clavier,
 * confirmation de confiance, signalement désactivé, langues et sens d'écriture.
 *
 * Un test ne peut pas cliquer sur l'icône (donc pas d'`activeTab`) : le verdict affiché
 * est celui d'un lien analysé par le menu contextuel, que la fenêtre lit au démarrage.
 */

import type { Page } from "@playwright/test";
import { HOMOGRAPH_URL, PHISHING_URL, SAFE_URL } from "./cases";
import { analyzeLink, expect, test } from "./fixtures";

const result = (popup: Page) => popup.locator("#result");
const focused = (popup: Page) => popup.evaluate(() => document.activeElement?.textContent?.trim() ?? "");

test.describe("lien de phishing", () => {
  test.beforeEach(async ({ sw }) => analyzeLink(sw, PHISHING_URL));

  test("verdict par icône, couleur et texte, explication, conseil, deux actions", async ({ openExtensionPage }) => {
    const popup = await openExtensionPage("popup.html");
    await expect(result(popup)).toContainText("Phishing probable");
    await expect(result(popup)).toContainText("Lien analysé");
    await expect(result(popup)).toContainText("ressemble fortement");
    await expect(result(popup)).toContainText("N'entrez aucun mot de passe");
    await expect(popup.getByRole("button", { name: "Toujours faire confiance à ce site" })).toBeVisible();
    await expect(popup.getByRole("button", { name: "Signaler une erreur" })).toBeVisible();
    await expect(popup.locator("#details")).toBeHidden(); // détails repliés par défaut
    await expect(popup.locator("#announce")).toHaveAttribute("role", "status");
  });

  test("clavier : ordre de tabulation, Maj+Tab, Entrée déplie les détails", async ({ openExtensionPage }) => {
    const popup = await openExtensionPage("popup.html");
    await expect(result(popup)).toContainText("Phishing probable");
    const order: string[] = [];
    for (let i = 0; i < 4; i++) {
      await popup.keyboard.press("Tab");
      order.push(await focused(popup));
    }
    expect(order).toEqual(["Options", "Détails techniques", "Toujours faire confiance à ce site", "Signaler une erreur"]);
    await popup.keyboard.press("Shift+Tab");
    await popup.keyboard.press("Shift+Tab");
    expect(await focused(popup)).toBe("Détails techniques");
    await popup.keyboard.press("Enter");
    const toggle = popup.getByRole("button", { name: "Détails techniques" });
    await expect(toggle).toHaveAttribute("aria-expanded", "true");
    await expect(popup.locator("#details")).toBeVisible();
    await expect(popup.locator("#details")).toContainText("paypa1-secure-login.example");
  });

  test("confiance : avertissement, focus sur « Annuler », Échap rend le focus", async ({ openExtensionPage }) => {
    const popup = await openExtensionPage("popup.html");
    const trust = popup.getByRole("button", { name: "Toujours faire confiance à ce site" });
    await trust.focus();
    await popup.keyboard.press("Enter");
    await expect(popup.locator(".panel")).toContainText("Faire confiance à");
    await expect(popup.locator(".panel")).toContainText("Attention");
    expect(await focused(popup)).toBe("Annuler");
    await popup.keyboard.press("Escape");
    await expect(popup.locator(".panel")).toHaveCount(0);
    await expect(trust).toBeFocused();
  });

  test("signalement désactivé par défaut, et la fenêtre dit pourquoi", async ({ openExtensionPage }) => {
    const popup = await openExtensionPage("popup.html");
    await popup.getByRole("button", { name: "Signaler une erreur" }).click();
    await expect(popup.locator(".panel")).toContainText("désactivé");
    await expect(popup.getByRole("button", { name: "Ouvrir les options" })).toBeFocused();
  });
});

test("lien sûr", async ({ sw, openExtensionPage }) => {
  await analyzeLink(sw, SAFE_URL);
  const popup = await openExtensionPage("popup.html");
  await expect(result(popup)).toContainText("Aucun signe de phishing");
});

test("homographe : alphabets mélangés, confiance impossible", async ({ sw, openExtensionPage }) => {
  await analyzeLink(sw, HOMOGRAPH_URL);
  const popup = await openExtensionPage("popup.html");
  await expect(result(popup)).toContainText("mélange des alphabets");
  await expect(popup.getByRole("button", { name: "Toujours faire confiance à ce site" })).toHaveCount(0);
});

test("le résultat d'un lien n'est lu qu'une fois", async ({ sw, openExtensionPage }) => {
  await analyzeLink(sw, PHISHING_URL);
  await (await openExtensionPage("popup.html")).close();
  expect(await sw.evaluate(() => chrome.storage.session.get("lastLinkAnalysis"))).toEqual({});
});

test("page non analysable expliquée", async ({ openExtensionPage }) => {
  // L'onglet actif est la fenêtre elle-même : une page de l'extension, pas un site web.
  const popup = await openExtensionPage("popup.html");
  await expect(result(popup)).toContainText("n'est pas un site web");
});

test("arabe : droite à gauche, traduction, propriétés logiques", async ({ sw, openExtensionPage }) => {
  await sw.evaluate(() => chrome.storage.local.set({ settings: { language: "ar" } }));
  await analyzeLink(sw, PHISHING_URL);
  const popup = await openExtensionPage("popup.html");
  await expect(popup.locator("html")).toHaveAttribute("dir", "rtl");
  await expect(popup.locator("html")).toHaveAttribute("lang", "ar");
  await expect(result(popup)).toContainText("تصيد احتيالي محتمل");
  // La bordure de début de la carte passe à droite d'elle-même.
  await expect(popup.locator(".card").first()).toHaveCSS("border-right-width", "5px");
});

test("anglais", async ({ sw, openExtensionPage }) => {
  await sw.evaluate(() => chrome.storage.local.set({ settings: { language: "en" } }));
  await analyzeLink(sw, PHISHING_URL);
  const popup = await openExtensionPage("popup.html");
  await expect(popup.locator("html")).toHaveAttribute("dir", "ltr");
  await expect(result(popup)).toContainText("Likely phishing");
});
