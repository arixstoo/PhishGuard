/**
 * Service worker (étape 5.4) dans un vrai Chromium : manifeste chargé, verdicts des 10
 * sites, badge effacé dès que l'onglet navigue, aucune analyse sans clic.
 */

import { SITES } from "./cases";
import { analyze, expect, test } from "./fixtures";

test("l'extension se charge avec exactement les permissions du manifeste", async ({ sw }) => {
  const manifest = await sw.evaluate(() => chrome.runtime.getManifest());
  expect(manifest.short_name).toBe("PhishGuard");
  expect(manifest.permissions).toEqual(["storage", "activeTab", "contextMenus"]);
  expect(manifest.host_permissions ?? []).toEqual([]);
  // Aucune permission optionnelle accordée à l'installation.
  const granted = await sw.evaluate(() => chrome.permissions.getAll());
  expect(granted.permissions?.sort()).toEqual(["activeTab", "contextMenus", "storage"]);
  expect(granted.origins).toEqual(["https://mail.google.com/*"]);
});

for (const { url, verdict } of SITES) {
  test(`verdict local : ${url} → ${verdict}`, async ({ sw }) => {
    const { analysis, elapsedMs } = await analyze(sw, url);
    expect(analysis.verdict).toBe(verdict);
    // Objectif de l'étape 5.4 : moins de 50 ms hors chargement du modèle (mesuré : 2 à 4 ms).
    expect(elapsedMs).toBeLessThan(50);
  });
}

test("le badge décrit une URL précise et s'efface dès que l'onglet navigue", async ({ context, sw, visit }) => {
  const page = await context.newPage();
  const phishing = "http://192.0.2.10/paypal/login.php";
  await visit(page, phishing);
  const tabId = await sw.evaluate(async () => (await chrome.tabs.query({ active: true, lastFocusedWindow: true }))[0]!.id!);
  await sw.evaluate(
    ([id, u]) =>
      (globalThis as unknown as { phishguardTest: { showVerdictFor(id: number, u: string): Promise<void> } }).phishguardTest.showVerdictFor(id, u),
    [tabId, phishing] as [number, string],
  );
  const badge = await sw.evaluate(async (id) => [await chrome.action.getBadgeText({ tabId: id }), await chrome.action.getTitle({ tabId: id })], tabId);
  expect(badge[0]).toBe("!");
  expect(badge[1]).toContain("192.0.2.10"); // le verdict en toutes lettres, avec l'hôte

  await visit(page, "https://www.wikipedia.org/");
  await expect.poll(() => sw.evaluate((id) => chrome.action.getBadgeText({ tabId: id }), tabId)).toBe("");
});

test("sans l'option, une page visitée n'est ni analysée ni gardée", async ({ context, sw, visit }) => {
  const page = await context.newPage();
  await visit(page, "http://paypa1-secure-login.example/verify/account");
  await page.waitForTimeout(500);
  const tabId = await sw.evaluate(async () => (await chrome.tabs.query({ active: true, lastFocusedWindow: true }))[0]!.id!);
  expect(await sw.evaluate((id) => chrome.action.getBadgeText({ tabId: id }), tabId)).toBe("");
  expect(await sw.evaluate(() => chrome.storage.session.get(null))).toEqual({});
});
