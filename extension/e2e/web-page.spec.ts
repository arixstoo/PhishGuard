/**
 * Page « coller et analyser » de l'API (étape 5.12), dans Chromium.
 *
 * Les fichiers de `src/phishguard/api/static/` sont servis tels quels, avec la politique de
 * contenu de l'API (`WEB_CSP`, lue dans `routers/web.py`) ; les réponses de l'API sont
 * simulées. Une raison renvoyée par le serveur contient du HTML piégé : il doit s'afficher
 * comme du texte. Aucune extension n'est chargée ici.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { expect, type Page, type Route, test } from "@playwright/test";

const HERE = new URL(".", import.meta.url).pathname.replace(/^\/([A-Z]:)/, "$1");
const STATIC = join(HERE, "..", "..", "src", "phishguard", "api", "static");
const ROUTER = readFileSync(join(HERE, "..", "..", "src", "phishguard", "api", "routers", "web.py"), "utf-8");
// La politique de la page, telle que l'API la sert (concaténation de chaînes Python).
const CSP = [.../WEB_CSP: Final = \(([\s\S]*?)\)/.exec(ROUTER)![1]!.matchAll(/"([^"]*)"/g)].map((m) => m[1]).join("");
const ORIGIN = "https://phishguard.test";
const XSS = `<img src=x onerror="document.title='pwned'">`;

const TYPES: Record<string, string> = {
  "index.html": "text/html; charset=utf-8",
  "paste.js": "text/javascript; charset=utf-8",
  "paste.css": "text/css; charset=utf-8",
  "icon.svg": "image/svg+xml",
};

function analysis(verdict: "safe" | "suspicious" | "phishing", channel: string, message: string) {
  return {
    verdict,
    score: { safe: 4, suspicious: 52, phishing: 96 }[verdict],
    channel,
    reasons: verdict === "safe" ? [] : [{ code: "x", source: "x", points: 50, message, params: {} }],
    advice: `Conseil ${channel} ${verdict}.`,
  };
}

interface Calls {
  text: unknown[];
  url: unknown[];
}

async function serve(page: Page, api: (path: string, body: Record<string, unknown>) => unknown | number): Promise<Calls> {
  const calls: Calls = { text: [], url: [] };
  await page.route(`${ORIGIN}/**`, async (route: Route) => {
    const url = new URL(route.request().url());
    if (url.pathname.startsWith("/v1/analyze/")) {
      const body = route.request().postDataJSON() as Record<string, unknown>;
      calls[url.pathname.endsWith("/text") ? "text" : "url"].push(body);
      const reply = api(url.pathname, body);
      if (typeof reply === "number") {
        return route.fulfill({ status: reply, headers: { "Retry-After": "42" }, json: { error: { code: "x" } } });
      }
      return route.fulfill({ status: 200, json: reply });
    }
    const name = url.pathname === "/" ? "index.html" : url.pathname.replace(/^\/static\//, "");
    if (!(name in TYPES)) return route.fulfill({ status: 404 });
    return route.fulfill({
      status: 200,
      headers: { "Content-Type": TYPES[name]!, ...(name === "index.html" ? { "Content-Security-Policy": CSP } : {}) },
      body: readFileSync(join(STATIC, name)),
    });
  });
  return calls;
}

test.use({ channel: "chromium", locale: "fr-FR" });

test("message piégé : verdict le plus grave, raisons en texte, lien désarmé", async ({ page }) => {
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(e.message));
  page.on("console", (m) => m.type() === "error" && errors.push(m.text()));
  const calls = await serve(page, (path) =>
    path.endsWith("/text") ? analysis("suspicious", "messaging", "Le message vous presse d'agir.") : analysis("phishing", "url", XSS),
  );
  await page.goto(`${ORIGIN}/`);
  await expect(page.getByText("Ne collez pas de mot de passe ou de données personnelles.")).toBeVisible();

  await page.getByLabel("Message ou lien à vérifier").fill(
    "Votre colis est bloqué : http://xn--pple-43d.com/suivi?jeton=SECRET. Payez vite.",
  );
  await page.getByRole("button", { name: "Analyser" }).click();

  const result = page.locator("#result");
  await expect(result.getByRole("heading", { level: 2 })).toHaveText(/Phishing probable/);
  await expect(result.getByRole("heading", { level: 2 })).toBeFocused();
  await expect(page.locator("#status")).toHaveText("Résultat : Phishing probable.");
  await expect(result).toContainText("Le message : suspect");
  await expect(result).toContainText("Lien vers xn--pple-43d.com : phishing");
  await expect(result).toContainText("Conseil : Conseil url phishing.");
  // Le HTML piégé est affiché comme du texte, jamais interprété.
  await expect(result).toContainText(XSS);
  await expect(result.locator("img")).toHaveCount(0);
  await expect(page).not.toHaveTitle("pwned");
  // Aucun lien cliquable, aucun chemin ni paramètre du lien affiché.
  await expect(result.locator("a")).toHaveCount(0);
  await expect(result).not.toContainText("SECRET");

  expect(calls.text).toEqual([
    { text: "Votre colis est bloqué : http://xn--pple-43d.com/suivi?jeton=SECRET. Payez vite.", channel: "messaging", language: "fr", analyst: false },
  ]);
  expect(calls.url).toEqual([{ url: "http://xn--pple-43d.com/suivi?jeton=SECRET", language: "fr", analyst: false, use_threat_intel: false }]);
  expect(errors).toEqual([]); // ni erreur de script, ni violation de la politique de contenu
});

test("un lien seul : une seule analyse, celle du lien", async ({ page }) => {
  const calls = await serve(page, () => analysis("safe", "url", ""));
  await page.goto(`${ORIGIN}/`);
  await page.getByLabel("Message ou lien à vérifier").fill("www.wikipedia.org");
  await page.keyboard.press("Tab");
  await page.getByRole("button", { name: "Analyser" }).press("Enter");
  await expect(page.locator("#result h2")).toHaveText(/Aucun signe de phishing/);
  expect(calls.text).toEqual([]);
  expect(calls.url).toEqual([{ url: "http://www.wikipedia.org", language: "fr", analyst: false, use_threat_intel: false }]);
});

test("texte vide : erreur annoncée sur le champ, aucune requête", async ({ page }) => {
  const calls = await serve(page, () => analysis("safe", "url", ""));
  await page.goto(`${ORIGIN}/`);
  await page.getByRole("button", { name: "Analyser" }).click();
  const field = page.getByLabel("Message ou lien à vérifier");
  await expect(field).toHaveAttribute("aria-invalid", "true");
  await expect(field).toBeFocused();
  await expect(page.locator("#text-error")).toHaveText("Collez d'abord un message ou un lien.");
  expect(calls).toEqual({ text: [], url: [] });
});

test("limite de débit : message clair avec le délai", async ({ page }) => {
  await serve(page, () => 429);
  await page.goto(`${ORIGIN}/`);
  await page.getByLabel("Message ou lien à vérifier").fill("Bonjour, cliquez ici");
  await page.getByRole("button", { name: "Analyser" }).click();
  await expect(page.locator("#result h2")).toHaveText("Trop d'analyses en peu de temps. Réessayez dans 42 secondes.");
});

test("arabe : droite à gauche, textes traduits, requêtes dans la langue choisie", async ({ page }) => {
  const calls = await serve(page, () => analysis("phishing", "messaging", "سبب"));
  await page.goto(`${ORIGIN}/`);
  await page.locator("#language").selectOption("ar");
  await expect(page.locator("html")).toHaveAttribute("dir", "rtl");
  await expect(page.getByText("لا تلصق كلمات مرور أو بيانات شخصية.")).toBeVisible();
  await page.locator("#text").fill("رسالة مريبة");
  await page.getByRole("button", { name: "تحليل" }).click();
  await expect(page.locator("#result h2")).toHaveText(/تصيد احتيالي محتمل/);
  await expect(page.locator("#result")).toHaveCSS("border-right-width", "5px");
  expect((calls.text[0] as { language: string }).language).toBe("ar");
});

test("Trusted Types refuse toute injection HTML ; « Effacer » vide le champ", async ({ page }) => {
  await serve(page, () => analysis("safe", "url", ""));
  await page.goto(`${ORIGIN}/`);
  const blocked = await page.evaluate(() => {
    try {
      document.body.innerHTML = "<b>x</b>"; // Trusted Types : refusé par le navigateur
      return false;
    } catch {
      return true;
    }
  });
  expect(blocked).toBe(true);
  // Effacer vide le champ et le résultat.
  await page.locator("#text").fill("abc");
  await page.getByRole("button", { name: "Effacer" }).click();
  await expect(page.locator("#text")).toHaveValue("");
  await expect(page.locator("#text")).toBeFocused();
});
