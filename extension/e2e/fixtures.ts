/**
 * Fixtures des parcours de bout en bout (étape 5.10).
 *
 * - **Un Chromium par worker**, avec l'extension de `dist-test/` chargée (contexte
 *   persistant, `--load-extension`) : c'est la seule façon de charger une extension.
 * - **Aucune page réelle** : toute requête qui ne vise pas le paquet de l'extension est
 *   servie par Playwright (maquette Gmail sous `https://mail.google.com/`, page factice
 *   ailleurs). Une URL de phishing n'est qu'une chaîne (règle du labo).
 * - **Réseau surveillé** : après chaque test, toute requête hors du paquet que le test
 *   n'a pas lui-même provoquée (navigation d'un onglet) le fait échouer. C'est la preuve,
 *   en CI, de « par défaut, aucune requête » (étape 5.7).
 * - Stockage de l'extension vidé avant chaque test : réglages par défaut.
 */

import { readFileSync } from "node:fs";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { type BrowserContext, chromium, type Page, test as base, type Worker } from "@playwright/test";

const HERE = new URL(".", import.meta.url).pathname.replace(/^\/([A-Z]:)/, "$1");
export const DIST = process.env["PHISHGUARD_E2E_DIST"] ?? join(HERE, "..", "dist-test");
const GMAIL_MOCK = readFileSync(join(HERE, "..", "test", "fixtures", "gmail-mock.html"));
export const GMAIL_URL = "https://mail.google.com/mail/u/0/#inbox";

interface Network {
  /** Requêtes hors du paquet de l'extension, dans l'ordre. */
  outside: string[];
  /** URLs que le test a lui-même demandées (navigation d'un onglet) : admises. */
  expected: Set<string>;
}

interface WorkerFixtures {
  extension: { context: BrowserContext; id: string; sw: Worker; network: Network };
}

interface TestFixtures {
  context: BrowserContext;
  extensionId: string;
  sw: Worker;
  /** Navigue un onglet vers `url` (servie par une page factice) et l'admet au réseau. */
  visit: (page: Page, url: string) => Promise<void>;
  /** Ouvre une page de l'extension (`popup.html`, `options.html`). */
  openExtensionPage: (path: string) => Promise<Page>;
  /** Ouvre la maquette Gmail. */
  openGmail: () => Promise<Page>;
  /** Vérifié après chaque test : aucune requête inattendue. */
  noUnexpectedRequests: void;
  resetExtension: void;
}

/** Le service worker de PhishGuard (Chromium a ses propres extensions internes). */
async function findServiceWorker(context: BrowserContext): Promise<Worker> {
  const deadline = Date.now() + 15_000;
  while (Date.now() < deadline) {
    for (const worker of context.serviceWorkers()) {
      if (!worker.url().startsWith("chrome-extension://")) continue;
      const name = await worker.evaluate(() => chrome.runtime.getManifest().short_name).catch(() => null);
      if (name === "PhishGuard") return worker;
    }
    await context.waitForEvent("serviceworker", { timeout: 1_000 }).catch(() => undefined);
  }
  throw new Error(`service worker de PhishGuard introuvable : extension construite dans ${DIST} ?`);
}

export const test = base.extend<TestFixtures, WorkerFixtures>({
  extension: [
    // eslint-disable-next-line no-empty-pattern
    async ({}, use) => {
      const profile = mkdtempSync(join(tmpdir(), "phishguard-e2e-"));
      const context = await chromium.launchPersistentContext(profile, {
        channel: "chromium", // vrai Chromium (le « headless shell » ne charge pas d'extension)
        headless: true,
        locale: "fr-FR",
        // Langue de l'interface de Chromium, donc du catalogue `_locales` choisi par Chrome :
        // `--lang` sous Windows et macOS ; sous Linux, Chromium l'ignore et lit `LANGUAGE`
        // puis `LANG` (le runner de la CI est en `C.UTF-8`, d'où une extension en anglais).
        args: [`--disable-extensions-except=${DIST}`, `--load-extension=${DIST}`, "--lang=fr"],
        env: { ...process.env, LANGUAGE: "fr", LANG: "fr_FR.UTF-8" },
      });
      const network: Network = { outside: [], expected: new Set() };
      context.on("request", (request) => {
        const url = request.url();
        if (!url.startsWith("chrome-extension://") && !url.startsWith("data:") && url !== "about:blank") {
          network.outside.push(url);
        }
      });
      await context.route("**/*", async (route) => {
        const url = route.request().url();
        if (url.startsWith("chrome-extension://")) return route.continue();
        if (url.startsWith("https://mail.google.com/mail/")) {
          return route.fulfill({ status: 200, contentType: "text/html; charset=utf-8", body: GMAIL_MOCK });
        }
        return route.fulfill({ status: 200, contentType: "text/html", body: "<title>page factice</title>" });
      });
      const sw = await findServiceWorker(context);
      await sw.evaluate(async () => {
        // Le build de test expose l'analyse : attendre que le module soit évalué.
        for (let i = 0; i < 100 && typeof (globalThis as { phishguardTest?: unknown }).phishguardTest !== "object"; i++) {
          await new Promise((r) => setTimeout(r, 50));
        }
      });
      const id = new URL(sw.url()).host;
      await use({ context, id, sw, network });
      await context.close();
      rmSync(profile, { recursive: true, force: true });
    },
    { scope: "worker" },
  ],

  // Automatique : installé avant les `beforeEach`, qui peuvent donc préparer l'état.
  resetExtension: [
    async ({ extension }, use) => {
      // Réglages par défaut, aucun cache, aucun onglet hérité du test précédent.
      await extension.sw.evaluate(async () => {
        await chrome.storage.local.clear();
        await chrome.storage.session.clear();
      });
      await use();
      for (const page of extension.context.pages()) await page.close();
    },
    { auto: true },
  ],
  context: async ({ extension }, use) => use(extension.context),
  extensionId: async ({ extension }, use) => use(extension.id),
  sw: async ({ extension }, use) => use(extension.sw),

  visit: async ({ extension }, use) => {
    await use(async (page, url) => {
      extension.network.expected.add(url);
      await page.goto(url);
    });
  },

  openExtensionPage: async ({ context, extensionId }, use) => {
    await use(async (path) => {
      const page = await context.newPage();
      await page.goto(`chrome-extension://${extensionId}/${path}`);
      return page;
    });
  },

  openGmail: async ({ context, extension }, use) => {
    await use(async () => {
      extension.network.expected.add(GMAIL_URL.replace(/#.*$/, ""));
      const page = await context.newPage();
      await page.goto(GMAIL_URL);
      return page;
    });
  },

  noUnexpectedRequests: [
    async ({ extension }, use) => {
      extension.network.outside.length = 0;
      extension.network.expected.clear();
      await use();
      const unexpected = extension.network.outside.filter((url) => !extension.network.expected.has(url));
      test.expect(unexpected, "requêtes hors du paquet de l'extension").toEqual([]);
    },
    { auto: true },
  ],
});

export const expect = test.expect;

/**
 * Analyse du service worker (build de test), sans clic sur l'icône. Un préchauffage dans
 * le même appel charge le modèle : la durée mesurée est celle de l'analyse seule (MV3 peut
 * arrêter le service worker entre deux tests, et le modèle est alors rechargé).
 */
export function analyze(sw: Worker, url: string) {
  return sw.evaluate(async (u) => {
    const test = (globalThis as unknown as { phishguardTest: { analyzeTimed(u: string): Promise<unknown> } }).phishguardTest;
    await test.analyzeTimed("https://prechauffage.example/");
    return test.analyzeTimed(u);
  }, url) as Promise<{ analysis: { verdict: string; score: number; hardRule: string | null; reasons: string[] }; elapsedMs: number }>;
}

/**
 * Simule « Analyser ce lien avec PhishGuard » : même résultat que le menu contextuel
 * (hôte, verdict, raisons ; jamais l'URL), lu par la fenêtre contextuelle.
 */
export async function analyzeLink(sw: Worker, url: string): Promise<void> {
  await sw.evaluate(async (u) => {
    const test = (globalThis as unknown as { phishguardTest: { analyzeUrl(u: string): Promise<Record<string, unknown>> } })
      .phishguardTest;
    const a = await test.analyzeUrl(u);
    await chrome.storage.session.set({
      lastLinkAnalysis: {
        at: Date.now(),
        host: a["host"],
        registeredDomain: a["registeredDomain"],
        verdict: a["verdict"],
        score: a["score"],
        reasons: a["reasons"],
        hardRule: a["hardRule"],
      },
    });
  }, url);
}
