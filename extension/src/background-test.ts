/**
 * Point d'entrée du **build de test** (`node build.mjs --test`, dossier `dist-test/`).
 *
 * Un test automatisé ne peut pas cliquer sur l'icône, donc n'obtient pas `activeTab` : il
 * appelle directement l'analyse et l'affichage du badge du vrai service worker. Ce fichier
 * n'est jamais inclus dans `dist/` (build.mjs refuse un bundle qui contiendrait ces crochets).
 */

import { analyzeUrl, showVerdict } from "./background";

Object.assign(globalThis, {
  phishguardTest: {
    analyzeUrl,
    analyzeTimed: async (url: string) => {
      const start = performance.now();
      const analysis = await analyzeUrl(url);
      return { analysis, elapsedMs: performance.now() - start };
    },
    showVerdictFor: async (tabId: number, url: string) => showVerdict(tabId, await analyzeUrl(url)),
  },
});
