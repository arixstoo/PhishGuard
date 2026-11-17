/**
 * Cas des parcours de bout en bout (étape 5.10), partagés avec `test/stub-model.test.ts`.
 *
 * Verdicts mesurés avec le vrai modèle `url_v2` (docs/extension-design.md, sections 4 et 6) :
 * le modèle de test (`stub-model.mjs`) doit les reproduire, pour que la CI vérifie la même
 * chose qu'un poste qui a le modèle. Aucune URL de phishing réelle : domaines `.example`,
 * IP de documentation (192.0.2.0/24), homographe construit ; aucune page n'est chargée.
 */

export type Verdict = "safe" | "suspicious" | "phishing";

export const SITES: readonly { url: string; verdict: Verdict }[] = [
  { url: "https://www.wikipedia.org/", verdict: "safe" },
  { url: "https://www.google.com/search?q=meteo", verdict: "safe" },
  { url: "https://github.com/arixstoo", verdict: "safe" },
  { url: "https://www.lemonde.fr/international/", verdict: "safe" },
  { url: "https://www.impots.gouv.fr/accueil", verdict: "safe" },
  { url: "https://www.amazon.fr/gp/cart/view.html", verdict: "safe" },
  { url: "http://paypa1-secure-login.example/verify/account", verdict: "phishing" },
  { url: "http://192.0.2.10/paypal/login.php", verdict: "phishing" },
  { url: "http://xn--pple-43d.com/", verdict: "phishing" },
  { url: "https://appleid.apple.com.verify-account.example/signin", verdict: "phishing" },
];

export const PHISHING_URL = "http://paypa1-secure-login.example/verify/account";
export const HOMOGRAPH_URL = "http://xn--pple-43d.com/";
export const SAFE_URL = "https://www.wikipedia.org/";

/**
 * Messages de la maquette `test/fixtures/gmail-mock.html` : verdict de la bannière
 * (`null` : aucune bannière) et nombre de marques posées après des liens.
 */
export const GMAIL_MESSAGES: readonly { id: number; banner: Exclude<Verdict, "safe"> | null; marks: number }[] = [
  { id: 1, banner: null, marks: 0 },
  { id: 2, banner: null, marks: 0 },
  { id: 3, banner: null, marks: 0 },
  { id: 4, banner: null, marks: 0 },
  { id: 5, banner: null, marks: 0 },
  { id: 6, banner: "phishing", marks: 1 },
  { id: 7, banner: "phishing", marks: 1 },
  { id: 8, banner: "phishing", marks: 1 },
  { id: 9, banner: "suspicious", marks: 0 },
  { id: 10, banner: "phishing", marks: 1 },
];
