/**
 * Navigateurs cibles de l'extension (étapes 6.9 et 6.10).
 *
 * Un seul code source, un manifeste par navigateur. `static/manifest.json` est celui de
 * Chrome ; `browserManifest(manifest, "firefox")` en dérive celui de Firefox :
 *
 * - **arrière-plan** : Firefox n'exécute pas de service worker d'extension ; il charge le
 *   même module comme page d'événements (`background.scripts`, `type: module`). Le code
 *   n'en dépend pas : il ne garde aucun état en mémoire qui ne soit dans `storage`
 *   (contrainte déjà imposée par MV3 sous Chrome) ;
 * - **identité** : `browser_specific_settings.gecko.id`, fixe pour toujours (c'est par lui
 *   qu'AMO relie les versions entre elles) ;
 * - **données** : `data_collection_permissions.required: ["none"]`, la déclaration
 *   qu'exige AMO pour toute nouvelle extension depuis novembre 2025 : par défaut, rien ne
 *   quitte l'appareil (docs/extension-privacy.md). Les options en ligne envoient à un
 *   serveur **choisi par l'utilisateur**, jamais à l'auteur : ce n'est pas une collecte ;
 * - **version minimale** : Firefox 140 (142 sur Android, `gecko_android`), première
 *   version qui lit cette déclaration ; elle fournit aussi Ed25519 dans WebCrypto
 *   (vérification des mises à jour du modèle, 129+), `storage.session` (115+) et
 *   `optional_host_permissions` en MV3 (128+) ;
 * - `minimum_chrome_version` retiré (clé inconnue de Firefox, signalée par `web-ext lint`).
 *
 * Tout le reste (autorisations, CSP, script de contenu, langues) est **identique** : la
 * justification de chaque autorisation (docs/extension-privacy.md) vaut pour les deux
 * stores, et `test/targets.test.ts` le vérifie.
 */

export const BROWSERS = /** @type {const} */ (["chrome", "firefox"]);

/** Identifiant AMO de l'extension. Ne jamais le changer : ce serait une autre extension. */
export const GECKO_ID = "phishguard@arixstoo.github.io";
export const FIREFOX_MIN_VERSION = "140.0";
/** Firefox pour Android lit `data_collection_permissions` à partir de la 142. */
export const FIREFOX_ANDROID_MIN_VERSION = "142.0";

/** Dossier de build de chaque cible (`dist-test/` reste réservé au build de test Chrome). */
export const DIST_DIRS = { chrome: "dist", firefox: "dist-firefox" };

/** Nom de l'archive de version d'une cible. */
export function archiveName(browser, version) {
  return browser === "chrome" ? `phishguard-extension-${version}.zip` : `phishguard-${browser}-${version}.zip`;
}

/** `--browser=firefox` ou `--browser firefox` dans `argv` ; Chrome par défaut. */
export function browserFromArgs(argv) {
  let browser = "chrome";
  argv.forEach((arg, i) => {
    if (arg.startsWith("--browser=")) browser = arg.slice("--browser=".length);
    else if (arg === "--browser") browser = argv[i + 1] ?? "";
  });
  if (!BROWSERS.includes(browser)) throw new Error(`navigateur inconnu : ${browser} (${BROWSERS.join(", ")})`);
  return browser;
}

/**
 * Manifeste de `browser` à partir de celui de Chrome. Pur : ne modifie pas `manifest`.
 */
export function browserManifest(manifest, browser) {
  const copy = structuredClone(manifest);
  if (browser === "chrome") return copy;
  if (browser !== "firefox") throw new Error(`navigateur inconnu : ${browser}`);
  const { service_worker: script, type, ...rest } = copy.background ?? {};
  if (!script || Object.keys(rest).length > 0) {
    throw new Error("manifeste Chrome : background.service_worker seul attendu");
  }
  delete copy.minimum_chrome_version;
  copy.background = type ? { scripts: [script], type } : { scripts: [script] };
  copy.browser_specific_settings = {
    gecko: {
      id: GECKO_ID,
      strict_min_version: FIREFOX_MIN_VERSION,
      data_collection_permissions: { required: ["none"] },
    },
    gecko_android: { strict_min_version: FIREFOX_ANDROID_MIN_VERSION },
  };
  return copy;
}
