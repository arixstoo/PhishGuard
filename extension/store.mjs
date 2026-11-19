/**
 * Fiche des stores (étapes 6.9 et 6.10) : `npm run store`.
 *
 *   npm run store            # vérifie store/listing.json, écrit release/store/<version>/
 *   npm run store -- --check # vérifie seulement (CI)
 *
 * Le Chrome Web Store et addons.mozilla.org n'ont pas d'API pour la fiche elle-même
 * (textes, pratiques de confidentialité) : elle se remplit à la main dans leur tableau de
 * bord. Ce script en fait une **opération de copier-coller vérifiée** :
 *
 * 1. **Contrôles** (`validateListing`, aussi lancés par `test/store.test.ts`) :
 *    - limites des stores : nom ≤ 75 caractères, résumé ≤ 132, description ≤ 16 000,
 *      justification ≤ 1 000 ;
 *    - le résumé de chaque langue est `extDescription` de `static/_locales` (une seule
 *      source : le manifeste et la fiche ne peuvent pas diverger) ;
 *    - une justification **par autorisation du manifeste**, ni plus ni moins ;
 *    - aucune donnée déclarée collectée, aucun code distant : ce que dit
 *      docs/extension-privacy.md, et ce que vérifient les tests et le build ;
 *    - chaque libellé de l'interface cité entre guillemets dans une description existe
 *      dans le catalogue de la langue : la fiche ne promet pas un bouton qui n'existe pas ;
 *    - images de `release/store/assets/` aux dimensions exigées, si elles existent
 *      (`npm run store:assets`).
 * 2. **Rendu** dans `release/store/<version>/` : un fichier texte par langue, et
 *    `dashboard.md`, toutes les réponses du formulaire dans l'ordre des onglets.
 */

import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));

export const LIMITS = { name: 75, summary: 132, description: 16_000, justification: 1_000, singlePurpose: 1_000 };

/** Dimensions exigées par le Chrome Web Store (et acceptées par AMO). */
export const IMAGE_SIZES = {
  screenshot: [1280, 800],
  "promo-small": [440, 280],
  "promo-marquee": [1400, 560],
  "store-icon": [128, 128],
};

export const DATA_CATEGORIES = [
  "personally_identifiable_information",
  "health_information",
  "financial_and_payment_information",
  "authentication_information",
  "personal_communications",
  "location",
  "web_history",
  "user_activity",
  "website_content",
];

/** Autorisations du manifeste, toutes sortes confondues (mêmes règles que test/audit.test.ts). */
export function manifestPermissions(manifest) {
  const out = [
    ...(manifest.permissions ?? []),
    ...(manifest.optional_permissions ?? []),
    ...(manifest.optional_host_permissions ?? []),
    ...(manifest.content_scripts ?? []).flatMap((script) => script.matches),
  ];
  return [...new Set(out)].sort();
}

/** Libellés cités entre guillemets : « … » (fr, ar) ou "…" (en). */
export function quotedLabels(text) {
  return [...text.matchAll(/«\s?([^»]+?)\s?»|"([^"]+)"/g)].map((m) => (m[1] ?? m[2]).trim());
}

/** Largeur et hauteur d'un PNG (en-tête IHDR), ou `null`. */
export function pngSize(bytes) {
  const signature = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
  if (bytes.length < 24 || signature.some((b, i) => bytes[i] !== b)) return null;
  if (bytes.toString("ascii", 12, 16) !== "IHDR") return null;
  return [bytes.readUInt32BE(16), bytes.readUInt32BE(20)];
}

/** Type d'image attendu d'après le nom (`screenshot-1-phishing.png` → `screenshot`). */
export function imageKind(name) {
  return Object.keys(IMAGE_SIZES).find((kind) => name === `${kind}.png` || name.startsWith(`${kind}-`)) ?? null;
}

/**
 * Erreurs de la fiche (liste vide : fiche valide).
 *
 * `catalogs` : `{ fr: messages.json, … }` ; `descriptions` : `{ fr: texte, … }`.
 */
export function validateListing({ listing, manifest, catalogs, descriptions }) {
  const errors = [];
  const check = (condition, message) => condition || errors.push(message);

  check(listing.format_version === 1, "format_version 1 attendu");
  check(listing.default_locale === manifest.default_locale, "default_locale différent du manifeste");
  const catalogLocales = Object.keys(catalogs).sort();
  check(
    JSON.stringify([...listing.locales].sort()) === JSON.stringify(catalogLocales),
    `langues de la fiche (${listing.locales}) ≠ langues de l'extension (${catalogLocales})`,
  );

  for (const locale of listing.locales) {
    const catalog = catalogs[locale];
    if (!catalog) continue;
    const name = catalog.extName?.message ?? "";
    const summary = catalog.extDescription?.message ?? "";
    const description = descriptions[locale] ?? "";
    check(name.length > 0 && name.length <= LIMITS.name, `${locale} : nom vide ou > ${LIMITS.name} caractères`);
    check(summary.length >= 30 && summary.length <= LIMITS.summary, `${locale} : résumé hors de 30 à ${LIMITS.summary} caractères (${summary.length})`);
    check(description.length >= 500, `${locale} : description trop courte (${description.length} caractères)`);
    check(description.length <= LIMITS.description, `${locale} : description > ${LIMITS.description} caractères`);
    check(!/\r/.test(description), `${locale} : fins de ligne Windows dans la description`);
    check(description.includes(listing.urls.homepage), `${locale} : la description doit citer ${listing.urls.homepage}`);
    for (const url of description.match(/https?:\/\/\S+/g) ?? []) {
      check(Object.values(listing.urls).includes(url), `${locale} : lien ${url} absent de listing.urls`);
    }
    const labels = new Set(Object.values(catalog).map((entry) => entry.message));
    for (const label of quotedLabels(description)) {
      check(labels.has(label), `${locale} : « ${label} » cité dans la description, absent de l'interface`);
    }
    for (const shot of listing.screenshots) {
      check(Boolean(shot.caption?.[locale]), `${locale} : légende manquante pour ${shot.id}`);
      check(Boolean(shot.subtitle?.[locale]), `${locale} : sous-titre manquant pour ${shot.id}`);
    }
    check(Boolean(listing.promo?.tagline?.[locale]), `${locale} : accroche de l'image promotionnelle manquante`);
  }

  for (const [lang, text] of Object.entries(listing.single_purpose)) {
    check(text.length > 10 && text.length <= LIMITS.singlePurpose, `objectif unique (${lang}) hors limites`);
  }

  const declared = manifestPermissions(manifest);
  const justified = Object.keys(listing.permissions).sort();
  check(
    JSON.stringify(justified) === JSON.stringify(declared),
    `justifications (${justified.join(", ")}) ≠ autorisations du manifeste (${declared.join(", ")})`,
  );
  for (const [permission, text] of Object.entries(listing.permissions)) {
    check(text.length > 20 && text.length <= LIMITS.justification, `${permission} : justification hors limites`);
  }

  check(listing.remote_code.uses_remote_code === false, "code distant déclaré : le build l'interdit");
  const collected = listing.data_usage.collected;
  check(
    JSON.stringify(Object.keys(collected).sort()) === JSON.stringify([...DATA_CATEGORIES].sort()),
    "catégories de données différentes de celles du formulaire",
  );
  for (const [category, value] of Object.entries(collected)) {
    check(value === false, `${category} déclaré collecté : contredit docs/extension-privacy.md`);
  }
  for (const [certification, value] of Object.entries(listing.data_usage.certifications)) {
    check(value === true, `certification ${certification} non donnée`);
  }
  for (const [key, url] of Object.entries(listing.urls)) {
    check(/^https:\/\/[^\s]+$/.test(url), `${key} : adresse https attendue`);
  }
  return errors;
}

/** Erreurs des images déjà produites dans `assetsDir` (aucune image : aucune erreur). */
export function validateAssets(assetsDir, listing) {
  const errors = [];
  if (!existsSync(assetsDir)) return errors;
  for (const locale of readdirSync(assetsDir)) {
    const dir = join(assetsDir, locale);
    const names = readdirSync(dir).filter((n) => n.endsWith(".png"));
    for (const name of names) {
      const kind = imageKind(name);
      const size = pngSize(readFileSync(join(dir, name)));
      if (!kind) errors.push(`${locale}/${name} : type d'image inconnu`);
      else if (!size || size[0] !== IMAGE_SIZES[kind][0] || size[1] !== IMAGE_SIZES[kind][1]) {
        errors.push(`${locale}/${name} : ${size ? size.join("×") : "PNG illisible"}, attendu ${IMAGE_SIZES[kind].join("×")}`);
      }
    }
    for (const shot of listing.screenshots) {
      if (!names.includes(`screenshot-${shot.id}.png`)) errors.push(`${locale} : screenshot-${shot.id}.png manquante`);
    }
  }
  return errors;
}

function load() {
  const listing = JSON.parse(readFileSync(join(here, "store/listing.json"), "utf-8"));
  const manifest = JSON.parse(readFileSync(join(here, "static/manifest.json"), "utf-8"));
  const catalogs = {};
  const descriptions = {};
  for (const locale of readdirSync(join(here, "static/_locales"))) {
    catalogs[locale] = JSON.parse(readFileSync(join(here, "static/_locales", locale, "messages.json"), "utf-8"));
    const path = join(here, "store", `description.${locale}.txt`);
    descriptions[locale] = existsSync(path) ? readFileSync(path, "utf-8") : "";
  }
  const pkg = JSON.parse(readFileSync(join(here, "package.json"), "utf-8"));
  return { listing, manifest, catalogs, descriptions, version: pkg.version };
}

const yes = (value) => (value ? "Oui" : "Non");

function dashboard({ listing, catalogs, version }) {
  const lines = [
    `# Fiche des stores, version ${version}`,
    "",
    "Généré par `npm run store` depuis `extension/store/listing.json` : ne pas modifier ici.",
    "Ordre des onglets du tableau de bord du Chrome Web Store ; AMO à la fin.",
    "",
    "## 1. Package",
    "",
    `- Chrome : \`release/phishguard-extension-${version}.zip\` (et son \`.sha256\`).`,
    `- Firefox : \`release/phishguard-firefox-${version}.zip\` ; sources : \`release/phishguard-source-${version}.zip\`.`,
    "",
    "## 2. Fiche (« Store listing »)",
    "",
    `Catégorie : ${listing.category.chrome}. Langue par défaut : ${listing.default_locale}.`,
    "",
  ];
  for (const locale of listing.locales) {
    lines.push(
      `- **${locale}** : nom « ${catalogs[locale].extName.message} », résumé repris du manifeste, description : \`listing-${locale}.txt\`, images : \`assets/${locale}/\`.`,
    );
  }
  lines.push(
    "",
    `Site : ${listing.urls.homepage}`,
    `Assistance : ${listing.urls.support}`,
    "",
    "## 3. Pratiques de confidentialité (« Privacy practices »)",
    "",
    `**Objectif unique** : ${listing.single_purpose.en}`,
    "",
    "**Justification des autorisations** (une par autorisation, champ par champ) :",
    "",
    "| Autorisation | Justification |",
    "|---|---|",
    ...Object.entries(listing.permissions).map(([p, text]) => `| \`${p}\` | ${text} |`),
    "",
    `**Code distant** : ${listing.remote_code.uses_remote_code ? "Oui" : "Non, je n'utilise pas de code distant"}. ${listing.remote_code.justification}`,
    "",
    "**Données collectées** : aucune case cochée.",
    "",
    "| Catégorie | Collectée |",
    "|---|---|",
    ...Object.entries(listing.data_usage.collected).map(([c, v]) => `| ${c.replaceAll("_", " ")} | ${yes(v)} |`),
    "",
    "**Certifications** (les trois cases cochées) :",
    "",
    ...Object.entries(listing.data_usage.certifications).map(([c, v]) => `- ${c.replaceAll("_", " ")} : ${yes(v)}`),
    "",
    `**Politique de confidentialité** : ${listing.urls.privacy_policy}`,
    "",
    "## 4. Distribution",
    "",
    "Premier envoi : visibilité **non répertoriée** (« Unlisted ») pour les testeurs de la bêta,",
    "puis **publique** après leurs retours (docs/store.md, section 5).",
    "",
    "## 5. addons.mozilla.org",
    "",
    `- Catégorie : ${listing.category.firefox.join(", ")} ; licence : MIT ; politique : ${listing.urls.privacy_policy}.`,
    `- Collecte de données : \`${listing.data_usage.firefox_data_collection_permissions.join(", ")}\` (déclarée dans le manifeste).`,
    `- Code source : ${listing.urls.source}, et l'archive des sources (code regroupé par esbuild : AMO l'exige).`,
    "- Notes pour les relecteurs : `docs/store.md`, section « Reconstruire l'extension ».",
    "",
  );
  return lines.join("\n");
}

function main() {
  const data = load();
  const assetsDir = join(here, "release/store/assets");
  const errors = [...validateListing(data), ...validateAssets(assetsDir, data.listing)];
  if (errors.length > 0) {
    for (const error of errors) console.error(`store : ${error}`);
    process.exit(1);
  }
  console.log(`store : fiche valide (${data.listing.locales.join(", ")}, ${Object.keys(data.listing.permissions).length} autorisations)`);
  if (process.argv.includes("--check")) return;
  const out = join(here, "release/store", data.version);
  mkdirSync(out, { recursive: true });
  for (const locale of data.listing.locales) {
    const catalog = data.catalogs[locale];
    writeFileSync(
      join(out, `listing-${locale}.txt`),
      `${catalog.extName.message}\n\n${catalog.extDescription.message}\n\n${data.descriptions[locale]}`,
    );
  }
  writeFileSync(join(out, "dashboard.md"), dashboard(data));
  console.log(`store : release/store/${data.version}/ (dashboard.md, listing-*.txt)`);
  if (!existsSync(assetsDir)) console.warn("store : aucune image ; npm run store:assets pour les produire");
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) main();
