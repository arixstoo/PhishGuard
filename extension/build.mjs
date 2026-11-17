/**
 * Build de l'extension (étape 5.2) : `npm run build` → `dist/`, à charger dans
 * chrome://extensions (mode développeur, « Charger l'extension non empaquetée »).
 *
 *   node build.mjs [--watch] [--allow-missing-model] [--test]
 *
 * `--test` construit dans `dist-test/` une variante qui expose au test automatisé
 * l'analyse du service worker (`globalThis.phishguardTest`) ; jamais à publier.
 * `--test --stub-model` y embarque le modèle de test des parcours Playwright
 * (`e2e/stub-model.mjs`) à la place du modèle signé, absent en CI (étape 5.10).
 *
 * 1. **Modèle** : `models/manifest.json` doit porter une signature Ed25519 valide
 *    (`keys/model-signing.pub`, étape 4.12), et `models/url_v2.json` exactement la taille et
 *    l'empreinte signées. Sinon, le build échoue : l'extension n'embarque jamais un modèle
 *    non signé. `--allow-missing-model` (CI) construit sans modèle ; l'extension l'affiche.
 * 2. **Code** : esbuild regroupe le service worker, les pages (fenêtre contextuelle,
 *    options) et le script Gmail, sans minification (le Chrome Web Store exige un code
 *    lisible), puis vérifie qu'aucun bundle n'emploie `eval`, `new Function`,
 *    `importScripts` (code distant interdit), une injection HTML, ni un canal réseau ;
 *    `fetch` n'est admis que dans `api.ts` et le chargement du modèle.
 * 3. **Fichiers statiques** : manifeste (version reprise de package.json), pages, langues,
 *    icônes générées ici (aucun binaire dans le dépôt).
 */

import { createHash, createPublicKey, verify } from "node:crypto";
import { cpSync, existsSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { deflateSync } from "node:zlib";
import * as esbuild from "esbuild";

const here = dirname(fileURLToPath(import.meta.url));
const repo = join(here, "..");
const args = new Set(process.argv.slice(2));
const testBuild = args.has("--test");
const dist = join(here, testBuild ? "dist-test" : "dist");
const MODEL_ROLE = "url-export";
const MODEL_PATH = "model/url-model.json";

const fail = (message) => {
  console.error(`build : ${message}`);
  process.exit(1);
};
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

// --------------------------------------------------------------------------- //
// 1. Modèle signé
// --------------------------------------------------------------------------- //

/** JSON canonique de Python (`sort_keys`, compact) pour un objet plat ASCII. */
const canonical = (object) =>
  `{${Object.keys(object)
    .sort()
    .map((k) => `${JSON.stringify(k)}:${JSON.stringify(object[k])}`)
    .join(",")}}`;

/** Même contrôle que `phishguard.registry._verify_signature`, champ par champ. */
function verifyManifest(manifestBytes, signatureBytes, publicKeyPem) {
  const signature = JSON.parse(signatureBytes.toString("utf-8"));
  const fields = ["algorithm", "format_version", "key_id", "signature"];
  if (Object.keys(signature).sort().join() !== fields.join()) fail("signature mal formée");
  if (signature.algorithm !== "ed25519" || signature.format_version !== 1) fail("format de signature inconnu");
  if (canonical(signature) !== signatureBytes.toString("utf-8")) fail("signature mal formée (JSON non canonique)");
  const key = createPublicKey(publicKeyPem);
  const raw = key.export({ format: "der", type: "spki" }).subarray(-32);
  if (signature.key_id !== sha256(raw).slice(0, 16)) fail("manifeste signé par une autre clé");
  const bytes = Buffer.from(signature.signature, "base64");
  if (bytes.length !== 64 || bytes.toString("base64") !== signature.signature) fail("signature mal encodée");
  if (!verify(null, manifestBytes, key, bytes)) fail("signature du manifeste des modèles INVALIDE");
}

/** Modèle de test des parcours Playwright (`e2e/stub-model.mjs`), build de test seulement. */
async function stubModelForTests() {
  if (!testBuild) fail("--stub-model n'est admis qu'avec --test : jamais dans dist/");
  const { stubModel } = await import("./e2e/stub-model.mjs");
  const reference = JSON.parse(readFileSync(join(here, "src/generated/reference-data.json"), "utf-8"));
  const bytes = Buffer.from(JSON.stringify(stubModel(reference.feature_extractor)), "utf-8");
  console.warn("build : modèle de TEST (e2e/stub-model.mjs), pour les parcours Playwright seulement");
  return { bytes, sha256: sha256(bytes) };
}

function signedModel() {
  const models = join(repo, "models");
  const manifestPath = join(models, "manifest.json");
  if (!existsSync(manifestPath)) {
    if (args.has("--allow-missing-model")) return null;
    fail("models/manifest.json absent : `make export` puis `make sign`, ou --allow-missing-model");
  }
  const manifestBytes = readFileSync(manifestPath);
  verifyManifest(
    manifestBytes,
    readFileSync(join(models, "manifest.json.sig")),
    readFileSync(join(repo, "keys", "model-signing.pub")),
  );
  const manifest = JSON.parse(manifestBytes.toString("utf-8"));
  const entry = manifest.artifacts.find((a) => a.role === MODEL_ROLE);
  if (!entry || !/^[\w.-]+$/.test(entry.name)) fail(`aucun artefact « ${MODEL_ROLE} » valide dans le manifeste`);
  const bytes = readFileSync(join(models, entry.name));
  if (bytes.length !== entry.size || sha256(bytes) !== entry.sha256) {
    fail(`${entry.name} ne correspond pas au manifeste signé (taille ou empreinte)`);
  }
  // Le modèle doit être celui dont viennent les vecteurs de référence testés.
  const golden = JSON.parse(readFileSync(join(repo, "tests/golden/url_vectors.json"), "utf-8"));
  if (golden.model_export_sha256 !== entry.sha256) {
    fail("le modèle signé n'est pas celui des vecteurs de référence : `make export`");
  }
  console.log(`modèle : ${entry.name} (${(entry.size / 1024).toFixed(0)} Kio), signature valide`);
  return { bytes, sha256: entry.sha256 };
}

// --------------------------------------------------------------------------- //
// 3. Icônes (bouclier), PNG écrits à la main
// --------------------------------------------------------------------------- //

const CRC_TABLE = Array.from({ length: 256 }, (_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});
const crc32 = (bytes) => {
  let c = 0xffffffff;
  for (const b of bytes) c = CRC_TABLE[(c ^ b) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
};
function chunk(type, data) {
  const head = Buffer.alloc(8);
  head.writeUInt32BE(data.length, 0);
  head.write(type, 4, "ascii");
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(Buffer.concat([head.subarray(4), data])), 0);
  return Buffer.concat([head, data, crc]);
}

function shieldPng(size) {
  const segment = (px, py, ax, ay, bx, by) => {
    const t = Math.max(0, Math.min(1, ((px - ax) * (bx - ax) + (py - ay) * (by - ay)) / ((bx - ax) ** 2 + (by - ay) ** 2)));
    return Math.hypot(px - ax - t * (bx - ax), py - ay - t * (by - ay));
  };
  const sample = (u, v) => {
    if (v < 0.07 || v > 0.95) return 0;
    const half = v <= 0.5 ? 0.41 : 0.41 * Math.sqrt(Math.max(0, 1 - ((v - 0.5) / 0.45) ** 2));
    if (Math.abs(u - 0.5) > half) return 0;
    const check = Math.min(segment(u, v, 0.3, 0.5, 0.45, 0.65), segment(u, v, 0.45, 0.65, 0.72, 0.34));
    return check < 0.06 ? 2 : 1; // 1 = bouclier, 2 = coche
  };
  const rows = [];
  const ss = 4; // suréchantillonnage : bords lissés
  for (let y = 0; y < size; y++) {
    const row = [0];
    for (let x = 0; x < size; x++) {
      let shield = 0;
      let check = 0;
      for (let i = 0; i < ss; i++)
        for (let j = 0; j < ss; j++) {
          const s = sample((x + (i + 0.5) / ss) / size, (y + (j + 0.5) / ss) / size);
          if (s >= 1) shield++;
          if (s === 2) check++;
        }
      const a = shield / ss ** 2;
      const w = shield ? check / shield : 0;
      // Bleu #1f4fd1 vers blanc pour la coche.
      row.push(Math.round(0x1f + w * (255 - 0x1f)), Math.round(0x4f + w * (255 - 0x4f)), Math.round(0xd1 + w * (255 - 0xd1)), Math.round(a * 255));
    }
    rows.push(Buffer.from(row));
  }
  const header = Buffer.alloc(13);
  header.writeUInt32BE(size, 0);
  header.writeUInt32BE(size, 4);
  header.set([8, 6, 0, 0, 0], 8); // 8 bits, RGBA
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk("IHDR", header),
    chunk("IDAT", deflateSync(Buffer.concat(rows), { level: 9 })),
    chunk("IEND", Buffer.alloc(0)),
  ]);
}

// --------------------------------------------------------------------------- //
// Build
// --------------------------------------------------------------------------- //

const FORBIDDEN = [
  [/\beval\s*\(/, "eval("],
  [/\bnew\s+Function\s*\(/, "new Function("],
  [/\bimportScripts\s*\(/, "importScripts("],
  [/\.innerHTML\s*=|\.outerHTML\s*=|insertAdjacentHTML|document\.write|createContextualFragment/, "injection HTML"],
  // Autres canaux réseau : aucun n'est employé, aucun ne doit apparaître (étape 5.7).
  [/\bXMLHttpRequest\b|\bnew\s+WebSocket\b|\bEventSource\b|\bsendBeacon\b/,"canal réseau (XHR, WebSocket, EventSource, sendBeacon)"],
];
const BUNDLES = ["background.js", "popup.js", "options.js", "gmail.js"];
// `fetch` n'est permis que dans le service worker (modèle du paquet, api.ts). La CSP
// autorise https: pour le serveur choisi par l'utilisateur : ce contrôle et api.ts
// (réglage + permission d'hôte) sont ce qui empêche tout autre envoi.
const NO_FETCH = ["popup.js", "options.js", "gmail.js"];
const FETCH_ALLOWED_SOURCES = new Set(["src/api.ts", "src/background.ts"]);

/** Sources TypeScript qui appellent `fetch` : seules celles de la liste sont admises. */
function checkSources(dir = join(here, "src")) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) checkSources(path);
    else if (entry.name.endsWith(".ts")) {
      const relative = path.slice(here.length + 1).replaceAll("\\", "/");
      const code = readFileSync(path, "utf-8").replace(/\/\*[\s\S]*?\*\/|\/\/.*$/gm, "");
      if (/\bfetch\s*\(/.test(code) && !FETCH_ALLOWED_SOURCES.has(relative)) {
        fail(`${relative} appelle fetch : seuls ${[...FETCH_ALLOWED_SOURCES].join(", ")} le peuvent`);
      }
    }
  }
}

function checkBundles() {
  for (const name of BUNDLES) {
    const code = readFileSync(join(dist, name), "utf-8");
    if (!testBuild && code.includes("phishguardTest")) fail(`${name} contient les crochets de test`);
    for (const [pattern, label] of FORBIDDEN) {
      if (pattern.test(code)) fail(`${name} contient ${label} : interdit (MV3, XSS, réseau)`);
    }
    if (NO_FETCH.includes(name) && /\bfetch\s*\(/.test(code)) fail(`${name} appelle fetch : interdit hors du service worker`);
  }
}

function writeStatic(model) {
  cpSync(join(here, "static"), dist, { recursive: true });
  const pkg = JSON.parse(readFileSync(join(here, "package.json"), "utf-8"));
  const manifest = JSON.parse(readFileSync(join(here, "static/manifest.json"), "utf-8"));
  manifest.version = pkg.version;
  writeFileSync(join(dist, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
  mkdirSync(join(dist, "icons"), { recursive: true });
  for (const size of [16, 32, 48, 128]) writeFileSync(join(dist, `icons/icon-${size}.png`), shieldPng(size));
  if (model) {
    mkdirSync(join(dist, dirname(MODEL_PATH)), { recursive: true });
    writeFileSync(join(dist, MODEL_PATH), model.bytes);
  }
}

const model = args.has("--stub-model") ? await stubModelForTests() : signedModel();
if (!model) console.warn("build : AUCUN modèle embarqué (--allow-missing-model) : l'extension ne pourra pas analyser");
rmSync(dist, { recursive: true, force: true });
mkdirSync(dist, { recursive: true });

checkSources();

const common = {
  outdir: dist,
  bundle: true,
  platform: "browser",
  target: "chrome127",
  charset: "utf8",
  legalComments: "none",
  minify: false,
  sourcemap: false,
  logLevel: "warning",
  define: {
    __MODEL_PATH__: JSON.stringify(MODEL_PATH),
    __MODEL_SHA256__: JSON.stringify(model ? model.sha256 : ""),
  },
};
// Pages et service worker : modules ES.
const pages = {
  ...common,
  format: "esm",
  entryPoints: {
    background: join(here, testBuild ? "src/background-test.ts" : "src/background.ts"),
    popup: join(here, "src/popup/popup.ts"),
    options: join(here, "src/options/options.ts"),
  },
};
// Script de contenu : script classique (les scripts de contenu ne sont pas des modules),
// enveloppé dans une fonction pour ne rien laisser dans la portée globale.
const contentScript = { ...common, format: "iife", entryPoints: { gmail: join(here, "src/gmail/gmail.ts") } };

if (args.has("--watch")) {
  writeStatic(model);
  for (const options of [pages, contentScript]) await (await esbuild.context(options)).watch();
  console.log("build : surveillance de src/ (Ctrl+C pour arrêter)");
} else {
  await Promise.all([esbuild.build(pages), esbuild.build(contentScript)]);
  checkBundles();
  writeStatic(model);
  for (const name of BUNDLES) {
    console.log(`${name} : ${(statSync(join(dist, name)).size / 1024).toFixed(0)} Kio`);
  }
  console.log(`extension prête : ${dist}`);
}
