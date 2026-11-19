/**
 * Archive de version de l'extension (étape 5.14) : `npm run package`.
 *
 *   npm run package           # build (modèle signé vérifié), puis release/phishguard-extension-<version>.zip
 *   npm run package:firefox   # idem pour Firefox : release/phishguard-firefox-<version>.zip (étape 6.10)
 *
 * 1. **Contrôles** sur `dist/` (ou `dist-firefox/`) : construit par `npm run build` (jamais `dist-test/`), avec
 *    le modèle embarqué, sans crochet de test, manifeste à la version de package.json.
 * 2. **Archive reproductible** : fichiers triés, date fixe (1980-01-01, la plus ancienne
 *    du format ZIP), aucun attribut du système ni champ « extra ». Deux constructions du
 *    même code donnent le même fichier, octet pour octet : un testeur, ou la CI, peut
 *    vérifier que l'archive reçue est bien celle de ce code (empreinte publiée à côté).
 * 3. `release/<nom>.zip.sha256`, au format de `sha256sum -c`.
 *
 * ZIP écrit ici, sans dépendance : en-têtes locaux, répertoire central, fin de
 * répertoire (APPNOTE 6.3.10), compression « deflate ».
 */

import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { deflateRawSync } from "node:zlib";
import { archiveName, browserFromArgs, DIST_DIRS } from "./targets.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const releaseDir = join(here, "release");

const fail = (message) => {
  console.error(`package : ${message}`);
  process.exit(1);
};

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

// 1980-01-01 00:00:00 en format MS-DOS : heure 0, date (0 << 9) | (1 << 5) | 1.
const DOS_TIME = 0;
const DOS_DATE = (1 << 5) | 1;
const UTF8_FLAG = 1 << 11;

function files(dir) {
  return readdirSync(dir, { withFileTypes: true })
    .flatMap((entry) => {
      const path = join(dir, entry.name);
      if (entry.isSymbolicLink()) fail(`lien symbolique refusé dans dist/ : ${entry.name}`);
      return entry.isDirectory() ? files(path) : [path];
    })
    .sort();
}

/** Archive ZIP déterministe de `entries` ([nom, octets]). */
export function zip(entries) {
  const locals = [];
  const centrals = [];
  let offset = 0;
  for (const [name, data] of entries) {
    const nameBytes = Buffer.from(name, "utf-8");
    const compressed = deflateRawSync(data, { level: 9 });
    const crc = crc32(data);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4); // version nécessaire : 2.0 (deflate)
    local.writeUInt16LE(UTF8_FLAG, 6);
    local.writeUInt16LE(8, 8); // deflate
    local.writeUInt16LE(DOS_TIME, 10);
    local.writeUInt16LE(DOS_DATE, 12);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(compressed.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(nameBytes.length, 26);
    local.writeUInt16LE(0, 28);
    locals.push(local, nameBytes, compressed);

    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4); // créé par : MS-DOS, 2.0 (aucun attribut Unix)
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(UTF8_FLAG, 8);
    central.writeUInt16LE(8, 10);
    central.writeUInt16LE(DOS_TIME, 12);
    central.writeUInt16LE(DOS_DATE, 14);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(compressed.length, 20);
    central.writeUInt32LE(data.length, 24);
    central.writeUInt16LE(nameBytes.length, 28);
    central.writeUInt32LE(offset, 42); // le reste (commentaire, disque, attributs) : 0
    centrals.push(central, nameBytes);
    offset += local.length + nameBytes.length + compressed.length;
  }
  const directory = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(directory.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, directory, end]);
}

function main() {
  let browser;
  try {
    browser = browserFromArgs(process.argv.slice(2));
  } catch (error) {
    fail(error.message);
  }
  const dist = join(here, DIST_DIRS[browser]);
  const pkg = JSON.parse(readFileSync(join(here, "package.json"), "utf-8"));
  const manifestPath = join(dist, "manifest.json");
  if (!existsSync(manifestPath)) fail(`${DIST_DIRS[browser]}/ absent : npm run build d'abord`);
  const manifest = JSON.parse(readFileSync(manifestPath, "utf-8"));
  if ((manifest.version_name ?? manifest.version) !== pkg.version) {
    fail(`dist/ a été construit pour ${manifest.version_name ?? manifest.version}, package.json dit ${pkg.version}`);
  }
  if (!existsSync(join(dist, "model", "url-model.json"))) {
    fail("dist/ sans modèle (--allow-missing-model ?) : une version sans modèle n'analyse rien");
  }
  if (browser === "firefox" && !manifest.browser_specific_settings?.gecko?.id) {
    fail("dist-firefox/ sans identifiant gecko : construit sans --browser=firefox ?");
  }
  if (browser === "chrome" && manifest.browser_specific_settings) {
    fail("dist/ porte un manifeste Firefox");
  }
  const entries = files(dist).map((path) => [relative(dist, path).replaceAll("\\", "/"), readFileSync(path)]);
  for (const [name, data] of entries) {
    if (name.endsWith(".js") && data.includes("phishguardTest")) fail(`${name} vient du build de test`);
    if (name.endsWith(".map")) fail(`${name} : pas de carte de sources dans une version`);
  }
  const archive = zip(entries);
  const name = archiveName(browser, pkg.version);
  const digest = createHash("sha256").update(archive).digest("hex");
  mkdirSync(releaseDir, { recursive: true });
  writeFileSync(join(releaseDir, name), archive);
  writeFileSync(join(releaseDir, `${name}.sha256`), `${digest}  ${name}\n`);
  const size = statSync(join(releaseDir, name)).size;
  console.log(`${entries.length} fichiers → release/${name} (${(size / 1024).toFixed(0)} Kio)`);
  console.log(`SHA-256 ${digest}`);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) main();
