/**
 * Audit des permissions et de la sécurité (étape 5.9) : ce que promet
 * `docs/extension-privacy.md` est vérifié ici, sur le manifeste et les sources.
 *
 * - le tableau des autorisations du document (celui du Chrome Web Store) contient
 *   **exactement** les autorisations du manifeste : en ajouter une sans la justifier fait
 *   échouer ce test ;
 * - le manifeste n'ouvre rien d'autre (ni hôte permanent, ni ressource exposée aux pages,
 *   ni messages des sites) et garde une CSP stricte pour les scripts ;
 * - les sources n'emploient que les API Chrome attendues, jamais `storage.sync`, et ne
 *   fabriquent aucun identifiant.
 *
 * Le build (`build.mjs`) contrôle en plus les bundles : `eval`, injection HTML, réseau.
 */

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const ROOT = new URL("..", import.meta.url).pathname.replace(/^\/([A-Z]:)/, "$1");
const manifest = JSON.parse(readFileSync(join(ROOT, "static/manifest.json"), "utf-8")) as Record<string, unknown>;
const privacy = readFileSync(join(ROOT, "../docs/extension-privacy.md"), "utf-8");
const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf-8")) as Record<string, unknown>;

/** Limite d'une justification dans le formulaire du Chrome Web Store. */
const STORE_JUSTIFICATION_MAX = 1000;

type Kind = "requise" | "optionnelle" | "script de contenu" | "hôte optionnel";

/** Autorisations déclarées par le manifeste, avec leur type. */
function declared(): Map<string, Kind> {
  const out = new Map<string, Kind>();
  const list = (key: string) => (manifest[key] as string[] | undefined) ?? [];
  for (const p of list("permissions")) out.set(p, "requise");
  for (const p of list("optional_permissions")) out.set(p, "optionnelle");
  for (const p of list("optional_host_permissions")) out.set(p, "hôte optionnel");
  for (const script of (manifest["content_scripts"] as { matches: string[] }[] | undefined) ?? []) {
    for (const match of script.matches) out.set(match, "script de contenu");
  }
  return out;
}

/** Lignes du tableau entre les marqueurs `permissions:start` et `permissions:end`. */
function documented(): { name: string; kind: string; justification: string }[] {
  const section = /<!-- permissions:start -->([\s\S]*?)<!-- permissions:end -->/.exec(privacy);
  if (!section) throw new Error("tableau des autorisations introuvable dans docs/extension-privacy.md");
  return section[1]!
    .split("\n")
    .filter((line) => line.startsWith("| `"))
    .map((line) => {
      const [name, kind, justification] = line.split("|").slice(1, 4).map((cell) => cell.trim());
      return { name: name!.replace(/^`|`$/g, ""), kind: kind!, justification: justification! };
    });
}

function sources(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    return statSync(path).isDirectory() ? sources(path) : name.endsWith(".ts") ? [path] : [];
  });
}
/** Code sans commentaires : un commentaire qui cite `storage.sync` pour l'exclure est permis. */
const code = (path: string) => readFileSync(path, "utf-8").replace(/\/\*[\s\S]*?\*\/|\/\/.*$/gm, "");
const SOURCES = sources(join(ROOT, "src")).map((path) => ({
  path: path.slice(ROOT.length).replaceAll("\\", "/"),
  code: code(path),
}));

describe("autorisations", () => {
  it("le document justifie exactement les autorisations du manifeste, avec leur type", () => {
    const rows = documented();
    expect(rows.map((r) => r.name).sort()).toEqual([...declared().keys()].sort());
    for (const row of rows) expect(row.kind, row.name).toBe(declared().get(row.name));
  });

  it("chaque justification tient dans le formulaire du Chrome Web Store, en une phrase", () => {
    for (const { name, justification } of documented()) {
      expect(justification.length, name).toBeGreaterThan(20);
      expect(justification.length, name).toBeLessThanOrEqual(STORE_JUSTIFICATION_MAX);
      // Une phrase : un seul point final, aucun autre point suivi d'un espace et d'une majuscule.
      expect(justification, name).toMatch(/[^.]\.$/);
      expect(/\.\s+\p{Lu}/u.test(justification), name).toBe(false);
    }
  });

  it("aucune autorisation qui avertit à l'installation, hors Gmail", () => {
    expect(manifest["permissions"]).toEqual(["storage", "activeTab", "contextMenus"]);
    expect(manifest["optional_permissions"]).toEqual(["tabs"]);
    expect(manifest["host_permissions"]).toBeUndefined();
  });

  it("le script de contenu ne vise que Gmail, cadre principal, sans accès aux autres pages", () => {
    const scripts = manifest["content_scripts"] as Record<string, unknown>[];
    expect(scripts).toHaveLength(1);
    expect(scripts[0]).toMatchObject({ matches: ["https://mail.google.com/*"], all_frames: false });
    expect(scripts[0]!["match_about_blank"]).toBeUndefined();
    expect(scripts[0]!["match_origin_as_fallback"]).toBeUndefined();
    expect(scripts[0]!["world"]).toBeUndefined(); // monde isolé : la page n'atteint pas le script
  });

  it("rien n'est exposé aux sites : ni ressource, ni messages, ni page remplacée", () => {
    for (const key of [
      "web_accessible_resources",
      "externally_connectable",
      "chrome_url_overrides",
      "chrome_settings_overrides",
      "sandbox",
      "update_url",
      "key",
      "oauth2",
    ]) {
      expect(manifest[key], key).toBeUndefined();
    }
  });
});

describe("politique de contenu (CSP)", () => {
  const csp = (manifest["content_security_policy"] as Record<string, string>)["extension_pages"]!;
  const directives = new Map(
    csp.split(";").map((d) => {
      const [name, ...values] = d.trim().split(/\s+/);
      return [name!, values];
    }),
  );

  it("scripts du paquet seulement, aucun relâchement", () => {
    expect(directives.get("script-src")).toEqual(["'self'"]);
    expect(directives.get("object-src")).toEqual(["'none'"]);
    expect(directives.get("base-uri")).toEqual(["'none'"]);
    expect(csp).not.toMatch(/unsafe-|data:|blob:|filesystem:/);
    // Aucun joker d'hôte (`*`, `*.exemple`) : seul le port de la boucle locale en a un.
    expect(csp.replaceAll(/:\*/g, "")).not.toContain("*");
  });

  it("le seul relâchement est connect-src, pour le serveur choisi par l'utilisateur", () => {
    expect(directives.get("connect-src")).toEqual(["'self'", "https:", "http://localhost:*", "http://127.0.0.1:*"]);
    expect(directives.get("default-src")).toEqual(["'self'"]);
  });

  it("pas de CSP pour un bac à sable (aucune page n'en a)", () => {
    expect(Object.keys(manifest["content_security_policy"] as object)).toEqual(["extension_pages"]);
  });
});

describe("sources", () => {
  // Chaque espace de noms correspond à une autorisation justifiée, ou à aucune (runtime, i18n).
  const ALLOWED_NAMESPACES = ["action", "contextMenus", "i18n", "permissions", "runtime", "storage", "tabs"];

  it("n'emploient que les API Chrome attendues", () => {
    const used = new Set(SOURCES.flatMap((s) => [...s.code.matchAll(/\bchrome\.([A-Za-z0-9]+)/g)].map((m) => m[1]!)));
    expect([...used].sort()).toEqual(ALLOWED_NAMESPACES);
  });

  it.each([
    ["storage.sync", /\bstorage\s*\.\s*sync\b/],
    ["identifiant aléatoire", /\brandomUUID\b|\bgetRandomValues\b|\bMath\s*\.\s*random\b/],
    ["empreinte du navigateur", /\bnavigator\s*\.\s*(userAgent|platform|hardwareConcurrency|deviceMemory|plugins)\b/],
    ["console (journal)", /\bconsole\s*\.\s*(log|info|debug)\b/],
    ["cookies de page", /\bdocument\s*\.\s*cookie\b/],
  ])("aucune trace de %s", (_label, pattern) => {
    const offenders = SOURCES.filter((s) => pattern.test(s.code)).map((s) => s.path);
    expect(offenders).toEqual([]);
  });

  it("chrome.tabs ne sert qu'à l'onglet actif ou désigné, jamais à parcourir les onglets", () => {
    const calls = new Set(SOURCES.flatMap((s) => [...s.code.matchAll(/\bchrome\.tabs\.([A-Za-z]+)/g)].map((m) => m[1]!)));
    expect([...calls].sort()).toEqual(["get", "onUpdated", "query"]);
    // Toute requête vise l'onglet actif de la fenêtre courante : celui où l'on a cliqué.
    const queries = SOURCES.flatMap((s) => [...s.code.matchAll(/\bchrome\.tabs\.query\(([^)]*)\)/g)].map((m) => m[1]!));
    expect(queries.length).toBeGreaterThan(0);
    for (const query of queries) expect(query.replaceAll(/\s/g, "")).toBe("{active:true,currentWindow:true}");
  });
});

describe("chaîne d'approvisionnement", () => {
  it("aucune dépendance d'exécution : seul notre code est embarqué", () => {
    expect(pkg["dependencies"]).toBeUndefined();
    expect(pkg["optionalDependencies"]).toBeUndefined();
  });

  it("versions exactes, scripts d'installation interdits", () => {
    for (const version of Object.values(pkg["devDependencies"] as Record<string, string>)) {
      expect(version).toMatch(/^\d+\.\d+\.\d+$/);
    }
    const npmrc = readFileSync(join(ROOT, ".npmrc"), "utf-8");
    expect(npmrc).toMatch(/^ignore-scripts=true$/m);
    expect(npmrc).toMatch(/^save-exact=true$/m);
  });
});
