/**
 * Fiche des stores (étape 6.9) : `store/listing.json` et les descriptions disent ce que
 * fait l'extension, ni plus ni moins. Les règles sont celles de `store.mjs` ; ce test les
 * applique à la vraie fiche, puis vérifie que chacune attrape bien l'erreur qu'elle vise.
 */

import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { DATA_CATEGORIES, imageKind, LIMITS, pngSize, quotedLabels, validateListing } from "../store.mjs";

const ROOT = new URL("..", import.meta.url).pathname.replace(/^\/([A-Z]:)/, "$1");
const read = (path: string) => readFileSync(join(ROOT, path), "utf-8");
const json = <T = Record<string, any>>(path: string) => JSON.parse(read(path)) as T;

function real() {
  const locales = readdirSync(join(ROOT, "static/_locales"));
  return {
    listing: json("store/listing.json"),
    manifest: json("static/manifest.json"),
    catalogs: Object.fromEntries(locales.map((l) => [l, json<Record<string, { message: string }>>(`static/_locales/${l}/messages.json`)])),
    descriptions: Object.fromEntries(locales.map((l) => [l, read(`store/description.${l}.txt`)])),
  };
}

describe("fiche réelle", () => {
  it("passe tous les contrôles de store.mjs", () => {
    expect(validateListing(real())).toEqual([]);
  });

  it("justifie les autorisations comme docs/extension-privacy.md, autorisation par autorisation", () => {
    const privacy = read("../docs/extension-privacy.md");
    const section = /<!-- permissions:start -->([\s\S]*?)<!-- permissions:end -->/.exec(privacy)![1]!;
    const documented = [...section.matchAll(/^\| `([^`]+)` \|/gm)].map((m) => m[1]).sort();
    expect(Object.keys(real().listing["permissions"]).sort()).toEqual(documented);
  });

  it("déclare le même objectif unique que docs/extension-privacy.md", () => {
    const privacy = read("../docs/extension-privacy.md").replace(/\s+/g, " ");
    expect(privacy).toContain(`*${real().listing["single_purpose"].fr.toLowerCase().replace(/\.$/, "")}.*`);
  });

  it("pointe vers la politique de confidentialité publiée par le site (PRIVACY.md → privacy/)", () => {
    const { urls } = real().listing;
    const mkdocs = read("../mkdocs.yml");
    const site = /^site_url: (\S+)$/m.exec(mkdocs)![1]!;
    expect(urls.homepage).toBe(site);
    expect(urls.privacy_policy).toBe(`${site}privacy/`);
    expect(read("../scripts/docs_site.py")).toContain('"PRIVACY.md": "privacy.md"');
  });

  it("chaque description cite au moins les trois verdicts de l'interface", () => {
    const { catalogs, descriptions } = real();
    for (const [locale, text] of Object.entries(descriptions)) {
      const quoted = quotedLabels(text);
      for (const key of ["verdict_safe", "verdict_phishing", "contextMenuAnalyzeLink"]) {
        expect(quoted, `${locale} : ${key}`).toContain(catalogs[locale]![key]!.message);
      }
    }
  });
});

describe("chaque règle attrape son erreur", () => {
  const broken = (mutate: (data: ReturnType<typeof real>) => void) => {
    const data = structuredClone(real());
    mutate(data);
    return validateListing(data);
  };

  it("autorisation ajoutée au manifeste sans justification", () => {
    const errors = broken((d) => d.manifest["permissions"].push("cookies"));
    expect(errors.join()).toMatch(/justifications/);
  });

  it("donnée déclarée collectée, ou catégorie oubliée", () => {
    expect(broken((d) => (d.listing["data_usage"].collected.web_history = true)).join()).toMatch(/web_history/);
    expect(broken((d) => delete d.listing["data_usage"].collected.location).join()).toMatch(/catégories/);
  });

  it("code distant déclaré", () => {
    expect(broken((d) => (d.listing["remote_code"].uses_remote_code = true)).join()).toMatch(/code distant/);
  });

  it("libellé cité qui n'existe pas dans l'interface", () => {
    const errors = broken((d) => (d.descriptions["fr"] += "\nCliquez sur « Tout bloquer ».\n"));
    expect(errors.join()).toMatch(/Tout bloquer/);
  });

  it("résumé trop long, description trop longue, langue sans fiche", () => {
    expect(broken((d) => (d.catalogs["en"]!["extDescription"]!.message = "x".repeat(LIMITS.summary + 1))).join()).toMatch(/résumé/);
    expect(broken((d) => (d.descriptions["ar"] = "x".repeat(LIMITS.description + 1))).join()).toMatch(/description >/);
    expect(broken((d) => (d.listing["locales"] = ["fr", "en"])).join()).toMatch(/langues/);
  });

  it("lien inconnu ou légende manquante", () => {
    expect(broken((d) => (d.descriptions["en"] += "\nhttps://example.org/\n")).join()).toMatch(/example\.org/);
    expect(broken((d) => delete d.listing["screenshots"][0].caption.ar).join()).toMatch(/légende/);
  });
});

describe("outils", () => {
  it("lit la taille d'un PNG et refuse autre chose", () => {
    const header = Buffer.alloc(24);
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]).copy(header);
    header.write("IHDR", 12, "ascii");
    header.writeUInt32BE(1280, 16);
    header.writeUInt32BE(800, 20);
    expect(pngSize(header)).toEqual([1280, 800]);
    expect(pngSize(Buffer.from("GIF89a-------------------"))).toBeNull();
  });

  it("reconnaît le type d'image par son nom", () => {
    expect(imageKind("screenshot-1-phishing.png")).toBe("screenshot");
    expect(imageKind("promo-small.png")).toBe("promo-small");
    expect(imageKind("store-icon.png")).toBe("store-icon");
    expect(imageKind("photo.png")).toBeNull();
  });

  it("couvre les neuf catégories du formulaire du Chrome Web Store", () => {
    expect(DATA_CATEGORIES).toHaveLength(9);
  });
});
