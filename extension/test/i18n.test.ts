/**
 * Langues (étape 5.8) : trois catalogues complets et cohérents, substitutions comme
 * `chrome.i18n`, pluriels de chaque langue, aucune clé employée sans traduction.
 */

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { CATALOGS, type Catalog, directionOf, format, LANGUAGES, translator } from "../src/i18n";

const SRC = new URL("../src/", import.meta.url).pathname.replace(/^\/([A-Z]:)/, "$1");
const PLURAL_RE = /_(zero|one|two|few|many|other)$/;
const TOKEN_RE = /\$([A-Za-z0-9_@]+)\$/g;

const baseKey = (key: string) => key.replace(PLURAL_RE, "");
const tokens = (message: string) => new Set([...message.matchAll(TOKEN_RE)].map((m) => m[1]!.toLowerCase()));

function sources(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    return statSync(path).isDirectory() ? sources(path) : name.endsWith(".ts") ? [path] : [];
  });
}

describe("catalogues", () => {
  const singular = (catalog: Catalog) => new Set(Object.keys(catalog).filter((k) => !PLURAL_RE.test(k)));
  const pluralBases = (catalog: Catalog) => new Set(Object.keys(catalog).filter((k) => PLURAL_RE.test(k)).map(baseKey));

  it.each(LANGUAGES.filter((l) => l !== "fr"))("%s a exactement les clés du français", (language) => {
    expect([...singular(CATALOGS[language])].sort()).toEqual([...singular(CATALOGS.fr)].sort());
    expect([...pluralBases(CATALOGS[language])].sort()).toEqual([...pluralBases(CATALOGS.fr)].sort());
  });

  it.each(LANGUAGES)("%s : chaque pluriel a toutes les formes de Intl.PluralRules", (language) => {
    const categories = new Intl.PluralRules(language).resolvedOptions().pluralCategories;
    for (const base of pluralBases(CATALOGS[language])) {
      for (const category of categories) expect(CATALOGS[language], `${base}_${category}`).toHaveProperty(`${base}_${category}`);
    }
  });

  it.each(LANGUAGES)("%s : placeholders déclarés, employés et identiques au français", (language) => {
    for (const [key, entry] of Object.entries(CATALOGS[language])) {
      const declared = new Set(Object.keys(entry.placeholders ?? {}));
      for (const name of tokens(entry.message)) expect(declared, `${language}.${key} : $${name}$`).toContain(name);
      const reference = CATALOGS.fr[key] ?? CATALOGS.fr[`${baseKey(key)}_other`];
      for (const [name, p] of Object.entries(entry.placeholders ?? {})) {
        expect(reference?.placeholders?.[name]?.content, `${language}.${key}.${name}`).toBe(p.content);
      }
    }
  });

  it.each(LANGUAGES)("%s : langCode désigne son propre dossier", (language) => {
    expect(CATALOGS[language]["langCode"]?.message).toBe(language);
  });

  it("aucun message ne contient de HTML (tout est inséré avec textContent)", () => {
    for (const language of LANGUAGES) {
      for (const [key, entry] of Object.entries(CATALOGS[language])) expect(entry.message, key).not.toMatch(/<[a-z/!]/i);
    }
  });
});

describe("clés employées par le code", () => {
  const code = sources(SRC).map((path) => readFileSync(path, "utf-8")).join("\n");
  const keys = new Set(Object.keys(CATALOGS.fr).map(baseKey));
  const has = (key: string) => keys.has(key);

  it("toute clé littérale t(\"…\") existe", () => {
    const literal = [...code.matchAll(/\bt(?:\.plural)?\(\s*"([A-Za-z0-9_]+)"/g)].map((m) => m[1]!);
    expect(literal.length).toBeGreaterThan(50);
    expect(literal.filter((k) => !has(k))).toEqual([]);
  });

  it("toute clé des pages HTML existe", () => {
    const staticDir = new URL("../static/", import.meta.url);
    for (const page of ["popup.html", "options.html"]) {
      const html = readFileSync(new URL(page, staticDir), "utf-8");
      const used = [...html.matchAll(/data-i18n(?:-placeholder|-aria-label)?="([^"]+)"/g)].map((m) => m[1]!);
      expect(used.filter((k) => !has(k)), page).toEqual([]);
    }
  });

  it("toutes les clés composées existent", () => {
    const verdicts = ["safe", "suspicious", "phishing"];
    const reasons = [
      "lookalike_host",
      "host_is_ip",
      "brand_impersonation",
      "has_userinfo",
      "is_shortener",
      "url_too_long",
      "text_domain_mismatch",
      "non_web_link",
      "display_name_spoof",
      "display_name_domain",
      "sender_lookalike",
    ];
    const composed = [
      ...verdicts.flatMap((v) => [`verdict_${v}`, `explain_${v}`, `advice_url_${v}`, `advice_email_${v}`]),
      ...reasons.map((r) => `reason_${r}`),
      ...["allowlist", "lookalike_host", "url_too_long"].flatMap((r) => [`rule_${r}`, `explain_${r === "lookalike_host" ? "lookalike" : r}`]),
      "popupTrustWarning_suspicious",
      "popupTrustWarning_phishing",
      ...["enrichment", "feedback"].flatMap((k) => [`opt_${k}_on`, `opt_${k}_off`]),
    ];
    expect(composed.filter((k) => !has(k))).toEqual([]);
  });

  it("chaque code de raison déclaré en TypeScript a son message", () => {
    // Les unions ReasonCode, LinkReason et SenderReason, lues dans le code lui-même.
    const declared = [...code.matchAll(/export type (?:ReasonCode|LinkReason|SenderReason)\s*=([^;]+);/g)].flatMap((m) =>
      [...m[1]!.matchAll(/"([a-z_]+)"/g)].map((x) => x[1]!),
    );
    expect(declared.length).toBeGreaterThanOrEqual(10);
    expect(declared.filter((reason) => !has(`reason_${reason}`))).toEqual([]);
  });
});

describe("substitutions (comme chrome.i18n.getMessage)", () => {
  const entry = { message: "A $HOST$ B $$ C $2", placeholders: { host: { content: "<$1>" } } };

  it("remplace placeholders, références positionnelles et $$", () => {
    expect(format(entry, ["x.fr", "deux"])).toBe("A <x.fr> B $ C deux");
  });

  it("ne réinterprète jamais une valeur substituée", () => {
    // Un nom d'hôte est contrôlé par l'attaquant : « $2 » ou « $HOST$ » y restent du texte.
    expect(format(entry, ["$2$HOST$", "ignoré"])).toBe("A <$2$HOST$> B $ C ignoré");
  });

  it("formate les nombres selon la langue et choisit la forme plurielle", () => {
    expect(translator("en").plural("gmailTitleSuspicious", 1)).toBe("PhishGuard: 1 suspicious link in this message");
    expect(translator("en").plural("gmailTitleSuspicious", 3)).toBe("PhishGuard: 3 suspicious links in this message");
    expect(translator("fr").plural("gmailTitleSuspicious", 2)).toBe("PhishGuard : 2 liens suspects dans ce message");
    const ar = translator("ar");
    expect(ar.plural("gmailTitleSuspicious", 2)).toContain("رابطان");
    expect(ar.plural("gmailTitleSuspicious", 5)).toContain("روابط");
    expect(ar.plural("gmailTitleSuspicious", 11)).toContain("رابطًا");
  });

  it("donne la direction d'écriture : arabe de droite à gauche", () => {
    expect([directionOf("ar"), directionOf("fr"), directionOf("en")]).toEqual(["rtl", "ltr", "ltr"]);
    expect(translator("ar").dir).toBe("rtl");
  });

  it("revient au français pour une clé absente, à la clé elle-même sinon", () => {
    expect(translator("en")("cle_inexistante")).toBe("cle_inexistante");
  });
});
