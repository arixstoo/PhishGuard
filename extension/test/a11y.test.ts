/**
 * Accessibilité (étape 5.8), ce qui se vérifie sans navigateur :
 *
 * - **contrastes WCAG AA** calculés depuis les couleurs réelles (`theme.css`, clair et
 *   sombre, et la bannière Gmail) : 4,5 pour le texte, 3 pour les contours et le focus ;
 * - structure des pages : langue, libellé de chaque champ, type de chaque bouton, zones
 *   annoncées par les lecteurs d'écran, aucun gestionnaire d'événement en ligne.
 *
 * Le rendu au clavier et au lecteur d'écran se vérifie dans Chromium (docs/extension-ui.md).
 */

import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { BANNER_COLORS } from "../src/gmail/banner";

const read = (name: string) => readFileSync(new URL(`../static/${name}`, import.meta.url), "utf-8");

function luminance(hex: string): number {
  const [r, g, b] = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255);
  const linear = (c: number) => (c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4);
  return 0.2126 * linear(r!) + 0.7152 * linear(g!) + 0.0722 * linear(b!);
}

export function contrast(a: string, b: string): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (hi! + 0.05) / (lo! + 0.05);
}

function tokens(block: string): Record<string, string> {
  return Object.fromEntries([...block.matchAll(/--([a-z-]+):\s*(#[0-9a-f]{6})\s*;/gi)].map((m) => [m[1]!, m[2]!.toLowerCase()]));
}

const css = read("theme.css");
const light = tokens(css.slice(css.indexOf(":root {"), css.indexOf("@media (prefers-color-scheme: dark)")));
const dark = { ...light, ...tokens(css.slice(css.indexOf("@media (prefers-color-scheme: dark)"))) };

// [texte, fond, minimum] : chaque couple réellement affiché par les pages.
const PAIRS: [string, string, number][] = [
  ["fg", "bg", 4.5],
  ["muted", "bg", 4.5],
  ["fg", "surface", 4.5],
  ["muted", "surface", 4.5],
  ["accent", "bg", 4.5], // boutons-liens
  ["accent-fg", "accent", 4.5], // bouton principal
  ["phishing", "bg", 4.5], // avertissements, erreurs
  ...(["safe", "suspicious", "phishing"] as const).flatMap((v): [string, string, number][] => [
    [v, `${v}-bg`, 4.5], // verdict sur sa carte
    ["fg", `${v}-bg`, 4.5], // texte de la carte
    ["muted", `${v}-bg`, 4.5], // « Lien analysé »
    ["focus", `${v}-bg`, 3], // titre focalisé dans la carte
    [v, "bg", 3], // bordure de la carte
  ]),
  ["focus", "bg", 3],
  ["line", "bg", 3], // contour des champs (WCAG 1.4.11)
];

describe.each([
  ["clair", light],
  ["sombre", dark],
])("contrastes du thème %s", (_, theme) => {
  it.each(PAIRS)("%s sur %s ≥ %s", (fg, bg, min) => {
    expect(theme[fg], fg).toBeDefined();
    expect(theme[bg], bg).toBeDefined();
    expect(contrast(theme[fg]!, theme[bg]!)).toBeGreaterThanOrEqual(min);
  });
});

describe("contrastes de la bannière Gmail", () => {
  it.each(["suspicious", "phishing"] as const)("%s", (verdict) => {
    const c = BANNER_COLORS[verdict];
    expect(contrast(c.text, c.background)).toBeGreaterThanOrEqual(4.5);
    expect(contrast(c.accent, c.background)).toBeGreaterThanOrEqual(4.5);
    expect(contrast(c.border, c.background)).toBeGreaterThanOrEqual(3);
    expect(contrast(BANNER_COLORS.focus, c.background)).toBeGreaterThanOrEqual(3);
    // Marque après un lien, sur le fond blanc d'un message.
    expect(contrast(c.border, "#ffffff")).toBeGreaterThanOrEqual(4.5);
  });

  it("bouton « Masquer »", () => {
    const b = BANNER_COLORS.button;
    expect(contrast(b.text, b.background)).toBeGreaterThanOrEqual(4.5);
    expect(contrast(b.border, b.background)).toBeGreaterThanOrEqual(3);
  });
});

describe.each(["popup.html", "options.html"])("structure de %s", (page) => {
  const html = read(page);

  it("déclare sa langue et son encodage", () => {
    expect(html).toMatch(/<html lang="[a-z]{2}">/);
    expect(html).toContain('<meta charset="utf-8" />');
  });

  it("donne un type à chaque bouton (aucun envoi de formulaire involontaire)", () => {
    for (const tag of html.match(/<button\b[^>]*>/g) ?? []) expect(tag).toMatch(/type="(button|submit)"/);
  });

  it("n'a aucun script ni gestionnaire en ligne (CSP script-src 'self')", () => {
    expect(html).not.toMatch(/\son[a-z]+=/i);
    expect(html.match(/<script\b[^>]*>/g)).toEqual([expect.stringMatching(/src="[a-z]+\.js"/)]);
  });

  it("a une zone annoncée aux lecteurs d'écran", () => {
    expect(html).toMatch(/role="status"[^>]*aria-live="polite"/);
  });
});

describe("options.html", () => {
  const html = read("options.html");

  it("associe un libellé à chaque champ", () => {
    const ids = [...html.matchAll(/<(?:input|select)\b[^>]*\bid="([^"]+)"/g)].map((m) => m[1]!);
    expect(ids.length).toBeGreaterThan(5);
    for (const id of ids) expect(html, id).toContain(`for="${id}"`);
  });

  it("relie chaque réglage à la phrase qui dit quelles données partent où", () => {
    for (const id of ["gmail", "auto", "enrichment", "feedback", "language"]) {
      const tag = html.match(new RegExp(`<(?:input|select)\\b[^>]*id="${id}"[^>]*>`))![0];
      const described = tag.match(/aria-describedby="([^"]+)"/)![1]!.split(" ");
      for (const target of described) expect(html).toContain(`id="${target}"`);
    }
  });
});
