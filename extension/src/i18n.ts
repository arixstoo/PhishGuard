/**
 * Langues (étape 5.8) : français, anglais, arabe.
 *
 * `chrome.i18n.getMessage` suit toujours la langue du navigateur : il ne permet pas le
 * choix de langue des options (étape 5.7). Les trois catalogues (`_locales/*`) sont donc
 * embarqués dans chaque script et lus ici, avec le même format et les mêmes
 * substitutions que Chrome (`$NOM$` → `placeholders.nom.content` → `$1`…). En mode
 * « langue du navigateur », c'est Chrome qui choisit le catalogue (`langCode`).
 *
 * Pluriels : `chrome.i18n` n'en gère pas ; l'arabe en a six formes. Une clé plurielle
 * `cle_<catégorie>` suit `Intl.PluralRules` (`one`, `two`, `few`, `many`, `other`…).
 *
 * Aucun texte traduit n'est du HTML : les pages l'insèrent avec `textContent`.
 */

import ar from "../static/_locales/ar/messages.json";
import en from "../static/_locales/en/messages.json";
import fr from "../static/_locales/fr/messages.json";

export const LANGUAGES = ["fr", "en", "ar"] as const;
export type Language = (typeof LANGUAGES)[number];
export type LanguageSetting = Language | "auto";

interface Entry {
  message: string;
  placeholders?: Record<string, { content: string }>;
}
export type Catalog = Readonly<Record<string, Entry>>;

export const CATALOGS: Readonly<Record<Language, Catalog>> = { fr, en, ar } as Record<Language, Catalog>;
export const DEFAULT_LANGUAGE: Language = "fr";

export const isLanguage = (value: unknown): value is Language =>
  typeof value === "string" && (LANGUAGES as readonly string[]).includes(value);

/** Langue effective : celle des options, ou le catalogue que Chrome a retenu pour le navigateur. */
export function resolveLanguage(setting: LanguageSetting): Language {
  if (setting !== "auto") return setting;
  const chosen = typeof chrome !== "undefined" ? chrome.i18n?.getMessage("langCode") : "";
  return isLanguage(chosen) ? chosen : DEFAULT_LANGUAGE;
}

export const directionOf = (language: Language): "rtl" | "ltr" => (language === "ar" ? "rtl" : "ltr");

/** Substitutions de `chrome.i18n.getMessage` : `$1`…`$9`, `$NOM$` (casse ignorée), `$$`. */
export function format(entry: Entry, substitutions: readonly string[]): string {
  const positional = (text: string) =>
    text.replace(/\$(\$|[1-9])/g, (_, ref: string) => (ref === "$" ? "$" : (substitutions[Number(ref) - 1] ?? "")));
  const placeholders = new Map(
    Object.entries(entry.placeholders ?? {}).map(([name, p]) => [name.toLowerCase(), p.content]),
  );
  // Un seul passage : une valeur substituée (un nom d'hôte contrôlé par l'attaquant)
  // n'est jamais réinterprétée comme une référence.
  return entry.message.replace(/\$([A-Za-z0-9_@]+)\$|\$(\$|[1-9])/g, (match, name?: string, ref?: string) => {
    if (name !== undefined) {
      const content = placeholders.get(name.toLowerCase());
      return content === undefined ? match : positional(content);
    }
    return ref === "$" ? "$" : (substitutions[Number(ref) - 1] ?? "");
  });
}

export type Translate = ((key: string, ...substitutions: (string | number)[]) => string) & {
  readonly language: Language;
  readonly dir: "rtl" | "ltr";
  /** Message pluriel : `cle_one`, `cle_other`… selon le nombre. */
  plural: (key: string, count: number, ...substitutions: (string | number)[]) => string;
};

export function translator(language: Language): Translate {
  const catalog = CATALOGS[language];
  const fallback = CATALOGS[DEFAULT_LANGUAGE];
  const rules = new Intl.PluralRules(language);
  const numbers = new Intl.NumberFormat(language);
  const text = (value: string | number) => (typeof value === "number" ? numbers.format(value) : value);
  const t = (key: string, ...substitutions: (string | number)[]) => {
    const entry = catalog[key] ?? fallback[key];
    return entry ? format(entry, substitutions.map(text)) : key;
  };
  const plural = (key: string, count: number, ...substitutions: (string | number)[]) => {
    const category = rules.select(count);
    const chosen = catalog[`${key}_${category}`] ? `${key}_${category}` : `${key}_other`;
    return t(chosen, count, ...substitutions);
  };
  return Object.assign(t, { language, dir: directionOf(language), plural });
}

/** Applique langue et direction à une page de l'extension, et traduit ses `data-i18n`. */
export function localizePage(t: Translate, root: Document = document): void {
  root.documentElement.lang = t.language;
  root.documentElement.dir = t.dir;
  for (const node of root.querySelectorAll<HTMLElement>("[data-i18n]")) {
    node.textContent = t(node.dataset["i18n"]!);
  }
  for (const node of root.querySelectorAll<HTMLElement>("[data-i18n-placeholder]")) {
    node.setAttribute("placeholder", t(node.dataset["i18nPlaceholder"]!));
  }
  for (const node of root.querySelectorAll<HTMLElement>("[data-i18n-aria-label]")) {
    node.setAttribute("aria-label", t(node.dataset["i18nAriaLabel"]!));
  }
}
