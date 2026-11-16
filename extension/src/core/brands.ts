/**
 * Marques usurpées et typosquatting : `phishguard.urls.brands` traduit à l'identique.
 *
 * La liste vient de `brands.json` (exportée telle que Python la charge, `strict` déjà
 * résolu). Une marque **stricte** doit apparaître comme mot entier ; une autre peut
 * apparaître dans un segment, tirets retirés.
 */

import reference from "../generated/reference-data.json";

const MIN_TYPO_TOKEN_LENGTH: number = reference.min_typo_token_length;
const GENERIC_USE_CCTLDS: ReadonlySet<string> = new Set(reference.generic_use_cctlds);
const TOKEN_SPLIT_RE = /[^0-9a-z]+/;
const EMPTY: ReadonlySet<string> = new Set();

export interface Brand {
  name: string;
  domains: readonly string[];
  strict: boolean;
  any_cctld: boolean;
}

/** Nombre de modifications au-delà duquel un domaine n'imite plus la marque. */
export const maxTypoEdits = (name: string): number => (name.length < 9 ? 1 : 2);

/** Mots alphanumériques d'un segment, en minuscules. */
export const tokens = (segment: string): string[] =>
  segment.toLowerCase().split(TOKEN_SPLIT_RE).filter(Boolean);

/** Distance de Levenshtein (chaînes ASCII : les mots sont déjà réduits à `[0-9a-z]`). */
export function levenshtein(a: string, b: string): number {
  if (a === b) return 0;
  if (!a.length) return b.length;
  if (!b.length) return a.length;
  let previous = Array.from({ length: b.length + 1 }, (_, j) => j);
  for (let i = 1; i <= a.length; i++) {
    const current = [i];
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      current[j] = Math.min(previous[j]! + 1, current[j - 1]! + 1, previous[j - 1]! + cost);
    }
    previous = current;
  }
  return previous[b.length]!;
}

const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

export class BrandIndex {
  readonly brands: readonly Brand[];
  private readonly official = new Map<string, Set<string>>();
  private readonly anyCctld: ReadonlySet<string>;
  private readonly strict: ReadonlySet<string>;
  private readonly loose: readonly string[];
  private readonly looseRe: RegExp | null;

  constructor(brands: readonly Brand[]) {
    this.brands = [...brands].sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    for (const brand of this.brands) {
      for (const domain of brand.domains) {
        const names = this.official.get(domain) ?? new Set<string>();
        names.add(brand.name);
        this.official.set(domain, names);
      }
    }
    this.anyCctld = new Set(this.brands.filter((b) => b.any_cctld).map((b) => b.name));
    this.strict = new Set(this.brands.filter((b) => b.strict).map((b) => b.name));
    // Plus longs d'abord : à une même position, « paypal » passe avant un nom plus court.
    this.loose = this.brands
      .filter((b) => !b.strict)
      .map((b) => b.name)
      .sort((a, b) => b.length - a.length || (a < b ? -1 : a > b ? 1 : 0));
    this.looseRe = this.loose.length ? new RegExp(this.loose.map(escapeRe).join("|")) : null;
  }

  /** Marques dont `registeredDomain` est un domaine officiel. */
  officialFor(registeredDomain: string): ReadonlySet<string> {
    const official = new Set(this.official.get(registeredDomain) ?? EMPTY);
    const dot = registeredDomain.indexOf(".");
    const label = dot < 0 ? registeredDomain : registeredDomain.slice(0, dot);
    const suffix = dot < 0 ? "" : registeredDomain.slice(dot + 1);
    const tld = suffix.slice(suffix.lastIndexOf(".") + 1);
    if (
      this.anyCctld.has(label) &&
      /^[A-Za-z]{2}$/.test(tld) &&
      !GENERIC_USE_CCTLDS.has(tld)
    ) {
      official.add(label);
    }
    return official;
  }

  /** Première marque trouvée dans les segments, hors marques de `exclude`. */
  find(segments: Iterable<string>, exclude: ReadonlySet<string> = EMPTY): string | null {
    for (const segment of segments) {
      const words = tokens(segment);
      if (!words.length) continue;
      for (const word of words) {
        if (this.strict.has(word) && !exclude.has(word)) return word;
      }
      const joined = words.join("");
      if (exclude.size) {
        for (const name of this.loose) {
          if (!exclude.has(name) && joined.includes(name)) return name;
        }
      } else if (this.looseRe !== null) {
        const match = this.looseRe.exec(joined);
        if (match) return match[0];
      }
    }
    return null;
  }

  /**
   * Distance minimale entre un label de domaine et une marque non stricte, plafonnée à
   * `cap` : `[distance, marque]`, ou `[cap, null]`. Seules les distances `<= cap - 1`
   * comptent (`score_cutoff` de rapidfuzz). Un mot contenu dans le nom de la marque n'est
   * pas comparé à cette marque (`cloud` n'imite pas `icloud`).
   */
  nearest(
    domainLabel: string,
    exclude: ReadonlySet<string> = EMPTY,
    cap = 3,
  ): [number, string | null] {
    const choices = exclude.size ? this.loose.filter((n) => !exclude.has(n)) : this.loose;
    const words = tokens(domainLabel);
    const candidates = new Set([
      words.join(""),
      ...words.filter((w) => w.length >= MIN_TYPO_TOKEN_LENGTH),
    ]);
    let best: [number, string] | null = null;
    for (const candidate of candidates) {
      if (candidate.length < MIN_TYPO_TOKEN_LENGTH) continue;
      for (const name of choices) {
        if (Math.abs(candidate.length - name.length) > cap - 1) continue;
        const distance = levenshtein(candidate, name);
        if (distance > cap - 1) continue;
        if (candidate !== name && name.includes(candidate)) continue;
        if (best === null || distance < best[0] || (distance === best[0] && name < best[1])) {
          best = [distance, name];
        }
      }
    }
    return best === null ? [cap, null] : best;
  }
}

let defaultIndex: BrandIndex | null = null;

export function loadBrands(): BrandIndex {
  defaultIndex ??= new BrandIndex(reference.brands);
  return defaultIndex;
}

let defaultShorteners: ReadonlySet<string> | null = null;

export function loadShorteners(): ReadonlySet<string> {
  defaultShorteners ??= new Set(reference.shorteners);
  return defaultShorteners;
}
