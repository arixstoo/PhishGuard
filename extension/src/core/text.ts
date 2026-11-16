/**
 * Chaînes « à la Python » : points de code et propriétés Unicode de l'interpréteur.
 *
 * Python compte et parcourt les chaînes par **point de code** ; JavaScript, par unité
 * UTF-16. `len("😀")` vaut 1 en Python, `"😀".length` vaut 2 : toute longueur, tout
 * comptage et toute entropie passent donc par {@link codePoints}.
 *
 * Les propriétés (`str.isalpha`, `str.isdigit`, `str.isspace`, catégories Cf et Cc,
 * `unicodedata.combining`, écriture d'une lettre) viennent de tables générées depuis
 * Python (`scripts/export_extension_data.py`), pas des classes `\p{...}` du moteur
 * JavaScript : elles suivent une autre version d'Unicode et d'autres définitions
 * (`isdigit` inclut les exposants, l'écriture est déduite du *nom* du caractère).
 */

import data from "../generated/unicode-data.json";

type Ranges = readonly (readonly number[])[];

/** Version d'Unicode des tables (celle de l'interpréteur Python qui les a produites). */
export const UNIDATA_VERSION: string = data.unidata_version;

function findRange(ranges: Ranges, cp: number): number {
  let lo = 0;
  let hi = ranges.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    const range = ranges[mid]!;
    if (cp < range[0]!) hi = mid - 1;
    else if (cp > range[1]!) lo = mid + 1;
    else return mid;
  }
  return -1;
}

const inRanges = (ranges: Ranges) => (cp: number) => findRange(ranges, cp) >= 0;

/** `str.isalpha()` d'un caractère : lettre (catégories Lu, Ll, Lt, Lm, Lo). */
export const isAlpha = inRanges(data.letters);
/** `str.isdigit()` d'un caractère : chiffres décimaux, mais aussi `²` ou `①`. */
export const isDigit = inRanges(data.digit);
/** `str.isspace()` d'un caractère (et `\s` des expressions de Python). */
export const isSpace = inRanges(data.space);
/** Catégorie Unicode Cf (largeur nulle, marques de direction, U+FEFF…). */
export const isFormat = inRanges(data.format);
/** Catégorie Unicode Cc (contrôles C0 et C1). */
export const isControl = inRanges(data.control);
/** `unicodedata.combining(c) != 0` : marque combinante (accent détaché). */
export const isCombining = inRanges(data.combining);

/**
 * Écriture d'une lettre, comme `phishguard.urls.idn.char_script` : premier mot de son nom
 * Unicode (`LATIN`, `CYRILLIC`, `HAN`…), `null` si ce n'est pas une lettre.
 */
export function charScript(cp: number): string | null {
  const index = findRange(data.letters, cp);
  return index < 0 ? null : data.scripts[data.letters[index]![2]!]!;
}

/** Points de code d'une chaîne (un surrogate isolé compte pour un). */
export function codePoints(text: string): number[] {
  const out: number[] = [];
  for (const char of text) out.push(char.codePointAt(0)!);
  return out;
}

/** `len(text)` de Python. */
export function pyLen(text: string): number {
  let n = 0;
  for (const _ of text) n++;
  return n;
}

/** Nombre de points de code qui vérifient `predicate`. */
export function countCodePoints(text: string, predicate: (cp: number) => boolean): number {
  let n = 0;
  for (const char of text) if (predicate(char.codePointAt(0)!)) n++;
  return n;
}

// eslint-disable-next-line no-control-regex
const ASCII_RE = /^[\x00-\x7f]*$/;
const ASCII_DIGITS_RE = /^[0-9]+$/;
const ASCII_ALPHA_RE = /^[A-Za-z]+$/;

/** `str.isascii()`. */
export const isAscii = (text: string): boolean => ASCII_RE.test(text);
/** `s.isascii() and s.isdigit()` (faux pour la chaîne vide, comme en Python). */
export const isAsciiDigits = (text: string): boolean => ASCII_DIGITS_RE.test(text);
/** `s.isascii() and s.isalpha()`. */
export const isAsciiAlpha = (text: string): boolean => ASCII_ALPHA_RE.test(text);

/** `str.isalpha()` d'une chaîne : non vide et faite de lettres. */
export function isAlphaString(text: string): boolean {
  if (text === "") return false;
  for (const char of text) if (!isAlpha(char.codePointAt(0)!)) return false;
  return true;
}

/** `str.strip()` sans argument : espaces Unicode de Python retirés aux deux bords. */
export function pyStrip(text: string): string {
  // Indices en unités UTF-16 : pas de reconstruction par points de code (une URL peut
  // faire des mégaoctets, trop pour String.fromCodePoint(...)). Les espaces de Python
  // sont tous dans le plan multilingue de base : une unité chacun.
  let start = 0;
  let end = text.length;
  while (start < end && isSpace(text.charCodeAt(start))) start++;
  while (end > start && isSpace(text.charCodeAt(end - 1))) end--;
  return text.slice(start, end);
}

/** `text.rstrip(chars)` (ensemble de caractères BMP). */
export function rstripChars(text: string, chars: string): string {
  let end = text.length;
  while (end > 0 && chars.includes(text[end - 1]!)) end--;
  return text.slice(0, end);
}

/** `s.partition(sep)`. */
export function partition(text: string, sep: string): [string, string, string] {
  const i = text.indexOf(sep);
  return i < 0 ? [text, "", ""] : [text.slice(0, i), sep, text.slice(i + sep.length)];
}

/** `s.rpartition(sep)`. */
export function rpartition(text: string, sep: string): [string, string, string] {
  const i = text.lastIndexOf(sep);
  return i < 0 ? ["", "", text] : [text.slice(0, i), sep, text.slice(i + sep.length)];
}

/** UTF-8 avec `errors="surrogatepass"` : un surrogate isolé est encodé sur 3 octets. */
export function utf8SurrogatePass(text: string): Uint8Array {
  const bytes: number[] = [];
  for (const char of text) {
    const cp = char.codePointAt(0)!;
    if (cp < 0x80) bytes.push(cp);
    else if (cp < 0x800) bytes.push(0xc0 | (cp >> 6), 0x80 | (cp & 0x3f));
    else if (cp < 0x10000)
      bytes.push(0xe0 | (cp >> 12), 0x80 | ((cp >> 6) & 0x3f), 0x80 | (cp & 0x3f));
    else
      bytes.push(
        0xf0 | (cp >> 18),
        0x80 | ((cp >> 12) & 0x3f),
        0x80 | ((cp >> 6) & 0x3f),
        0x80 | (cp & 0x3f),
      );
  }
  return Uint8Array.from(bytes);
}
