/**
 * Classes de caractères des expressions régulières **de Python**, pour porter à
 * l'identique quelques expressions de l'API (liens et expéditeur d'un email, étape 5.6).
 *
 * Les expressions JavaScript ne voient pas les mêmes caractères :
 *
 * | Python (`str`)            | JavaScript (`u`)                 |
 * |---------------------------|----------------------------------|
 * | `\w` : `isalnum()` ou `_` | `\w` : `[A-Za-z0-9_]` seulement  |
 * | `\s` : `isspace()`        | `\s` : autre liste (U+FEFF, pas U+001C) |
 * | `\b` : bord d'un `\w` Unicode | `\b` : bord d'un `\w` ASCII  |
 * | `[a-z]` + `re.I` : `İ ı ſ K` en plus | `/[a-z]/iu` : `ſ K` seulement |
 *
 * Les tables viennent de Python (`unicode-data.json`) : rien n'est recopié à la main.
 */

import data from "../generated/unicode-data.json";

type Ranges = readonly (readonly number[])[];

const cp = (value: number) => `\\u{${value.toString(16)}}`;

/** Contenu d'une classe `[...]` (sans les crochets) pour des plages de points de code. */
const rangesClass = (ranges: Ranges): string =>
  ranges.map(([a, b]) => (a === b ? cp(a!) : `${cp(a!)}-${cp(b!)}`)).join("");

/** `\w` de Python, à placer dans une classe : `[${WORD}]`. */
export const WORD = rangesClass(data.word);
/** `\s` de Python, à placer dans une classe : `[${SPACE}]`, et `[^${SPACE}]` pour `\S`. */
export const SPACE = rangesClass(data.space);

const IGNORECASE: Readonly<Record<string, readonly number[]>> = data.ignorecase;

/** Une lettre ASCII sous `re.IGNORECASE`, dans une classe : `[${letterIgnoreCase("s")}]`. */
export function letterIgnoreCase(letter: string): string {
  const lower = letter.toLowerCase();
  return `${lower}${lower.toUpperCase()}${(IGNORECASE[lower] ?? []).map(cp).join("")}`;
}

/** `[a-z]` sous `re.IGNORECASE`, dans une classe. */
export const ASCII_LETTER_IGNORECASE = `a-zA-Z${Object.values(IGNORECASE).flat().map(cp).join("")}`;

// Hors d'une classe, le mode `u` n'admet l'échappement que des caractères de syntaxe et de « / ».
const escape = (char: string) => char.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&");

/** Texte littéral sous `re.IGNORECASE` : `https` → `[hH][tT][tT][pP][sSſ]`. */
export const literalIgnoreCase = (text: string): string =>
  Array.from(text, (char) => (/[a-z]/i.test(char) ? `[${letterIgnoreCase(char)}]` : escape(char))).join("");

/** `\b` de Python : bord entre un caractère `\w` (Unicode) et un autre. */
export const WORD_BOUNDARY = `(?:(?<=[${WORD}])(?![${WORD}])|(?<![${WORD}])(?=[${WORD}]))`;

/** `$` de Python (sans `re.M`) : fin de la chaîne, ou juste avant un saut de ligne final. */
export const PY_END = "(?=\\n?$)";
