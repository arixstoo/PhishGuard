/**
 * Codec `punycode` de Python (`encodings/punycode.py`), traduit ligne à ligne.
 *
 * Ni `URL` ni `punycode.js` : le navigateur applique UTS #46 (autre repli de casse, rejet
 * de caractères interdits), alors que l'extracteur Python appelle directement le codec
 * RFC 3492, sans contrôle. Les features doivent voir l'hôte comme Python le voit.
 *
 * Le décodage calcule en `BigInt` : Python travaille en entiers exacts, et un label
 * malformé de 59 chiffres dépasse largement 2^53.
 */

import { codePoints } from "./text";

const BASE = 36;
const DIGITS = "abcdefghijklmnopqrstuvwxyz0123456789";

export class PunycodeError extends Error {
  override name = "PunycodeError";
}

function threshold(j: number, bias: number): number {
  const res = BASE * (j + 1) - bias;
  return res < 1 ? 1 : res > 26 ? 26 : res;
}

function adapt(delta: bigint, first: boolean, numchars: number): number {
  delta = first ? delta / 700n : delta / 2n;
  delta += delta / BigInt(numchars);
  let divisions = 0n;
  while (delta > 455n) {
    delta = delta / 35n;
    divisions += 36n;
  }
  return Number(divisions + (36n * delta) / (delta + 38n));
}

// --------------------------------------------------------------------------- //
// Encodage
// --------------------------------------------------------------------------- //

function insertionUnsort(text: number[], extended: number[]): number[] {
  let oldchar = 0x80;
  let oldindex = -1;
  const result: number[] = [];
  for (const char of extended) {
    let index = -1;
    let pos = -1;
    const curlen = text.filter((c) => c < char).length;
    let delta = (curlen + 1) * (char - oldchar);
    for (;;) {
      // selective_find
      let found = false;
      while (++pos < text.length) {
        const c = text[pos]!;
        if (c === char) {
          index += 1;
          found = true;
          break;
        } else if (c < char) {
          index += 1;
        }
      }
      if (!found) break;
      delta += index - oldindex;
      result.push(delta - 1);
      oldindex = index;
      delta = 0;
    }
    oldchar = char;
  }
  return result;
}

function generateGeneralizedInteger(n: number, bias: number): string {
  let result = "";
  for (let j = 0; ; j++) {
    const t = threshold(j, bias);
    if (n < t) return result + DIGITS[n]!;
    result += DIGITS[t + ((n - t) % (BASE - t))]!;
    n = Math.floor((n - t) / (BASE - t));
  }
}

/** `text.encode("punycode")` : sans préfixe `xn--`, sans changement de casse. */
export function punycodeEncode(text: string): string {
  const cps = codePoints(text);
  const base = String.fromCodePoint(...cps.filter((c) => c < 0x80));
  const extended = [...new Set(cps.filter((c) => c >= 0x80))].sort((a, b) => a - b);
  const deltas = insertionUnsort(cps, extended);
  let bias = 72;
  let encoded = "";
  deltas.forEach((delta, points) => {
    encoded += generateGeneralizedInteger(delta, bias);
    bias = adapt(BigInt(delta), points === 0, base.length + points + 1);
  });
  return base ? `${base}-${encoded}` : encoded;
}

// --------------------------------------------------------------------------- //
// Décodage (errors="strict")
// --------------------------------------------------------------------------- //

/** `text.encode("ascii").decode("punycode")` ; lève {@link PunycodeError} comme Python. */
export function punycodeDecode(text: string): string {
  // eslint-disable-next-line no-control-regex
  if (!/^[\x00-\x7f]*$/.test(text)) throw new PunycodeError("non-ASCII");
  const pos = text.lastIndexOf("-");
  const base = codePoints(pos === -1 ? "" : text.slice(0, pos));
  const extended = (pos === -1 ? text : text.slice(pos + 1)).toUpperCase();

  let char = 0x80n;
  let position = -1n;
  let bias = 72;
  let extpos = 0;
  while (extpos < extended.length) {
    const first = extpos === 0; // adapt(delta, (extpos == 0), len(base)) en Python
    // decode_generalized_number
    let result = 0n;
    let w = 1n;
    for (let j = 0; ; j++) {
      if (extpos >= extended.length) throw new PunycodeError("incomplete punicode string");
      const c = extended.charCodeAt(extpos++);
      let digit: number;
      if (c >= 0x41 && c <= 0x5a) digit = c - 0x41;
      else if (c >= 0x30 && c <= 0x39) digit = c - 22;
      else throw new PunycodeError("Invalid extended code point");
      const t = threshold(j, bias);
      result += BigInt(digit) * w;
      if (digit < t) break;
      w *= BigInt(BASE - t);
    }
    const delta = result;
    position += delta + 1n;
    const size = BigInt(base.length + 1);
    char += position / size;
    if (char > 0x10ffffn) throw new PunycodeError("Invalid character");
    position %= size;
    base.splice(Number(position), 0, Number(char));
    bias = adapt(delta, first, base.length);
  }
  return String.fromCodePoint(...base);
}
