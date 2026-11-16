/**
 * Noms de domaine internationalisés : `phishguard.urls.idn` traduit à l'identique.
 *
 * Punycode (codec de Python), écritures déduites des noms Unicode (tables générées) et
 * table de confusables écrite à la main côté Python, exportée telle quelle.
 */

import reference from "../generated/reference-data.json";
import { punycodeDecode, punycodeEncode } from "./punycode";
import { sha256, toHex } from "./sha256";
import { charScript, codePoints, isAscii, isCombining, pyLen, utf8SurrogatePass } from "./text";

const ACE_PREFIX = "xn--";
const MAX_LABEL_LENGTH = 63;

const CONFUSABLES: ReadonlyMap<string, string> = new Map(Object.entries(reference.confusables));
const ALLOWED_SCRIPT_MIXES: readonly ReadonlySet<string>[] = reference.allowed_script_mixes.map(
  (mix) => new Set(mix),
);

/** `label_to_ascii` : NFKC, minuscules, puis Punycode s'il reste du non-ASCII. */
export function labelToAscii(label: string): string {
  if (isAscii(label)) return label.toLowerCase();
  const folded = label.normalize("NFKC").toLowerCase();
  if (isAscii(folded)) return folded;
  if (pyLen(folded) > MAX_LABEL_LENGTH) {
    // Label impossible en DNS : forme ASCII courte et stable (voir idn.py).
    return `${ACE_PREFIX}oversized-${toHex(sha256(utf8SurrogatePass(folded))).slice(0, 32)}`;
  }
  return ACE_PREFIX + punycodeEncode(folded);
}

/** `label_to_unicode` : forme Unicode d'un label `xn--` ; mal encodé, il est rendu tel quel. */
export function labelToUnicode(label: string): string {
  if (!label.startsWith(ACE_PREFIX) || pyLen(label) > MAX_LABEL_LENGTH) return label;
  try {
    return punycodeDecode(label.slice(ACE_PREFIX.length));
  } catch {
    return label;
  }
}

export const toAscii = (host: string): string => host.split(".").map(labelToAscii).join(".");
export const toUnicode = (host: string): string => host.split(".").map(labelToUnicode).join(".");

/** Écritures des lettres d'un label (chiffres et tirets ignorés). */
export function labelScripts(label: string): Set<string> {
  const scripts = new Set<string>();
  for (const cp of codePoints(label)) {
    const script = charScript(cp);
    if (script !== null) scripts.add(script);
  }
  return scripts;
}

const isSubset = (a: ReadonlySet<string>, b: ReadonlySet<string>) => [...a].every((x) => b.has(x));

/** Vrai si un label mêle des écritures non admises ensemble (UTS #39, Highly Restrictive). */
export function isMixedScript(host: string): boolean {
  return host.split(".").some((label) => {
    const scripts = labelScripts(label);
    return scripts.size > 1 && !ALLOWED_SCRIPT_MIXES.some((allowed) => isSubset(scripts, allowed));
  });
}

/** Squelette visuel en minuscules : accents retirés, confusables remplacés. */
export function skeleton(text: string): string {
  let out = "";
  for (const char of text.toLowerCase().normalize("NFKD")) {
    if (isCombining(char.codePointAt(0)!)) continue;
    out += CONFUSABLES.get(char) ?? char;
  }
  return out;
}
