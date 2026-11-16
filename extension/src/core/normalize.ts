/**
 * Normalisation défensive des URLs et alerte d'hôte (`phishguard.security.normalize`).
 *
 * Seules les parties que lit l'extension sont portées : `normalize_url_text` (NFKC et
 * caractères invisibles retirés, **sans repli** des confusables) et `host_script_alert`,
 * la règle dure `lookalike_host` de la fusion.
 */

import { isMixedScript, labelScripts, skeleton, toUnicode } from "./idn";
import { isAsciiAlpha, isAlpha, isControl, isFormat, rstripChars } from "./text";

export const NORMALIZATION_VERSION = "1.0.0";

export type HostAlert = "mixed_script_label" | "lookalike_label";

const KEPT_CONTROLS = new Set([0x09, 0x0a, 0x0d]);

/** Caractères de format (Cf) et de contrôle (Cc, sauf `\t\n\r`) retirés. */
export function stripInvisible(text: string): string {
  let out = "";
  for (const char of text) {
    const cp = char.codePointAt(0)!;
    if (isFormat(cp) || (isControl(cp) && !KEPT_CONTROLS.has(cp))) continue;
    out += char;
  }
  return out;
}

/** `normalize_url_text(url).text`. */
export const normalizeUrlText = (url: string): string => stripInvisible(url.normalize("NFKC"));

/**
 * `host_script_alert` : alerte forte si l'hôte imite des lettres latines.
 *
 * - `mixed_script_label` : un label mêle des écritures non admises ensemble (`аpple.com`) ;
 * - `lookalike_label` : un label entièrement étranger dont le squelette est latin, dans un
 *   hôte qui contient du latin (`раураl.com`).
 */
export function hostScriptAlert(host: string): HostAlert | null {
  const unicodeHost = toUnicode(rstripChars(host.toLowerCase(), "."));
  if (isMixedScript(unicodeHost)) return "mixed_script_label";
  const labels = unicodeHost.split(".").filter(Boolean);
  const scripts = labels.map(labelScripts);
  if (!scripts.some((s) => s.has("LATIN"))) return null;
  for (let i = 0; i < labels.length; i++) {
    const labelScriptSet = scripts[i]!;
    if (labelScriptSet.size === 0 || labelScriptSet.has("LATIN")) continue;
    let letters = "";
    for (const char of labels[i]!) if (isAlpha(char.codePointAt(0)!)) letters += char;
    if (isAsciiAlpha(skeleton(letters))) return "lookalike_label";
  }
  return null;
}
