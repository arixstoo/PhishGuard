/**
 * Liens et expéditeur d'un email : `phishguard.email.html` et `phishguard.email.parser`
 * traduits à l'identique (étape 5.6).
 *
 * L'API et l'extension doivent dire la même chose d'un même lien. Ce module reprend donc
 * les fonctions Python qui décident qu'un lien est trompeur, ligne à ligne, avec leurs
 * expressions régulières (classes de caractères de Python : voir `pyre.ts`) :
 *
 * - `make_link` : cible réelle, domaine du texte affiché, `mismatch` (« le texte affiche
 *   une adresse, le lien mène ailleurs ») ;
 * - `unwrap_rewritten` : liens réécrits par une passerelle de sécurité (Safe Links,
 *   Symantec, Proofpoint) ;
 * - `display_name_domain`, `make_address` : nom affiché de l'expéditeur qui imite une
 *   autre adresse.
 *
 * S'y ajoute ce que seul Gmail fait : la redirection `https://www.google.com/url?q=…`.
 *
 * Tout est pur : aucune API Chrome, aucun DOM. Les tests rejouent les cas produits par
 * Python (`python-parity.json`, section `mail`).
 */

import { normalizeUrl } from "./features";
import { toAscii } from "./idn";
import { ipVersion } from "./ip";
import { extractDomain } from "./psl";
import { ASCII_LETTER_IGNORECASE, literalIgnoreCase, PY_END, SPACE, WORD, WORD_BOUNDARY } from "./pyre";
import { hostname, unquote, urlsplit, UrlSplitError } from "./pyurl";
import { pyStrip, rpartition } from "./text";

// --------------------------------------------------------------------------- //
// Chaînes à la Python
// --------------------------------------------------------------------------- //

const SPACE_RUN = new RegExp(`[${SPACE}]+`, "u");

/** `" ".join(text.split())` : espaces Unicode de Python réduits à un seul. */
export const collapseSpaces = (text: string): string => text.split(SPACE_RUN).filter(Boolean).join(" ");

/** `text.strip(chars)` : retire aux deux bords tout caractère de `chars`. */
export function stripChars(text: string, chars: string): string {
  let start = 0;
  let end = text.length;
  while (start < end && chars.includes(text[start]!)) start++;
  while (end > start && chars.includes(text[end - 1]!)) end--;
  return text.slice(start, end);
}

/** `urllib.parse.parse_qs(query)` (Python 3.13) : valeurs vides ignorées, `+` → espace. */
export function parseQs(query: string): Map<string, string[]> {
  const result = new Map<string, string[]>();
  if (!query) return result;
  const unquotePlus = (s: string) => unquote(s.replaceAll("+", " "));
  for (const nameValue of query.split("&")) {
    if (!nameValue) continue;
    const i = nameValue.indexOf("=");
    if (i < 0) continue; // pas de « = » : ignoré (keep_blank_values=False)
    const value = nameValue.slice(i + 1);
    if (!value) continue;
    const name = unquotePlus(nameValue.slice(0, i));
    const values = result.get(name) ?? [];
    values.push(unquotePlus(value));
    result.set(name, values);
  }
  return result;
}

const first = (query: Map<string, string[]>, name: string): string | null => query.get(name)?.[0] ?? null;

// --------------------------------------------------------------------------- //
// Domaine enregistré d'un texte ou d'une cible
// --------------------------------------------------------------------------- //

/**
 * `phishguard.email.html.registered_domain` : domaine enregistré d'une URL ou d'un hôte
 * (forme ASCII), `null` si rien n'est lisible ou si l'hôte n'a pas de suffixe public connu.
 */
export function registeredDomainOf(urlOrHost: string): string | null {
  const candidate = pyStrip(urlOrHost);
  if (!candidate) return null;
  const normalized = normalizeUrl(candidate);
  if (normalized === null) return null;
  let host: string;
  try {
    host = toAscii(normalized[1]);
  } catch {
    return null; // UnicodeError de Python
  }
  // phishguard.data.urls.registered_domain
  if (ipVersion(host) !== null) return host;
  const parts = extractDomain(host);
  if (parts.topDomainUnderPublicSuffix) return parts.topDomainUnderPublicSuffix;
  if (parts.isPrivate && parts.suffix === host) return host;
  return null;
}

/** `_scheme` : schéma en minuscules, `""` si l'URL ne se découpe pas. */
export function schemeOf(href: string): string {
  try {
    return urlsplit(pyStrip(href)).scheme.toLowerCase();
  } catch (error) {
    if (error instanceof UrlSplitError) return "";
    throw error;
  }
}

const isWebScheme = (scheme: string) => scheme === "http" || scheme === "https";

// --------------------------------------------------------------------------- //
// Passerelles de sécurité et redirection de Google
// --------------------------------------------------------------------------- //

export type Rewriter = "safelinks" | "symantec" | "proofpoint";

function split(href: string) {
  try {
    const parts = urlsplit(href);
    return { parts, host: (hostname(parts) ?? "").toLowerCase() };
  } catch (error) {
    if (error instanceof UrlSplitError) return null;
    throw error;
  }
}

/** `unwrap_rewritten` : `[URL d'origine, passerelle]` d'un lien réécrit, sinon `null`. Un seul niveau. */
export function unwrapRewritten(href: string): [string, Rewriter] | null {
  const split_ = split(href);
  if (split_ === null) return null;
  const { parts, host } = split_;
  const query = parseQs(parts.query);
  let inner: string | null = null;
  let name: Rewriter | null = null;
  if (host.endsWith(".safelinks.protection.outlook.com")) {
    [inner, name] = [first(query, "url"), "safelinks"];
  } else if (host === "clicktime.symantec.com") {
    [inner, name] = [first(query, "u"), "symantec"];
  } else if (host === "urldefense.proofpoint.com" && parts.path.startsWith("/v2/url")) {
    // v2 : « - » remplace « % » et « _ » remplace « / » dans le paramètre u.
    const encoded = first(query, "u");
    inner = encoded ? unquote(encoded.replaceAll("-", "%").replaceAll("_", "/")) : null;
    name = "proofpoint";
  } else if (host === "urldefense.com" && parts.path.startsWith("/v3/__")) {
    const marker = "/v3/__";
    const body = href.slice(href.indexOf(marker) + marker.length);
    const end = body.indexOf("__;");
    [inner, name] = [end >= 0 ? body.slice(0, end) : null, "proofpoint"];
  }
  if (!inner || name === null || !isWebScheme(schemeOf(inner))) return null;
  return [inner, name];
}

/**
 * Hôtes de la redirection de Google. Liste **fermée** : déballer la redirection d'un
 * hôte qui ne serait pas celui de Google (`google.evil/url?q=https://banque.fr`) ferait
 * analyser la cible annoncée au lieu de l'hôte réellement visité.
 */
const GOOGLE_REDIRECT_HOSTS: ReadonlySet<string> = new Set(["www.google.com", "google.com"]);
const MAX_GOOGLE_REDIRECTS = 5;

/**
 * Cible d'un lien `https://www.google.com/url?q=<cible>` (Gmail, Google Docs, Agenda),
 * redirections imbriquées comprises. Un lien qui n'en est pas une est rendu tel quel.
 */
export function unwrapGoogleRedirect(href: string): { target: string; unwrapped: boolean } {
  let current = pyStrip(href);
  let unwrapped = false;
  for (let i = 0; i < MAX_GOOGLE_REDIRECTS; i++) {
    const split_ = split(current);
    if (split_ === null || !isWebScheme(split_.parts.scheme.toLowerCase())) break;
    if (!GOOGLE_REDIRECT_HOSTS.has(split_.host) || split_.parts.path !== "/url") break;
    const query = parseQs(split_.parts.query);
    const inner = first(query, "q") ?? first(query, "url");
    if (inner === null || !isWebScheme(schemeOf(inner))) break;
    current = pyStrip(inner);
    unwrapped = true;
  }
  return { target: current, unwrapped };
}

// --------------------------------------------------------------------------- //
// Lien
// --------------------------------------------------------------------------- //

const NOT_SPACE = `[^${SPACE}]`;
const LABEL = `[${WORD}-]`;
const TLD = `[${ASCII_LETTER_IGNORECASE}]{2,24}`;

/** `_ADDRESS_LIKE_RE` (`re.IGNORECASE`) : schéma, « www. » ou nom de domaine avec un TLD. */
const ADDRESS_LIKE_RE = new RegExp(
  `^(?:${literalIgnoreCase("http")}${literalIgnoreCase("s")}?://|${literalIgnoreCase("www")}\\.)` +
    `${NOT_SPACE}+${PY_END}` +
    `|^${LABEL}+(?:\\.${LABEL}+)*\\.${TLD}(?:[/:?#]${NOT_SPACE}*)?${PY_END}`,
  "u",
);

/** Caractères retirés autour du texte affiché avant de le comparer. */
const SHOWN_STRIP = "<>()[]\"'.,;";

export interface Link {
  href: string;
  text: string;
  scheme: string;
  /** Domaine enregistré de la cible (celle d'origine si une passerelle l'a réécrite). */
  hrefDomain: string | null;
  /** Domaine enregistré du texte affiché, s'il ressemble à une adresse. */
  textDomain: string | null;
  mismatch: boolean;
  rewrittenBy: Rewriter | null;
  /** `link_target` : URL où mène vraiment le lien. */
  target: string;
}

/** `make_link` : lien tel que l'API le lit dans un email. */
export function makeLink(rawHref: string, rawText: string): Link {
  const href = pyStrip(rawHref);
  const text = collapseSpaces(rawText);
  const scheme = schemeOf(href);
  // Un href relatif (« page.html », « /aide ») n'a pas de domaine : seuls les liens web
  // absolus, y compris « //hote » et « www.hote », sont comparés.
  const absolute = isWebScheme(scheme) || href.startsWith("//") || href.startsWith("www.");
  const unwrapped = isWebScheme(scheme) ? unwrapRewritten(href) : null;
  const [target, rewrittenBy] = unwrapped ?? [href, null];
  const hrefDomain = absolute ? registeredDomainOf(target.startsWith("//") ? target.slice(2) : target) : null;
  const shown = stripChars(text, SHOWN_STRIP);
  const textDomain = ADDRESS_LIKE_RE.test(shown) ? registeredDomainOf(shown) : null;
  let mismatch = textDomain !== null && hrefDomain !== null && textDomain !== hrefDomain;
  // Un texte qui affiche une adresse web alors que la cible n'est pas du web
  // (javascript:, data:…) est aussi un leurre.
  if (textDomain !== null && !["http", "https", "", "mailto"].includes(scheme)) mismatch = true;
  return { href, text, scheme, hrefDomain, textDomain, mismatch, rewrittenBy, target };
}

// --------------------------------------------------------------------------- //
// Expéditeur
// --------------------------------------------------------------------------- //

/** `_EMAIL_IN_TEXT_RE` */
const EMAIL_IN_TEXT_RE = new RegExp(`[${WORD}.+-]+@(${LABEL}+(?:\\.${LABEL}+)+)`, "u");
/** `_DOMAIN_IN_TEXT_RE` (`re.IGNORECASE`) */
const DOMAIN_IN_TEXT_RE = new RegExp(`${WORD_BOUNDARY}((?:${LABEL}+\\.)+${TLD})${WORD_BOUNDARY}`, "u");

/**
 * `display_name_domain` : domaine enregistré d'une adresse ou d'un domaine écrit dans le
 * nom affiché. `"service@paypal.com" <x@evil.example>` : le nom imite une adresse PayPal.
 */
export function displayNameDomain(displayName: string): string | null {
  return displayNameClaim(displayName)?.domain ?? null;
}

/**
 * Ce que le nom affiché prétend : une **adresse** (`service@paypal.com`) ou seulement un
 * **domaine** (`impots.gouv.fr`). Même lecture que `display_name_domain` ; la distinction
 * sert à graduer l'alerte (voir `inspectSender`).
 */
export function displayNameClaim(displayName: string): { domain: string | null; kind: "address" | "domain" } | null {
  const email = EMAIL_IN_TEXT_RE.exec(displayName);
  if (email) return { domain: registeredDomainOf(email[1]!), kind: "address" };
  const domain = DOMAIN_IN_TEXT_RE.exec(displayName);
  return domain ? { domain: registeredDomainOf(domain[1]!), kind: "domain" } : null;
}

export interface Address {
  displayName: string;
  address: string;
  domain: string | null;
  registeredDomain: string | null;
}

/** `make_address` */
export function makeAddress(displayName: string, rawAddress: string): Address | null {
  const address = pyStrip(stripChars(pyStrip(rawAddress), "<>"));
  if (!address && !displayName) return null;
  const domain = address.includes("@") ? rstripDots(rpartition(address, "@")[2].toLowerCase()) : null;
  return {
    displayName: pyStrip(displayName),
    address,
    domain: domain || null,
    registeredDomain: domain ? registeredDomainOf(domain) : null,
  };
}

function rstripDots(text: string): string {
  let end = text.length;
  while (end > 0 && text[end - 1] === ".") end--;
  return text.slice(0, end);
}
