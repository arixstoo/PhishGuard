/**
 * Features lexicales d'URL : `phishguard.urls.features` traduit à l'identique.
 *
 * Chaque feature est une fonction pure de l'URL, sans réseau ni horloge. Les vecteurs de
 * référence (`tests/golden/url_vectors.json`) et les cas de parité
 * (`test/fixtures/python-parity.json`) vérifient que ce fichier donne **exactement** les
 * valeurs de Python. Toute modification d'une feature côté Python incrémente
 * `FEATURE_EXTRACTOR_VERSION` et doit être reportée ici.
 */

import reference from "../generated/reference-data.json";
import { type BrandIndex, loadBrands, loadShorteners, maxTypoEdits } from "./brands";
import { isMixedScript, skeleton, toAscii, toUnicode } from "./idn";
import { isIPv6, ipVersion } from "./ip";
import { normalizeUrlText } from "./normalize";
import { extractDomain } from "./psl";
import { hostname, port as splitPort, unquote, urlsplit, urlunsplit, UrlSplitError } from "./pyurl";
import {
  countCodePoints,
  isAsciiDigits,
  isDigit,
  isSpace,
  pyLen,
  pyStrip,
  rpartition,
  rstripChars,
} from "./text";

export const FEATURE_EXTRACTOR_VERSION: string = reference.feature_extractor.version;
export const REFERENCE_DATA_SHA256: string = reference.feature_extractor.reference_data_sha256;
export const FEATURE_NAMES: readonly string[] = reference.feature_names;
const KEYWORDS: readonly string[] = reference.keywords;
const BRAND_DISTANCE_CAP: number = reference.brand_distance_cap;
const DEFAULT_PORTS: Readonly<Record<string, number>> = { http: 80, https: 443 };

const HEX_NUMBER_RE = /^0x[0-9a-f]*$/;
const EMBEDDED_URL_RE = /https?:|www\./;
const PATH_SEGMENT_SPLIT_RE = /[/?&=;#]/;
const SCHEME_RE = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//;

export type Features = Record<string, number>;

export class InvalidUrlError extends Error {
  override name = "InvalidUrlError";
}

export interface ParsedUrl {
  url: string;
  scheme: string;
  /** Forme ASCII (Punycode), comme `location.hostname`. */
  host: string;
  hostUnicode: string;
  isIp: boolean;
  /** L'hôte lui-même pour une IP ou un hôte sans suffixe connu. */
  registeredDomain: string;
  /** Label juste avant le suffixe public, forme Unicode (`""` pour une IP). */
  domainLabel: string;
  subdomains: string[];
  hasUserinfo: boolean;
  port: number | null;
  path: string;
  query: string;
}

/** Table de risque des TLD apprise à l'entraînement (export du modèle). */
export interface TldTable {
  prior: number;
  rates: Readonly<Record<string, number>>;
}

// --------------------------------------------------------------------------- //
// Fonctions élémentaires
// --------------------------------------------------------------------------- //

/** Entropie de Shannon (bits par caractère), points de code comptés dans leur ordre. */
export function entropy(text: string): number {
  const counts = new Map<string, number>();
  let n = 0;
  for (const char of text) {
    counts.set(char, (counts.get(char) ?? 0) + 1);
    n++;
  }
  if (n === 0) return 0;
  let sum = 0;
  for (const c of counts.values()) sum += (c / n) * Math.log2(c / n);
  return 0 - sum;
}

/** IPv6, ou hôte que le navigateur lit comme une IPv4 (règle WHATWG « ends in a number »). */
export function isIpHost(host: string): boolean {
  if (host.includes(":")) return isIPv6(host.split("%", 1)[0]!);
  const labels = host.split(".");
  if (labels.length > 1 && labels[labels.length - 1] === "") labels.pop();
  const last = labels[labels.length - 1]!;
  return isAsciiDigits(last) || HEX_NUMBER_RE.test(last);
}

export function keywordHits(text: string): number {
  const lowered = text.toLowerCase();
  return KEYWORDS.filter((keyword) => lowered.includes(keyword)).length;
}

export const countQueryParams = (query: string): number =>
  query.split("&").filter(Boolean).length;

/** Dernier label de l'hôte (forme ASCII), ou `""` pour une adresse IP. */
export function topLevelDomain(host: string): string {
  if (ipVersion(host) !== null) return "";
  return rpartition(rstripChars(host, "."), ".")[2].toLowerCase();
}

function hasSpace(text: string): boolean {
  for (const char of text) if (isSpace(char.codePointAt(0)!)) return true;
  return false;
}

// --------------------------------------------------------------------------- //
// Normalisation et découpage
// --------------------------------------------------------------------------- //

/** `phishguard.data.urls.normalize_url` : `[url, hôte]`, ou `null` si l'URL est invalide. */
export function normalizeUrl(raw: string): [string, string] | null {
  let candidate = pyStrip(raw);
  if (!candidate || hasSpace(candidate)) return null;
  if (!SCHEME_RE.test(candidate)) candidate = `http://${candidate}`;
  let parts;
  try {
    parts = urlsplit(candidate);
    splitPort(parts);
  } catch (error) {
    if (error instanceof UrlSplitError) return null;
    throw error;
  }
  const scheme = parts.scheme.toLowerCase();
  const host = rstripChars(hostname(parts) ?? "", ".").toLowerCase();
  if ((scheme !== "http" && scheme !== "https") || !host) return null;
  const [userinfo, at, hostport] = rpartition(parts.netloc, "@");
  const url = urlunsplit({
    scheme,
    netloc: `${userinfo}${at}${hostport.toLowerCase()}`,
    path: parts.path || "/",
    query: parts.query,
    fragment: parts.fragment,
  });
  return [url, host];
}

export interface ParsedHost {
  host: string;
  hostUnicode: string;
  isIp: boolean;
  registeredDomain: string;
  domainLabel: string;
  subdomains: string[];
}

/** Découpe un hôte déjà normalisé (minuscules, forme ASCII ou Unicode). */
export function parseHost(host: string): ParsedHost {
  const hostAscii = toAscii(host);
  const isIp = isIpHost(hostAscii);
  let registered = hostAscii;
  let domainLabel = "";
  let subdomain = "";
  if (!isIp) {
    const ext = extractDomain(hostAscii);
    registered = ext.topDomainUnderPublicSuffix || hostAscii;
    domainLabel = ext.domain;
    subdomain = ext.subdomain;
  }
  return {
    host: hostAscii,
    hostUnicode: toUnicode(hostAscii),
    isIp,
    registeredDomain: registered,
    domainLabel: toUnicode(domainLabel),
    subdomains: subdomain
      .split(".")
      .filter(Boolean)
      .map((s) => toUnicode(s)),
  };
}

/** Normalise et découpe une URL ; lève {@link InvalidUrlError} si elle est invalide. */
export function parseUrl(input: string): ParsedUrl {
  const normalized = normalizeUrl(normalizeUrlText(input));
  if (normalized === null) throw new InvalidUrlError("URL invalide");
  const [url, host] = normalized;
  let parts;
  let port;
  try {
    parts = urlsplit(url);
    port = splitPort(parts);
  } catch (error) {
    // Python lèverait ValueError (dont InvalidUrlError hérite) : URL refusée.
    if (error instanceof UrlSplitError) throw new InvalidUrlError("URL invalide");
    throw error;
  }
  const parsedHost = parseHost(host);
  return {
    url,
    scheme: parts.scheme,
    host: parsedHost.host,
    hostUnicode: parsedHost.hostUnicode,
    isIp: parsedHost.isIp,
    registeredDomain: parsedHost.registeredDomain,
    domainLabel: parsedHost.domainLabel,
    subdomains: parsedHost.subdomains,
    hasUserinfo: parts.netloc.includes("@"),
    port: port === DEFAULT_PORTS[parts.scheme] ? null : port,
    path: parts.path,
    query: parts.query,
  };
}

// --------------------------------------------------------------------------- //
// Extracteur
// --------------------------------------------------------------------------- //

const flag = (value: boolean): number => (value ? 1 : 0);

export interface ExtractorOptions {
  brands?: BrandIndex;
  shorteners?: ReadonlySet<string>;
  /** Sans table, `tld_phish_rate` n'est pas calculée (comme l'extracteur Python par défaut). */
  tldTable?: TldTable | null;
}

export class UrlFeatureExtractor {
  private readonly brands: BrandIndex;
  private readonly shorteners: ReadonlySet<string>;
  private readonly tldTable: TldTable | null;
  // Les features d'hôte reviennent souvent : petit cache borné (ordre d'insertion = LRU).
  private readonly hostCache = new Map<string, Features>();
  private static readonly HOST_CACHE_SIZE = 512;

  constructor(options: ExtractorOptions = {}) {
    this.brands = options.brands ?? loadBrands();
    this.shorteners = options.shorteners ?? loadShorteners();
    this.tldTable = options.tldTable ?? null;
  }

  /** Noms des features calculées, dans l'ordre de l'extracteur Python. */
  get featureNames(): string[] {
    return FEATURE_NAMES.filter((name) => name !== "tld_phish_rate" || this.tldTable !== null);
  }

  /** Features d'une URL déjà découpée, dans l'ordre de {@link featureNames}. */
  extractParsed(parsed: ParsedUrl): Features {
    const values = { ...this.hostFeatures(parsed.host), ...this.urlFeatures(parsed) };
    const out: Features = {};
    for (const name of this.featureNames) out[name] = values[name]!;
    return out;
  }

  extract(url: string): Features {
    return this.extractParsed(parseUrl(url));
  }

  private hostFeatures(host: string): Features {
    const cached = this.hostCache.get(host);
    if (cached !== undefined) {
      this.hostCache.delete(host);
      this.hostCache.set(host, cached);
      return cached;
    }
    const values = this.computeHostFeatures(host);
    this.hostCache.set(host, values);
    if (this.hostCache.size > UrlFeatureExtractor.HOST_CACHE_SIZE) {
      this.hostCache.delete(this.hostCache.keys().next().value!);
    }
    return values;
  }

  private computeHostFeatures(host: string): Features {
    const parsed = parseHost(host);
    const unicodeHost = parsed.hostUnicode;
    const subdomains = [...parsed.subdomains];
    if (subdomains[0] === "www") subdomains.shift();

    const official = this.brands.officialFor(parsed.registeredDomain);
    const labels = [...parsed.subdomains, parsed.domainLabel];
    const isIdn = unicodeHost !== parsed.host;

    const found = parsed.isIp ? null : this.brands.find(labels, official);
    const [distance, nearest] = parsed.isIp
      ? [BRAND_DISTANCE_CAP, null]
      : this.brands.nearest(parsed.domainLabel, official, BRAND_DISTANCE_CAP);

    const values: Features = {
      host_is_ip: flag(parsed.isIp),
      host_n_subdomains: subdomains.length,
      host_n_hyphens: countCodePoints(unicodeHost, (cp) => cp === 0x2d),
      host_n_digits: countCodePoints(unicodeHost, isDigit),
      host_entropy: entropy(unicodeHost),
      host_kw_hits: keywordHits(unicodeHost),
      host_is_idn: flag(isIdn),
      host_len: pyLen(unicodeHost),
      brand_in_host: flag(found !== null),
      brand_min_distance: distance,
      is_typosquat: flag(nearest !== null && distance >= 1 && distance <= maxTypoEdits(nearest)),
      host_mixed_script: flag(isMixedScript(unicodeHost)),
      homograph_brand: flag(
        isIdn &&
          this.brands.find(labels, official) === null &&
          this.brands.find(labels.map(skeleton), official) !== null,
      ),
      is_shortener: flag(
        this.shorteners.has(parsed.host) || this.shorteners.has(parsed.registeredDomain),
      ),
    };
    if (this.tldTable !== null) {
      const tld = topLevelDomain(parsed.host);
      values["tld_phish_rate"] = Object.hasOwn(this.tldTable.rates, tld)
        ? this.tldTable.rates[tld]!
        : this.tldTable.prior;
    }
    return values;
  }

  private urlFeatures(parsed: ParsedUrl): Features {
    const decoded = unquote(parsed.query ? `${parsed.path}?${parsed.query}` : parsed.path);
    const official = this.brands.officialFor(parsed.registeredDomain);
    return {
      is_https: flag(parsed.scheme === "https"),
      has_userinfo: flag(parsed.hasUserinfo),
      has_port: flag(parsed.port !== null),
      path_depth: parsed.path.split("/").filter(Boolean).length,
      query_n_params: countQueryParams(parsed.query),
      path_n_digits: countCodePoints(decoded, isDigit),
      path_kw_hits: keywordHits(decoded),
      path_has_embedded_url: flag(EMBEDDED_URL_RE.test(decoded.toLowerCase())),
      path_len: pyLen(parsed.path),
      query_len: pyLen(parsed.query),
      brand_in_path: flag(this.brands.find(decoded.split(PATH_SEGMENT_SPLIT_RE), official) !== null),
    };
  }
}
