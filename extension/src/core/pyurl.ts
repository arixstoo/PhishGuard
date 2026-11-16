/**
 * `urllib.parse` de Python 3.13 : `urlsplit`, `urlunsplit`, `unquote`, traduits à
 * l'identique.
 *
 * La classe `URL` du navigateur suit le standard WHATWG : elle décode les IPv4 en
 * hexadécimal, applique UTS #46 à l'hôte, retire tabulations et sauts de ligne, résout
 * `..`. L'extracteur Python a été entraîné sur ce que voit `urlsplit`, qui ne fait rien de
 * cela. Utiliser `URL` donnerait d'autres features, donc d'autres scores, en silence :
 * c'est la première source d'écarts que le plan signale (étape 5.3).
 */

import { ipVersion } from "./ip";
import { isAscii, isAsciiDigits, partition, rpartition } from "./text";

export class UrlSplitError extends Error {
  override name = "UrlSplitError";
}

export interface SplitResult {
  scheme: string;
  netloc: string;
  path: string;
  query: string;
  fragment: string;
}

const SCHEME_CHARS = /^[A-Za-z0-9+\-.]*$/;
// eslint-disable-next-line no-control-regex
const C0_CONTROL_OR_SPACE = /^[\x00-\x20]+/;

function checkBracketedHost(hostname: string): void {
  if (hostname.startsWith("v")) {
    // \Av[a-fA-F0-9]+\..+\Z ; « . » ne passe pas un saut de ligne (absent ici).
    if (!/^v[a-fA-F0-9]+\.[^\n]+$/.test(hostname)) {
      throw new UrlSplitError("IPvFuture address is invalid");
    }
    return;
  }
  const version = ipVersion(hostname);
  if (version === null) throw new UrlSplitError("does not appear to be an IP address");
  if (version === 4) throw new UrlSplitError("An IPv4 address cannot be in brackets");
}

function checkBracketedNetloc(netloc: string): void {
  const hostnameAndPort = rpartition(netloc, "@")[2];
  const [beforeBracket, haveOpenBracket, bracketed] = partition(hostnameAndPort, "[");
  let hostname: string;
  if (haveOpenBracket) {
    if (beforeBracket) throw new UrlSplitError("Invalid IPv6 URL");
    let port: string;
    [hostname, , port] = partition(bracketed, "]");
    if (port && !port.startsWith(":")) throw new UrlSplitError("Invalid IPv6 URL");
  } else {
    hostname = partition(hostnameAndPort, ":")[0];
  }
  checkBracketedHost(hostname);
}

function checkNetloc(netloc: string): void {
  if (!netloc || isAscii(netloc)) return;
  const n = netloc.replaceAll("@", "").replaceAll(":", "").replaceAll("#", "").replaceAll("?", "");
  const normalized = n.normalize("NFKC");
  if (n === normalized) return;
  for (const c of "/?#@:") {
    if (normalized.includes(c)) {
      throw new UrlSplitError("netloc contains invalid characters under NFKC normalization");
    }
  }
}

/** `urllib.parse.urlsplit(url)` ; lève {@link UrlSplitError} là où Python lève `ValueError`. */
export function urlsplit(input: string): SplitResult {
  let url = input.replace(C0_CONTROL_OR_SPACE, "");
  url = url.replaceAll("\t", "").replaceAll("\r", "").replaceAll("\n", "");
  let scheme = "";
  let netloc = "";
  let query = "";
  let fragment = "";
  const i = url.indexOf(":");
  if (i > 0 && /^[A-Za-z]/.test(url) && SCHEME_CHARS.test(url.slice(0, i))) {
    scheme = url.slice(0, i).toLowerCase();
    url = url.slice(i + 1);
  }
  if (url.startsWith("//")) {
    let delim = url.length;
    for (const c of "/?#") {
      const w = url.indexOf(c, 2);
      if (w >= 0) delim = Math.min(delim, w);
    }
    netloc = url.slice(2, delim);
    url = url.slice(delim);
    const open = netloc.includes("[");
    const close = netloc.includes("]");
    if (open !== close) throw new UrlSplitError("Invalid IPv6 URL");
    if (open && close) checkBracketedNetloc(netloc);
  }
  if (url.includes("#")) [url, , fragment] = partition(url, "#");
  if (url.includes("?")) [url, , query] = partition(url, "?");
  checkNetloc(netloc);
  return { scheme, netloc, path: url, query, fragment };
}

function hostinfo(netloc: string): [string, string | null] {
  const info = rpartition(netloc, "@")[2];
  const [, haveOpenBracket, bracketed] = partition(info, "[");
  let hostname: string;
  let port: string;
  if (haveOpenBracket) {
    let rest: string;
    [hostname, , rest] = partition(bracketed, "]");
    port = partition(rest, ":")[2];
  } else {
    [hostname, , port] = partition(info, ":");
  }
  return [hostname, port ? port : null];
}

/** `SplitResult.hostname` : en minuscules, sauf l'identifiant de zone IPv6. */
export function hostname(parts: SplitResult): string | null {
  const host = hostinfo(parts.netloc)[0];
  if (!host) return null;
  const [name, percent, zone] = partition(host, "%");
  return name.toLowerCase() + percent + zone;
}

/** `SplitResult.port` ; lève {@link UrlSplitError} si le port est invalide. */
export function port(parts: SplitResult): number | null {
  const raw = hostinfo(parts.netloc)[1];
  if (raw === null) return null;
  if (!isAsciiDigits(raw)) throw new UrlSplitError("Port could not be cast to integer value");
  const value = Number(raw);
  if (!(value >= 0 && value <= 65535)) throw new UrlSplitError("Port out of range 0-65535");
  return value;
}

/** `urllib.parse.urlunsplit` pour une URL à `netloc` (http, https). */
export function urlunsplit(parts: SplitResult): string {
  let url = parts.path;
  if (parts.netloc) {
    if (url && !url.startsWith("/")) url = `/${url}`;
    url = `//${parts.netloc}${url}`;
  } else if (url.startsWith("//")) {
    url = `//${url}`;
  } else if (["http", "https"].includes(parts.scheme) && (!url || url.startsWith("/"))) {
    url = `//${url}`;
  }
  if (parts.scheme) url = `${parts.scheme}:${url}`;
  if (parts.query) url = `${url}?${parts.query}`;
  if (parts.fragment) url = `${url}#${parts.fragment}`;
  return url;
}

// --------------------------------------------------------------------------- //
// unquote
// --------------------------------------------------------------------------- //

// UTF-8, remplacement des séquences invalides par U+FFFD (sous-partie maximale, comme
// `errors="replace"` de Python) ; le BOM est conservé, comme par Python.
const decoder = new TextDecoder("utf-8", { fatal: false, ignoreBOM: true });
const HEX_PAIR = /^[0-9A-Fa-f]{2}/;

function unquoteAscii(text: string): string {
  const bits = text.split("%");
  if (bits.length === 1) return text;
  const bytes: number[] = [];
  const pushAscii = (s: string) => {
    for (let i = 0; i < s.length; i++) bytes.push(s.charCodeAt(i));
  };
  pushAscii(bits[0]!);
  for (const item of bits.slice(1)) {
    if (HEX_PAIR.test(item)) {
      bytes.push(parseInt(item.slice(0, 2), 16));
      pushAscii(item.slice(2));
    } else {
      bytes.push(0x25);
      pushAscii(item);
    }
  }
  return decoder.decode(Uint8Array.from(bytes));
}

/**
 * `urllib.parse.unquote(text)` : `%XX` décodés en UTF-8, par plages ASCII. Un caractère
 * non ASCII coupe la plage : `%C3é%A9` donne deux U+FFFD autour du `é`, comme en Python.
 */
export function unquote(text: string): string {
  if (!text.includes("%")) return text;
  // eslint-disable-next-line no-control-regex
  return text.replace(/[\x00-\x7f]+/g, (run) => unquoteAscii(run));
}
