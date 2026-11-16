/**
 * Adresses IP au sens du module `ipaddress` de Python 3.13 (analyse stricte).
 *
 * Pas `new URL()` : le navigateur lit `0x7f.1` ou `3232235777` comme des IPv4 (règle
 * WHATWG), alors que `ipaddress` les refuse. Les deux lectures servent à des endroits
 * différents de l'extracteur (`host_is_ip` suit la règle WHATWG, `top_level_domain` et
 * `urlsplit` suivent `ipaddress`) : chacune est reproduite là où Python l'emploie.
 */

import { isAscii, isAsciiDigits, partition } from "./text";

const HEXTET_COUNT = 8;
const HEX_RE = /^[0-9a-fA-F]*$/;

/** `ipaddress.IPv4Address(text)` réussit. */
export function isIPv4(text: string): boolean {
  if (text === "" || text.includes("/")) return false;
  const octets = text.split(".");
  if (octets.length !== 4) return false;
  return octets.every((octet) => {
    if (!isAsciiDigits(octet) || octet.length > 3) return false;
    if (octet !== "0" && octet[0] === "0") return false;
    return Number(octet) <= 255;
  });
}

function ipv6Body(text: string): boolean {
  if (text === "" || text.length > 45) return false;
  // split(':', maxsplit=9) : au plus 10 parties, le reste dans la dernière.
  const all = text.split(":");
  const parts = all.length > HEXTET_COUNT + 2 ? [...all.slice(0, 9), all.slice(9).join(":")] : all;
  if (parts.length < 3) return false;
  if (parts[parts.length - 1]!.includes(".")) {
    if (!isIPv4(parts.pop()!)) return false;
    parts.push("0", "0"); // deux hextets valides, seule leur présence compte ici
  }
  if (parts.length > HEXTET_COUNT + 1) return false;

  let skipIndex: number | null = null;
  for (let i = 1; i < parts.length - 1; i++) {
    if (!parts[i]) {
      if (skipIndex !== null) return false;
      skipIndex = i;
    }
  }
  let hi: number;
  let lo: number;
  if (skipIndex !== null) {
    hi = skipIndex;
    lo = parts.length - skipIndex - 1;
    if (!parts[0]) {
      hi -= 1;
      if (hi) return false;
    }
    if (!parts[parts.length - 1]) {
      lo -= 1;
      if (lo) return false;
    }
    if (HEXTET_COUNT - (hi + lo) < 1) return false;
  } else {
    if (parts.length !== HEXTET_COUNT) return false;
    if (!parts[0] || !parts[parts.length - 1]) return false;
    hi = parts.length;
    lo = 0;
  }
  const hextets = [...parts.slice(0, hi), ...parts.slice(parts.length - lo)];
  // _parse_hextet : chiffres hexadécimaux ASCII seulement, au plus 4 ; "" vaut int("") →
  // ValueError en Python, donc refusé ici aussi.
  return hextets.every((h) => h !== "" && HEX_RE.test(h) && isAscii(h) && h.length <= 4);
}

/** `ipaddress.IPv6Address(text)` réussit (identifiant de zone `%…` admis). */
export function isIPv6(text: string): boolean {
  if (text.includes("/")) return false;
  const [address, sep, scope] = partition(text, "%");
  if (sep && (!scope || scope.includes("%"))) return false;
  return ipv6Body(address);
}

/** Version de `ipaddress.ip_address(text)`, ou `null` si ce n'est pas une adresse. */
export function ipVersion(text: string): 4 | 6 | null {
  if (isIPv4(text)) return 4;
  if (isIPv6(text)) return 6;
  return null;
}

/** IPv4 au sens de `tldextract.remote.looks_like_ip` (expression régulière ASCII). */
const LOOKS_LIKE_IP_RE =
  /^(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$/;

export function looksLikeIp(text: string): boolean {
  return LOOKS_LIKE_IP_RE.test(text);
}
