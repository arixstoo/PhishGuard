/**
 * Liste des suffixes publics et découpage d'un hôte, comme `tldextract` 5.x.
 *
 * La liste est **celle que tldextract embarque**, exportée depuis Python
 * (`reference-data.json`), et non celle d'une bibliothèque JavaScript (`tldts`) : sa
 * version fixe `host_n_subdomains` et le domaine enregistré, et une liste plus récente
 * donnerait d'autres features. L'algorithme (`suffix_index`, `_extract_netloc`) est
 * traduit à l'identique, suffixes privés compris (`github.io`, `blogspot.com`).
 */

import reference from "../generated/reference-data.json";
import { isIPv6, looksLikeIp } from "./ip";
import { punycodeDecode } from "./punycode";
import { partition, pyStrip, rpartition } from "./text";

interface TrieNode {
  matches: Map<string, TrieNode>;
  end: boolean;
  isPrivate: boolean;
}

const newNode = (): TrieNode => ({ matches: new Map(), end: false, isPrivate: false });

function addSuffix(root: TrieNode, suffix: string, isPrivate: boolean): void {
  let node = root;
  for (const label of suffix.split(".").reverse()) {
    let next = node.matches.get(label);
    if (next === undefined) {
      next = newNode();
      node.matches.set(label, next);
    }
    node = next;
  }
  node.end = true;
  node.isPrivate = isPrivate;
}

let trie: TrieNode | null = null;

/** Arbre construit à la première utilisation (≈ 10 000 suffixes, quelques ms). */
function suffixTrie(): TrieNode {
  if (trie === null) {
    const root = newNode();
    // Même ordre que Trie.create : publics, puis privés (un privé écrase un public).
    for (const suffix of new Set(reference.public_suffix_list.public)) addSuffix(root, suffix, false);
    for (const suffix of new Set(reference.public_suffix_list.private)) addSuffix(root, suffix, true);
    trie = root;
  }
  return trie;
}

/**
 * `tldextract.tldextract._decode_punycode`. Python passe par `idna.decode` (IDNA 2008,
 * strict), qui refuse un A-label vide ou terminé par un tiret. Le résultat ne sert qu'à
 * chercher le label dans la liste : tout label de la liste est un U-label valide (contrôlé
 * à l'export), donc le décodeur Punycode seul trouve exactement les mêmes suffixes.
 */
function decodeLabel(label: string): string {
  const lowered = label.toLowerCase();
  if (!lowered.startsWith("xn--")) return lowered;
  const body = lowered.slice(4);
  if (body === "" || body.endsWith("-")) return lowered;
  try {
    return punycodeDecode(body);
  } catch {
    return lowered;
  }
}

interface SuffixIndex {
  publicIndex: number;
  publicNode: TrieNode;
}

function suffixIndex(labels: string[]): SuffixIndex | null {
  let node = suffixTrie();
  let suffixNode = node;
  let suffixIdx = labels.length;
  let labelIdx = labels.length;
  for (let i = labels.length - 1; i >= 0; i--) {
    const decoded = decodeLabel(labels[i]!);
    const next = node.matches.get(decoded);
    if (next !== undefined) {
      labelIdx -= 1;
      node = next;
      if (node.end) {
        suffixIdx = labelIdx;
        suffixNode = node;
      }
      continue;
    }
    const wildcard = node.matches.get("*");
    if (wildcard !== undefined) {
      const exception = node.matches.has(`!${decoded}`);
      return { publicIndex: exception ? labelIdx : labelIdx - 1, publicNode: wildcard };
    }
    break;
  }
  if (suffixIdx === labels.length) return null;
  return { publicIndex: suffixIdx, publicNode: suffixNode };
}

export interface ExtractResult {
  subdomain: string;
  domain: string;
  suffix: string;
  isPrivate: boolean;
  /** `top_domain_under_public_suffix` : `domaine.suffixe`, ou `""`. */
  topDomainUnderPublicSuffix: string;
}

const SCHEME_CHARS = /^[A-Za-z0-9+\-.]*$/;

function schemelessUrl(url: string): string {
  const start = url.indexOf("//");
  if (start === 0) return url.slice(2);
  if (start < 2 || url[start - 1] !== ":" || !SCHEME_CHARS.test(url.slice(0, start - 1))) {
    return url;
  }
  return url.slice(start + 2);
}

/** `tldextract.remote.lenient_netloc`. */
function lenientNetloc(url: string): string {
  const authority = partition(partition(partition(schemelessUrl(url), "/")[0], "?")[0], "#")[0];
  const afterUserinfo = rpartition(authority, "@")[2];
  if (afterUserinfo.startsWith("[")) {
    const [inside, close] = partition(afterUserinfo, "]");
    if (close === "]") return `${inside}]`;
  }
  let host = pyStrip(partition(afterUserinfo, ":")[0]);
  while (host && ".。．｡".includes(host[host.length - 1]!)) host = host.slice(0, -1);
  return host;
}

const result = (subdomain: string, domain: string, suffix: string, isPrivate: boolean) => ({
  subdomain,
  domain,
  suffix,
  isPrivate,
  topDomainUnderPublicSuffix: suffix && domain ? `${domain}.${suffix}` : "",
});

/** `TLDExtract(include_psl_private_domains=True)(url)`, hors ligne. */
export function extractDomain(url: string): ExtractResult {
  const netloc = lenientNetloc(url).replace(/[。．｡]/g, ".");
  if (
    netloc.length >= 4 &&
    netloc.startsWith("[") &&
    netloc.endsWith("]") &&
    isIPv6(netloc.slice(1, -1))
  ) {
    return result("", netloc, "", false);
  }
  const labels = netloc.split(".");
  const index = suffixIndex(labels);
  if (index === null) {
    if (labels.length === 4 && looksLikeIp(netloc)) return result("", netloc, "", false);
    return result(labels.slice(0, -1).join("."), labels[labels.length - 1]!, "", false);
  }
  const { publicIndex, publicNode } = index;
  return result(
    publicIndex >= 2 ? labels.slice(0, publicIndex - 1).join(".") : "",
    publicIndex > 0 ? labels[publicIndex - 1]! : "",
    labels.slice(publicIndex).join("."),
    publicNode.isPrivate,
  );
}
