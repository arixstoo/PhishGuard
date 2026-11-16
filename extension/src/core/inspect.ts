/**
 * Verdict d'un message ouvert dans Gmail (étape 5.6) : chaque lien, puis l'expéditeur.
 *
 * Pour un lien :
 *
 * 1. la redirection de Google (`google.com/url?q=`) est déballée, puis le lien est lu
 *    comme l'API le lit (`makeLink` : passerelles de sécurité, texte affiché) ;
 * 2. `javascript:`, `data:`, `vbscript:`, `file:` → suspect (`non_web_link`, comme l'API) ;
 * 3. un lien web est analysé comme une page (`UrlAnalyzer` + `decide`, liste blanche
 *    comprise) ;
 * 4. « le domaine du texte affiché diffère de celui de la cible » (`mismatch`) → au moins
 *    suspect, même si le modèle trouve la cible sûre : c'est le leurre le plus courant.
 *
 * Pour l'expéditeur, la règle `display_name_spoof` de l'API (« le nom affiché cite un autre
 * domaine que celui de l'adresse réelle »), **graduée** comme le fait le score de l'API, où
 * elle ne pèse que 25 points, sous le seuil « suspect » (30) :
 *
 * - le nom affiché est une **adresse** d'un autre domaine (`"service@paypal.com"
 *   <x@autre.example>`) : suspect à lui seul (`display_name_spoof`), presque jamais légitime ;
 * - il ne cite qu'un **domaine** (`impots.gouv.fr` pour `@dgfip.finances.gouv.fr`, courant
 *   chez les expéditeurs légitimes) : raison affichée si la bannière l'est déjà, jamais
 *   déclencheur (`display_name_domain`) ;
 * - domaine de l'adresse qui imite des lettres latines (`sender_lookalike`) → phishing.
 *
 * Pur et synchrone : aucune API Chrome, rien n'est conservé.
 */

import reference from "../generated/reference-data.json";
import { decide, InvalidUrlError, type ReasonCode, type UrlAnalyzer, type Verdict } from "./analyze";
import { toAscii } from "./idn";
import { displayNameClaim, makeAddress, makeLink, unwrapGoogleRedirect } from "./mail";
import { hostScriptAlert } from "./normalize";

export type LinkReason = ReasonCode | "text_domain_mismatch" | "non_web_link";
export type SenderReason = "display_name_spoof" | "display_name_domain" | "sender_lookalike";

/** Raisons d'expéditeur qui suffisent, seules, à rendre un message suspect. */
const SENDER_TRIGGERS: ReadonlySet<SenderReason> = new Set(["display_name_spoof", "sender_lookalike"]);

const SUSPICIOUS_SCORE: number = reference.fusion.thresholds.suspicious;
const NON_WEB_SCHEMES: ReadonlySet<string> = new Set(["javascript", "data", "vbscript", "file"]);
const RANK: Readonly<Record<Verdict, number>> = { safe: 0, suspicious: 1, phishing: 2 };

export interface LinkInput {
  href: string;
  text: string;
}

export interface SenderInput {
  name: string;
  email: string;
}

export interface LinkVerdict {
  /** `null` : lien sans cible web (relatif, `mailto:`, `tel:`), rien à juger. */
  verdict: Verdict | null;
  score: number;
  /** Hôte réellement visité, forme Unicode (affichage). */
  host: string;
  reasons: LinkReason[];
}

export interface MailVerdict {
  verdict: Verdict;
  links: LinkVerdict[];
  sender: SenderReason[];
  /** Liens suspects ou de phishing. */
  flagged: number;
}

export const worst = (a: Verdict, b: Verdict): Verdict => (RANK[a] >= RANK[b] ? a : b);

export function inspectLink(
  analyzer: UrlAnalyzer,
  input: LinkInput,
  isAllowlisted: (registeredDomain: string) => boolean,
): LinkVerdict {
  const { target: unwrapped } = unwrapGoogleRedirect(input.href);
  const link = makeLink(unwrapped, input.text);
  if (NON_WEB_SCHEMES.has(link.scheme)) {
    return { verdict: "suspicious", score: SUSPICIOUS_SCORE, host: "", reasons: ["non_web_link"] };
  }
  const web = link.scheme === "http" || link.scheme === "https" || link.href.startsWith("//") || link.href.startsWith("www.");
  if (!web) return { verdict: null, score: 0, host: "", reasons: [] };

  let analysis;
  try {
    const local = analyzer.score(link.target.startsWith("//") ? link.target.slice(2) : link.target);
    analysis = decide(local, { allowlisted: isAllowlisted(local.registeredDomain) });
  } catch (error) {
    if (!(error instanceof InvalidUrlError)) throw error;
    // Cible illisible : seul un texte trompeur reste à signaler.
    return link.mismatch
      ? { verdict: "suspicious", score: SUSPICIOUS_SCORE, host: "", reasons: ["text_domain_mismatch"] }
      : { verdict: null, score: 0, host: "", reasons: [] };
  }
  const reasons: LinkReason[] = [...analysis.reasons];
  let { verdict, score } = analysis;
  if (link.mismatch) {
    reasons.unshift("text_domain_mismatch");
    // La liste blanche porte sur la cible : un site de confiance reste de confiance.
    if (verdict === "safe" && analysis.hardRule !== "allowlist") {
      verdict = "suspicious";
      score = Math.max(score, SUSPICIOUS_SCORE);
    }
  }
  return { verdict, score, host: analysis.host, reasons };
}

export function inspectSender(sender: SenderInput | null): SenderReason[] {
  if (sender === null) return [];
  const address = makeAddress(sender.name, sender.email);
  if (address === null) return [];
  const reasons: SenderReason[] = [];
  if (address.domain !== null) {
    let ascii: string | null = null;
    try {
      ascii = toAscii(address.domain);
    } catch {
      ascii = null;
    }
    if (ascii !== null && hostScriptAlert(ascii) !== null) reasons.push("sender_lookalike");
  }
  if (address.registeredDomain !== null) {
    const claim = displayNameClaim(address.displayName);
    if (claim !== null && claim.domain !== null && claim.domain !== address.registeredDomain) {
      reasons.push(claim.kind === "address" ? "display_name_spoof" : "display_name_domain");
    }
  }
  return reasons;
}

export function inspectMail(
  analyzer: UrlAnalyzer,
  links: readonly LinkInput[],
  sender: SenderInput | null,
  isAllowlisted: (registeredDomain: string) => boolean,
): MailVerdict {
  const verdicts = links.map((link) => inspectLink(analyzer, link, isAllowlisted));
  const senderReasons = inspectSender(sender);
  let verdict: Verdict = "safe";
  for (const link of verdicts) if (link.verdict !== null) verdict = worst(verdict, link.verdict);
  if (senderReasons.includes("sender_lookalike")) verdict = "phishing";
  else if (senderReasons.some((r) => SENDER_TRIGGERS.has(r))) verdict = worst(verdict, "suspicious");
  const flagged = verdicts.filter((link) => link.verdict === "suspicious" || link.verdict === "phishing").length;
  return { verdict, links: verdicts, sender: senderReasons, flagged };
}
