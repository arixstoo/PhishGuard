/**
 * Messages vers le service worker. Deux émetteurs, deux protocoles, jamais mélangés :
 *
 * - **Pages de l'extension** (fenêtre contextuelle, options), vérifiées par leur origine :
 *   analyse d'un onglet, liste blanche, signalement. Elles désignent un onglet, jamais une
 *   URL : le service worker lit lui-même son adresse (permission `activeTab`).
 * - **Script de contenu Gmail**, vérifié par son origine (`https://mail.google.com`, cadre
 *   principal) : **une seule** requête, l'analyse des liens du message ouvert. Il tourne
 *   dans une page qu'il faut supposer hostile : il ne peut ni lire ni modifier la liste
 *   blanche, ni analyser un onglet, ni rien envoyer sur le réseau.
 *
 * Toute requête est validée strictement ; une forme inconnue est refusée.
 */

import type { Analysis, Verdict } from "./core/analyze";
import type { LinkInput, LinkVerdict, SenderInput, SenderReason } from "./core/inspect";
import { MAX_LINK_HREF_CHARS, MAX_LINK_TEXT_CHARS, MAX_MAIL_LINKS } from "./limits";
import type { Judgement, RemoteAnalysis } from "./api";
import type { Language } from "./i18n";

export type Request =
  | { type: "analyze-tab"; tabId: number }
  | { type: "analyze-tab-online"; tabId: number }
  | { type: "allowlist-add-tab"; tabId: number }
  | { type: "allowlist-add-domain"; domain: string }
  | { type: "allowlist-remove"; domain: string }
  | { type: "allowlist-get" }
  | { type: "feedback"; domain: string; verdict: Verdict; judgement: Judgement };

export interface MailRequest {
  type: "mail-inspect";
  links: LinkInput[];
  sender: SenderInput | null;
}

export type ErrorCode =
  | "not-analyzable"
  | "no-access"
  | "model-unavailable"
  | "bad-request"
  | "internal"
  | "network-disabled"
  | "remote-failed"
  | "not-reportable"
  | "invalid-domain"
  | "allowlist-full"
  | "disabled";

export type Response =
  | { ok: true; analysis: Analysis; elapsedMs: number; online: boolean }
  | { ok: true; remote: RemoteAnalysis; verdict: Verdict }
  | { ok: true; domain: string }
  | { ok: true; domains: string[] }
  | { ok: true }
  | { ok: false; error: ErrorCode };

export type MailResponse =
  | {
      ok: true;
      language: Language;
      verdict: Verdict;
      flagged: number;
      links: LinkVerdict[];
      sender: SenderReason[];
    }
  | { ok: false; error: ErrorCode };

const MAX_DOMAIN_CHARS = 253;
const MAX_SENDER_NAME_CHARS = 256;
const MAX_SENDER_EMAIL_CHARS = 320;
const VERDICTS: readonly unknown[] = ["safe", "suspicious", "phishing"];
const JUDGEMENTS: readonly unknown[] = ["false_positive", "false_negative"];

const asRecord = (value: unknown): Record<string, unknown> | null =>
  typeof value === "object" && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
const isTabId = (value: unknown): value is number => typeof value === "number" && Number.isInteger(value) && value >= 0;
const isText = (value: unknown, max: number): value is string => typeof value === "string" && value.length <= max;
const isDomain = (value: unknown): value is string => isText(value, MAX_DOMAIN_CHARS) && value.length > 0;

/** Requête d'une page de l'extension (forme inconnue → `null`). */
export function parseRequest(message: unknown): Request | null {
  const m = asRecord(message);
  if (m === null) return null;
  switch (m["type"]) {
    case "analyze-tab":
    case "analyze-tab-online":
    case "allowlist-add-tab":
      return isTabId(m["tabId"]) ? { type: m["type"], tabId: m["tabId"] } : null;
    case "allowlist-add-domain":
    case "allowlist-remove":
      return isDomain(m["domain"]) ? { type: m["type"], domain: m["domain"] } : null;
    case "allowlist-get":
      return { type: "allowlist-get" };
    case "feedback":
      return isDomain(m["domain"]) && VERDICTS.includes(m["verdict"]) && JUDGEMENTS.includes(m["judgement"])
        ? {
            type: "feedback",
            domain: m["domain"],
            verdict: m["verdict"] as Verdict,
            judgement: m["judgement"] as Judgement,
          }
        : null;
    default:
      return null;
  }
}

/** Requête du script de contenu Gmail (forme inconnue ou hors bornes → `null`). */
export function parseMailRequest(message: unknown): MailRequest | null {
  const m = asRecord(message);
  if (m === null || m["type"] !== "mail-inspect") return null;
  const links = m["links"];
  if (!Array.isArray(links) || links.length > MAX_MAIL_LINKS) return null;
  const parsed: LinkInput[] = [];
  for (const item of links) {
    const link = asRecord(item);
    if (link === null || !isText(link["href"], MAX_LINK_HREF_CHARS) || !isText(link["text"], MAX_LINK_TEXT_CHARS)) {
      return null;
    }
    parsed.push({ href: link["href"], text: link["text"] });
  }
  let sender: SenderInput | null = null;
  if (m["sender"] !== null && m["sender"] !== undefined) {
    const s = asRecord(m["sender"]);
    if (s === null || !isText(s["name"], MAX_SENDER_NAME_CHARS) || !isText(s["email"], MAX_SENDER_EMAIL_CHARS)) {
      return null;
    }
    sender = { name: s["name"], email: s["email"] };
  }
  return { type: "mail-inspect", links: parsed, sender };
}
