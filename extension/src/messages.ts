/**
 * Messages entre les pages de l'extension et le service worker.
 *
 * Seules les pages de l'extension (fenêtre contextuelle, plus tard options) peuvent les
 * envoyer : le service worker refuse tout message venu d'un onglet (script de contenu) ou
 * d'une autre extension. Les pages n'envoient jamais d'URL : elles désignent un onglet, et
 * le service worker lit lui-même son adresse (permission `activeTab`).
 */

import type { Analysis } from "./core/analyze";

export type Request =
  | { type: "analyze-tab"; tabId: number }
  | { type: "allowlist-add-tab"; tabId: number }
  | { type: "allowlist-remove"; domain: string };

export type ErrorCode = "not-analyzable" | "no-access" | "model-unavailable" | "bad-request" | "internal";

export type Response =
  | { ok: true; analysis: Analysis; elapsedMs: number }
  | { ok: true; domain: string }
  | { ok: true }
  | { ok: false; error: ErrorCode };

/** Validation stricte d'une requête reçue (forme inconnue → `null`). */
export function parseRequest(message: unknown): Request | null {
  if (typeof message !== "object" || message === null) return null;
  const m = message as Record<string, unknown>;
  const isTabId = (value: unknown): value is number =>
    typeof value === "number" && Number.isInteger(value) && value >= 0;
  switch (m["type"]) {
    case "analyze-tab":
    case "allowlist-add-tab":
      return isTabId(m["tabId"]) ? { type: m["type"], tabId: m["tabId"] } : null;
    case "allowlist-remove":
      return typeof m["domain"] === "string" && m["domain"].length <= 253
        ? { type: "allowlist-remove", domain: m["domain"] }
        : null;
    default:
      return null;
  }
}
