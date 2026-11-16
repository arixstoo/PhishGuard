/** Décision locale (fusion sans enrichissement) et validation des messages. */

import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { decide, type LocalScore, MAX_ANALYZED_URL_CHARS, toScore, UrlAnalyzer, verdictFor } from "../src/core/analyze";
import { InvalidUrlError } from "../src/core/features";
import { loadUrlModel } from "../src/core/model";
import { parseRequest } from "../src/messages";

const local = (overrides: Partial<LocalScore> = {}): LocalScore => ({
  host: "exemple.fr",
  registeredDomain: "exemple.fr",
  modelVersion: "test",
  rawScore: 0.5,
  probability: 0.5,
  hostAlert: null,
  reasons: [],
  ...overrides,
});

describe("décision", () => {
  it("suit les seuils de fusion.json : sûr < 30 ≤ suspect ≤ 70 < phishing", () => {
    expect(verdictFor(29)).toBe("safe");
    expect(verdictFor(30)).toBe("suspicious");
    expect(verdictFor(70)).toBe("suspicious");
    expect(verdictFor(71)).toBe("phishing");
  });

  it("arrondit comme to_score (0,5 vers le haut, bornes 0 et 100)", () => {
    expect(toScore(0.295)).toBe(30);
    expect(toScore(0.2949)).toBe(29);
    expect(toScore(-1)).toBe(0);
    expect(toScore(2)).toBe(100);
  });

  it("donne le score du modèle sans règle dure", () => {
    const a = decide(local({ probability: 0.42 }));
    expect([a.score, a.verdict, a.hardRule]).toEqual([42, "suspicious", null]);
  });

  it("applique la liste blanche", () => {
    const a = decide(local({ probability: 0.99 }), { allowlisted: true });
    expect([a.score, a.verdict, a.hardRule]).toEqual([0, "safe", "allowlist"]);
  });

  it("place l'hôte imitateur AVANT la liste blanche, comme l'API", () => {
    // Une liste blanche obtenue par confusion (аpple.com pris pour apple.com) n'innocente pas.
    const a = decide(local({ probability: 0.01, hostAlert: "mixed_script_label" }), { allowlisted: true });
    expect([a.score, a.verdict, a.hardRule]).toEqual([100, "phishing", "lookalike_host"]);
  });

  it("signale une URL trop longue au lieu de l'ignorer (pas d'évasion par la longueur)", () => {
    const parity = JSON.parse(
      readFileSync(new URL("./fixtures/python-parity.json", import.meta.url), "utf-8"),
    ) as { synthetic_models: { model: unknown }[] };
    const analyzer = new UrlAnalyzer(loadUrlModel(parity.synthetic_models[0]!.model));
    const long = `https://exemple.fr/?${"a".repeat(MAX_ANALYZED_URL_CHARS)}`;
    const a = decide(analyzer.score(long), { allowlisted: true });
    expect([a.verdict, a.hardRule]).toEqual(["suspicious", "url_too_long"]);
    expect(() => analyzer.score("chrome://settings")).toThrow(InvalidUrlError);
    expect(() => analyzer.score("file:///C:/secret.txt")).toThrow(InvalidUrlError);
  });
});

describe("messages", () => {
  it.each([
    [{ type: "analyze-tab", tabId: 3 }, { type: "analyze-tab", tabId: 3 }],
    [{ type: "allowlist-add-tab", tabId: 0 }, { type: "allowlist-add-tab", tabId: 0 }],
    [{ type: "allowlist-remove", domain: "exemple.fr", extra: 1 }, { type: "allowlist-remove", domain: "exemple.fr" }],
  ])("accepte %j", (message, expected) => {
    expect(parseRequest(message)).toEqual(expected);
  });

  it.each([
    null,
    "analyze-tab",
    { type: "analyze-tab" },
    { type: "analyze-tab", tabId: -1 },
    { type: "analyze-tab", tabId: 1.5 },
    { type: "analyze-tab", tabId: "1" },
    { type: "analyze-url", url: "https://evil.example" }, // une page ne transmet jamais d'URL
    { type: "allowlist-remove", domain: "x".repeat(254) },
    { type: "__proto__" },
  ])("refuse %j", (message) => {
    expect(parseRequest(message)).toBeNull();
  });
});
