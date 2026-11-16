/**
 * Réglages et réseau (étape 5.7) : **par défaut, aucune requête**.
 *
 * `fetch` et `chrome.permissions` sont simulés : on vérifie qu'aucun appel ne part tant
 * que les deux clés (réglage + permission de l'hôte) ne sont pas réunies, puis la forme
 * exacte de ce qui part, et le refus de toute réponse hors schéma.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  analyzeOnline,
  NetworkDisabledError,
  parseRemoteAnalysis,
  RemoteError,
  sendFeedback,
  strictest,
  urlForServer,
} from "../src/api";
import { DEFAULT_SETTINGS, parseServerUrl, parseSettings, serverPermissionPattern, type Settings } from "../src/settings";

const KEY = `pg_${"A".repeat(43)}`;
const REMOTE = {
  verdict: "phishing",
  score: 91,
  reasons: [{ code: "signal.virustotal_engines", message: "6 antivirus signalent ce site.", points: 60, params: {} }],
  advice: "N'entrez aucun mot de passe.",
  enrichment: "used",
  model_version: "url_v2",
  signals: {},
  mitre: [],
};

let granted: string[];
let fetchMock: ReturnType<typeof vi.fn>;

beforeEach(() => {
  granted = [];
  fetchMock = vi.fn(async () => new Response(JSON.stringify(REMOTE), { status: 200 }));
  vi.stubGlobal("fetch", fetchMock);
  vi.stubGlobal("chrome", {
    permissions: { contains: vi.fn(async ({ origins }: { origins: string[] }) => origins.every((o) => granted.includes(o))) },
  });
});

afterEach(() => vi.unstubAllGlobals());

const online = (overrides: Partial<Settings> = {}): Settings =>
  parseSettings({ ...DEFAULT_SETTINGS, serverUrl: "https://pg.exemple.org", enrichment: true, feedback: true, ...overrides });

describe("réglages", () => {
  it("par défaut : rien ne sort de l'appareil", () => {
    expect(parseSettings(undefined)).toEqual(DEFAULT_SETTINGS);
    expect(DEFAULT_SETTINGS).toMatchObject({ enrichment: false, feedback: false, autoAnalyze: false, serverUrl: "" });
  });

  it("une valeur invalide revient à son défaut (storage.local est modifiable par un script de contenu)", () => {
    const s = parseSettings({ language: "de", gmail: "oui", autoAnalyze: 1, apiKey: "secret", serverUrl: 42, extra: true });
    expect(s).toEqual(DEFAULT_SETTINGS);
  });

  it("sans serveur valide, les options réseau sont éteintes", () => {
    expect(parseSettings({ enrichment: true, feedback: true, apiKey: KEY })).toMatchObject({
      enrichment: false,
      feedback: false,
      apiKey: "",
    });
    expect(parseSettings({ enrichment: true, serverUrl: "http://evil.example" }).enrichment).toBe(false);
  });

  it.each([
    ["https://pg.exemple.org", "https://pg.exemple.org"],
    ["https://pg.exemple.org/", "https://pg.exemple.org"],
    [" https://PG.Exemple.org:8443/api/ ", "https://pg.exemple.org:8443/api"],
    ["http://127.0.0.1:8000", "http://127.0.0.1:8000"],
    ["http://localhost:8000/", "http://localhost:8000"],
  ])("serveur accepté : %s", (input, expected) => {
    expect(parseServerUrl(input)).toBe(expected);
  });

  it.each([
    "http://pg.exemple.org", // http hors boucle locale
    "http://192.168.1.10:8000",
    "https://user:pass@pg.exemple.org",
    "https://pg.exemple.org/?token=x",
    "https://pg.exemple.org/#x",
    "https://pg.exemple.org/?",
    "javascript:alert(1)",
    "chrome-extension://abc/",
    "ftp://pg.exemple.org",
    "pg.exemple.org",
    "",
    `https://${"a".repeat(600)}.org`,
  ])("serveur refusé : %s", (input) => {
    expect(parseServerUrl(input)).toBeNull();
  });

  it("demande la permission de l'hôte seul (pas d'un motif plus large)", () => {
    expect(serverPermissionPattern("https://pg.exemple.org:8443/api")).toBe("https://pg.exemple.org/*");
  });
});

describe("aucune requête sans les deux clés", () => {
  it("réglage désactivé : pas de fetch", async () => {
    granted = ["https://pg.exemple.org/*"];
    await expect(analyzeOnline(online({ enrichment: false }), "https://x.fr/", "fr")).rejects.toThrow(NetworkDisabledError);
    await expect(sendFeedback(online({ feedback: false }), "x.fr", "phishing", "false_positive")).rejects.toThrow(
      NetworkDisabledError,
    );
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("permission de l'hôte absente : pas de fetch, même si les réglages ont été modifiés", async () => {
    await expect(analyzeOnline(online(), "https://x.fr/", "fr")).rejects.toThrow(NetworkDisabledError);
    granted = ["https://autre.exemple.org/*"];
    await expect(analyzeOnline(online(), "https://x.fr/", "fr")).rejects.toThrow(NetworkDisabledError);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("réglages par défaut : pas de fetch", async () => {
    granted = ["https://pg.exemple.org/*"];
    await expect(analyzeOnline(parseSettings({}), "https://x.fr/", "fr")).rejects.toThrow(NetworkDisabledError);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe("ce qui part", () => {
  beforeEach(() => {
    granted = ["https://pg.exemple.org/*"];
  });

  it("analyse : URL sans fragment, aucun cookie, aucune redirection suivie", async () => {
    const result = await analyzeOnline(online({ apiKey: KEY }), "https://x.fr/login?next=1#access_token=SECRET", "ar");
    expect(fetchMock).toHaveBeenCalledOnce();
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://pg.exemple.org/v1/analyze/url");
    expect(JSON.parse(init.body as string)).toEqual({
      url: "https://x.fr/login?next=1",
      language: "ar",
      use_threat_intel: true,
      analyst: false,
    });
    expect(init).toMatchObject({ method: "POST", credentials: "omit", redirect: "error", referrerPolicy: "no-referrer" });
    expect(init.headers).toMatchObject({ "X-API-Key": KEY, "Content-Type": "application/json" });
    expect(result).toEqual({
      verdict: "phishing",
      score: 91,
      reasons: [{ code: "signal.virustotal_engines", message: "6 antivirus signalent ce site." }],
      advice: "N'entrez aucun mot de passe.",
      enrichment: "used",
      modelVersion: "url_v2",
    });
  });

  it("sans clé d'API : aucun en-tête X-API-Key", async () => {
    await analyzeOnline(online(), "https://x.fr/", "fr");
    expect((fetchMock.mock.calls[0]![1] as RequestInit).headers).not.toHaveProperty("X-API-Key");
  });

  it("chemin du serveur conservé (serveur derrière un proxy)", async () => {
    granted = ["https://pg.exemple.org/*"];
    await analyzeOnline(online({ serverUrl: "https://pg.exemple.org/phishguard" }), "https://x.fr/", "fr");
    expect(fetchMock.mock.calls[0]![0]).toBe("https://pg.exemple.org/phishguard/v1/analyze/url");
  });

  it("URL trop longue pour l'API : rien n'est envoyé", async () => {
    await expect(analyzeOnline(online(), `https://x.fr/${"a".repeat(2100)}`, "fr")).rejects.toThrow(RemoteError);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("signalement : le domaine seulement", async () => {
    await sendFeedback(online(), "paypa1.example", "phishing", "false_positive");
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://pg.exemple.org/v1/feedback");
    expect(JSON.parse(init.body as string)).toEqual({
      domain: "paypa1.example",
      verdict: "phishing",
      judgement: "false_positive",
    });
  });

  it("signalement incohérent (faux positif sur un verdict sûr) : refusé avant l'envoi", async () => {
    await expect(sendFeedback(online(), "x.fr", "safe", "false_positive")).rejects.toThrow(RemoteError);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it.each([
    [500, "http"],
    [429, "http"],
  ])("erreur HTTP %s", async (status, code) => {
    fetchMock.mockResolvedValueOnce(new Response("{}", { status }));
    await expect(analyzeOnline(online(), "https://x.fr/", "fr")).rejects.toMatchObject({ code });
  });

  it("panne réseau ou délai dépassé", async () => {
    fetchMock.mockRejectedValueOnce(new TypeError("Failed to fetch"));
    await expect(analyzeOnline(online(), "https://x.fr/", "fr")).rejects.toMatchObject({ code: "network" });
    fetchMock.mockRejectedValueOnce(new DOMException("timeout", "TimeoutError"));
    await expect(analyzeOnline(online(), "https://x.fr/", "fr")).rejects.toMatchObject({ code: "timeout" });
  });
});

describe("réponse du serveur : non fiable", () => {
  it.each([
    ["verdict inconnu", { ...REMOTE, verdict: "ok" }],
    ["score hors bornes", { ...REMOTE, score: 101 }],
    ["score non entier", { ...REMOTE, score: 1.5 }],
    ["score en texte", { ...REMOTE, score: "12" }],
    ["plus de trois raisons", { ...REMOTE, reasons: Array(4).fill(REMOTE.reasons[0]) }],
    ["raison sans message", { ...REMOTE, reasons: [{ code: "x" }] }],
    ["message démesuré", { ...REMOTE, reasons: [{ code: "x", message: "a".repeat(1000) }] }],
    ["conseil absent", { ...REMOTE, advice: undefined }],
    ["enrichissement inconnu", { ...REMOTE, enrichment: "maybe" }],
    ["tableau", [REMOTE]],
    ["null", null],
  ])("refuse : %s", (_, value) => {
    expect(() => parseRemoteAnalysis(value)).toThrow(RemoteError);
  });

  it("refuse une réponse trop grosse ou qui n'est pas du JSON", async () => {
    granted = ["https://pg.exemple.org/*"];
    fetchMock.mockResolvedValueOnce(new Response("x".repeat(300_000), { status: 200 }));
    await expect(analyzeOnline(online(), "https://x.fr/", "fr")).rejects.toMatchObject({ code: "invalid-response" });
    fetchMock.mockResolvedValueOnce(new Response("<html>", { status: 200 }));
    await expect(analyzeOnline(online(), "https://x.fr/", "fr")).rejects.toMatchObject({ code: "invalid-response" });
  });

  it("ne peut jamais rendre le verdict plus rassurant que l'analyse locale", () => {
    expect(strictest("phishing", "safe")).toBe("phishing");
    expect(strictest("suspicious", "safe")).toBe("suspicious");
    expect(strictest("safe", "phishing")).toBe("phishing");
    expect(strictest("safe", "safe")).toBe("safe");
  });

  it("retire le fragment, et lui seul", () => {
    expect(urlForServer("https://x.fr/a?b=1#c")).toBe("https://x.fr/a?b=1");
    expect(urlForServer("https://x.fr/a?b=1")).toBe("https://x.fr/a?b=1");
  });
});
