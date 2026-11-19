/**
 * Envoi au Chrome Web Store (étape 6.9) : `publish-chrome.mjs` contre une API simulée.
 * Aucune requête réelle : `fetch` est injecté.
 */

import { describe, expect, it } from "vitest";
import { zip } from "../package.mjs";
import { accessToken, manifestFromZip, publish, PublishError, readConfig, upload } from "../publish-chrome.mjs";

const ENV = {
  CWS_CLIENT_ID: "client.apps.googleusercontent.com",
  CWS_CLIENT_SECRET: "secret-client",
  CWS_REFRESH_TOKEN: "1//refresh-token",
  CWS_PUBLISHER_ID: "publisher-123",
  CWS_EXTENSION_ID: "abcdefghijklmnopabcdefghijklmnop",
};
const TOKEN = "ya29.access-token-for-tests";

interface Call {
  url: string;
  init: Record<string, any>;
}

function api(responses: [number, unknown][]) {
  const calls: Call[] = [];
  const fetchImpl = async (url: string, init: Record<string, any> = {}) => {
    calls.push({ url, init });
    const [status, body] = responses.shift() ?? [500, { error: { message: "réponse inattendue" } }];
    return { ok: status < 400, status, statusText: "", text: async () => JSON.stringify(body) };
  };
  return { calls, fetchImpl };
}

const archive = (manifest: Record<string, unknown>) =>
  zip([
    ["background.js", Buffer.from("// code")],
    ["manifest.json", Buffer.from(JSON.stringify(manifest))],
  ]);

describe("configuration", () => {
  it("exige les cinq variables et des identifiants bien formés", () => {
    expect(readConfig(ENV).extensionId).toBe(ENV.CWS_EXTENSION_ID);
    expect(() => readConfig({ ...ENV, CWS_REFRESH_TOKEN: "" })).toThrow(/CWS_REFRESH_TOKEN/);
    expect(() => readConfig({ ...ENV, CWS_EXTENSION_ID: "pas-un-identifiant" })).toThrow(/32 lettres/);
    expect(() => readConfig({ ...ENV, CWS_PUBLISHER_ID: "../items" })).toThrow(/PUBLISHER/);
  });
});

describe("archive", () => {
  it("lit le manifeste d'une archive produite par package.mjs", () => {
    expect(manifestFromZip(archive({ version: "1.0.0" }))).toEqual({ version: "1.0.0" });
  });

  it("refuse une archive sans manifeste ou illisible", () => {
    expect(() => manifestFromZip(zip([["a.js", Buffer.from("x")]]))).toThrow(/absent/);
    expect(() => manifestFromZip(Buffer.from("pas un zip"))).toThrow(PublishError);
  });
});

describe("API", () => {
  const config = readConfig(ENV);

  it("échange le jeton de rafraîchissement, sans jamais suivre de redirection", async () => {
    const { calls, fetchImpl } = api([[200, { access_token: TOKEN, expires_in: 3599 }]]);
    expect(await accessToken(config, fetchImpl)).toBe(TOKEN);
    expect(calls[0]!.url).toBe("https://oauth2.googleapis.com/token");
    expect(calls[0]!.init["redirect"]).toBe("error");
    expect(String(calls[0]!.init["body"])).toContain("grant_type=refresh_token");
  });

  it("une erreur cite le message de l'API, jamais le jeton ni le secret", async () => {
    const { fetchImpl } = api([[401, { error: { message: "invalid_grant" } }]]);
    const error = await accessToken(config, fetchImpl).then(
      () => new Error("aucune erreur"),
      (e: Error) => e,
    );
    expect(error).toBeInstanceOf(PublishError);
    expect(error.message).toContain("invalid_grant");
    expect(error.message).not.toContain(ENV.CWS_CLIENT_SECRET);
    expect(error.message).not.toContain(ENV.CWS_REFRESH_TOKEN);
  });

  it("envoie l'archive brute au bon élément et vérifie la version annoncée", async () => {
    const { calls, fetchImpl } = api([[200, { uploadState: "SUCCEEDED", crxVersion: "1.0.0" }]]);
    const body = archive({ version: "1.0.0" });
    expect(await upload(config, TOKEN, body, "1.0.0", { fetchImpl })).toEqual({ version: "1.0.0" });
    expect(calls[0]!.url).toBe(
      "https://chromewebstore.googleapis.com/upload/v2/publishers/publisher-123/items/abcdefghijklmnopabcdefghijklmnop:upload",
    );
    expect(calls[0]!.init["headers"]).toMatchObject({ Authorization: `Bearer ${TOKEN}`, "Content-Type": "application/zip" });
    expect(calls[0]!.init["body"]).toBe(body);
  });

  it("attend la fin d'un envoi asynchrone par fetchStatus", async () => {
    const { calls, fetchImpl } = api([
      [200, { uploadState: "IN_PROGRESS" }],
      [200, { lastAsyncUploadState: "IN_PROGRESS" }],
      [200, { lastAsyncUploadState: "SUCCEEDED", submittedItemRevisionStatus: { distributionChannels: [{ crxVersion: "1.0.0" }] } }],
    ]);
    const waits: number[] = [];
    await upload(config, TOKEN, archive({ version: "1.0.0" }), "1.0.0", { fetchImpl, sleep: async (ms) => void waits.push(ms) });
    expect(calls.map((c) => c.url.split(":").pop())).toEqual(["upload", "fetchStatus", "fetchStatus"]);
    expect(waits).toEqual([2_000, 4_000]);
  });

  it("refuse un envoi échoué, ou une version différente de l'archive", async () => {
    let { fetchImpl } = api([[200, { uploadState: "FAILED" }]]);
    await expect(upload(config, TOKEN, archive({}), "1.0.0", { fetchImpl })).rejects.toThrow(/FAILED/);
    ({ fetchImpl } = api([[200, { uploadState: "SUCCEEDED", crxVersion: "0.9.0" }]]));
    await expect(upload(config, TOKEN, archive({}), "1.0.0", { fetchImpl })).rejects.toThrow(/0\.9\.0/);
  });

  it("abandonne un envoi qui ne finit jamais", async () => {
    const { fetchImpl } = api(Array.from({ length: 10 }, () => [200, { uploadState: "IN_PROGRESS", lastAsyncUploadState: "IN_PROGRESS" }]));
    await expect(upload(config, TOKEN, archive({}), "1.0.0", { fetchImpl, sleep: async () => {}, attempts: 3 })).rejects.toThrow(/IN_PROGRESS/);
  });

  it("soumet à la revue, publication différée sur demande, jamais sans revue", async () => {
    const { calls, fetchImpl } = api([[200, { state: "PENDING_REVIEW", warningInfo: { warnings: [{ reason: "x", description: "avertissement" }] } }]]);
    const result = await publish(config, TOKEN, { staged: true, fetchImpl });
    expect(result).toEqual({ state: "PENDING_REVIEW", warnings: ["avertissement"] });
    const body = JSON.parse(calls[0]!.init["body"]);
    expect(body).toEqual({ publishType: "STAGED_PUBLISH", blockOnWarnings: true });
    expect(body.skipReview).toBeUndefined();
  });
});
