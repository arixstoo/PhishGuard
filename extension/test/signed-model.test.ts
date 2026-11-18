/**
 * Vérification des modèles téléchargés (étape 6.8).
 *
 * Critère de l'étape : **un modèle falsifié (un octet modifié) est rejeté**. On le vérifie
 * octet par octet sur la signature et le manifeste, et sur des positions réparties dans
 * tout le modèle (début, fin, et un pas régulier), en plus des refus ciblés : autre clé,
 * retour arrière, autre extracteur, nom de fichier piégé, tailles démesurées.
 *
 * Interopérabilité : une publication signée par **Python** (`phishguard.registry`, fixture
 * `test/fixtures/signed-release/`) est acceptée, et le vrai manifeste du dépôt aussi quand
 * il est présent (`models/`, non versionné).
 */

import { existsSync, readFileSync } from "node:fs";
import { createPublicKey } from "node:crypto";
import { join } from "node:path";
import { beforeAll, describe, expect, it } from "vitest";
import {
  isNewerRelease,
  MAX_MANIFEST_BYTES,
  MAX_SIGNATURE_BYTES,
  ModelReleaseError,
  parseRelease,
  type RejectionCode,
  trustAnchorFromBase64,
  type TrustAnchor,
  verifyModelRelease,
} from "../src/core/signed-model";
import { canonicalJson, newSigner, signatureFor, signedRelease, type SignedRelease, type TestSigner } from "./release-fixture";

const ROOT = new URL("..", import.meta.url).pathname.replace(/^\/([A-Z]:)/, "$1");
const encoder = new TextEncoder();
const BUNDLED = "2026.11.15";
const MODEL = encoder.encode(JSON.stringify({ format: "phishguard-url-lightgbm", trees: [1, 2, 3], pad: "x".repeat(4000) }));

let signer: TestSigner;
let anchor: TrustAnchor;
let good: SignedRelease;

beforeAll(async () => {
  signer = await newSigner();
  anchor = { publicKey: signer.publicKey };
  good = await signedRelease(signer, MODEL);
});

const verify = (files: SignedRelease, notOlderThan: string | null = BUNDLED, key: TrustAnchor = anchor) =>
  verifyModelRelease(files, key, { notOlderThan });

async function rejection(promise: Promise<unknown>): Promise<RejectionCode> {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(ModelReleaseError);
    return (error as ModelReleaseError).code;
  }
  throw new Error("publication acceptée alors qu'elle devait être refusée");
}

const flip = (bytes: Uint8Array, index: number): Uint8Array => {
  const copy = bytes.slice();
  copy[index] = copy[index]! ^ 0x01;
  return copy;
};

describe("publication valide", () => {
  it("est acceptée et rend les octets vérifiés du modèle", async () => {
    const verified = await verify(good);
    expect(verified).toMatchObject({ release: "2026.12.01", modelVersion: "url_v3", artifactName: "url_v3.json" });
    expect(verified.model).toEqual(MODEL);
  });
});

describe("un octet modifié est rejeté", () => {
  it("dans le modèle (critère de l'étape 6.8)", async () => {
    const positions = new Set([0, 1, MODEL.length - 1]);
    for (let i = 0; i < MODEL.length; i += 97) positions.add(i);
    for (const index of positions) {
      expect(await rejection(verify({ ...good, model: flip(good.model, index) })), `octet ${index}`).toBe("artifact-mismatch");
    }
  });

  it("dans le manifeste, à chaque position", async () => {
    for (let index = 0; index < good.manifest.length; index++) {
      const code = await rejection(verify({ ...good, manifest: flip(good.manifest, index) }));
      // La signature porte sur les octets exacts : rien n'est interprété avant elle.
      expect(["bad-signature", "malformed-manifest"], `octet ${index} → ${code}`).toContain(code);
    }
  });

  it("dans la signature, à chaque position", async () => {
    for (let index = 0; index < good.signature.length; index++) {
      const code = await rejection(verify({ ...good, signature: flip(good.signature, index) }));
      expect(["bad-signature", "malformed-signature", "unknown-key"], `octet ${index} → ${code}`).toContain(code);
    }
  });

  it("un modèle tronqué ou rallongé d'un octet", async () => {
    expect(await rejection(verify({ ...good, model: good.model.slice(0, -1) }))).toBe("artifact-mismatch");
    const longer = new Uint8Array(good.model.length + 1);
    longer.set(good.model);
    expect(await rejection(verify({ ...good, model: longer }))).toBe("artifact-mismatch");
  });
});

describe("clé", () => {
  it("une publication signée par une autre clé est refusée", async () => {
    const other = await signedRelease(await newSigner(), MODEL);
    expect(await rejection(verify(other))).toBe("unknown-key");
  });

  it("une autre clé qui recopie le bon key_id ne passe pas : seule la cryptographie compte", async () => {
    const intruder = await newSigner();
    const forged = await signatureFor({ publicKey: signer.publicKey, sign: intruder.sign }, good.manifest);
    expect(await rejection(verify({ ...good, signature: forged }))).toBe("bad-signature");
  });

  it("clé embarquée : base64 canonique de 32 octets, sinon aucune mise à jour possible", () => {
    const raw = btoa(String.fromCharCode(...signer.publicKey));
    expect(trustAnchorFromBase64(raw)?.publicKey).toEqual(signer.publicKey);
    expect(trustAnchorFromBase64("")).toBeNull();
    expect(trustAnchorFromBase64("AAAA")).toBeNull();
  });
});

describe("document de signature validé en entier", () => {
  const document = async () => JSON.parse(new TextDecoder().decode(good.signature)) as Record<string, unknown>;

  it("JSON non canonique (espaces, ordre des clés) refusé", async () => {
    const doc = await document();
    const spaced = encoder.encode(JSON.stringify(doc, null, 1));
    expect(await rejection(verify({ ...good, signature: spaced }))).toBe("malformed-signature");
    const reordered = encoder.encode(JSON.stringify({ signature: doc["signature"], ...doc }));
    expect(await rejection(verify({ ...good, signature: reordered }))).toBe("malformed-signature");
  });

  it("champ en trop ou manquant refusé", async () => {
    const doc = await document();
    const extra = encoder.encode(canonicalJson({ ...doc, comment: "x" }));
    expect(await rejection(verify({ ...good, signature: extra }))).toBe("malformed-signature");
    const { key_id: _ignored, ...missing } = doc;
    expect(await rejection(verify({ ...good, signature: encoder.encode(canonicalJson(missing)) }))).toBe("malformed-signature");
  });

  it("base64 malléable (bits inutilisés du dernier caractère) refusé", async () => {
    const doc = await document();
    const text = doc["signature"] as string;
    // 64 octets → 88 caractères dont « == » : le caractère avant porte 4 bits inutilisés.
    const last = text.at(-3)!;
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const twin = alphabet[alphabet.indexOf(last) ^ 0x01]!;
    const malleable = { ...doc, signature: `${text.slice(0, -3)}${twin}==` };
    expect(atob(malleable.signature as string)).toBe(atob(text)); // mêmes octets décodés
    expect(await rejection(verify({ ...good, signature: encoder.encode(canonicalJson(malleable)) }))).toBe(
      "malformed-signature",
    );
  });

  it("autre algorithme ou version de format refusés", async () => {
    const doc = await document();
    for (const patch of [{ algorithm: "rsa" }, { format_version: 2 }]) {
      const bytes = encoder.encode(canonicalJson({ ...doc, ...patch }));
      expect(await rejection(verify({ ...good, signature: bytes }))).toBe("malformed-signature");
    }
  });
});

describe("retour arrière", () => {
  it("une publication pas plus récente que le paquet est refusée, même bien signée", async () => {
    expect(await rejection(verify(good, "2026.12.01"))).toBe("rollback");
    expect(await rejection(verify(good, "2027.01.01"))).toBe("rollback");
    await expect(verify(good, "2026.11.30")).resolves.toBeDefined();
  });

  it("ordre total des publications, rang du jour compris", () => {
    expect(isNewerRelease("2026.12.01.1", "2026.12.01")).toBe(true);
    expect(isNewerRelease("2026.12.01.10", "2026.12.01.9")).toBe(true);
    expect(isNewerRelease("2026.12.01", "2026.12.01.1")).toBe(false);
    expect(isNewerRelease("2027.01.01", "2026.12.31")).toBe(true);
    expect(isNewerRelease("2026.12.01", null)).toBe(true);
    expect(isNewerRelease("v2", null)).toBe(false); // illisible : jamais plus récente
    expect(parseRelease("2026.13.01")).toBeNull();
    expect(parseRelease("2026.12.01-rc")).toBeNull();
  });

  it("une publication au format non daté est refusée", async () => {
    const odd = await signedRelease(signer, MODEL, { release: "latest" });
    expect(await rejection(verify(odd))).toBe("malformed-manifest");
  });
});

describe("contenu du manifeste (signé, mais incohérent)", () => {
  it("modèle d'un autre extracteur de features", async () => {
    for (const options of [{ extractorVersion: "2.0.0" }, { referenceSha256: "f".repeat(64) }]) {
      const release = await signedRelease(signer, MODEL, options);
      expect(await rejection(verify(release))).toBe("incompatible-extractor");
    }
  });

  it("nom d'artefact qui sort du dossier, ou différent du modèle annoncé", async () => {
    for (const name of ["../url_v3.json", "/etc/url_v3.json", ".url_v3.json", "url_v4.json"]) {
      const release = await signedRelease(signer, MODEL, {
        edit: (m) => {
          (m["artifacts"] as Record<string, unknown>[])[1]!["name"] = name;
        },
      });
      expect(await rejection(verify(release)), name).toBe("malformed-manifest");
    }
  });

  it("aucun ou plusieurs artefacts url-export", async () => {
    const none = await signedRelease(signer, MODEL, { edit: (m) => void (m["artifacts"] = []) });
    expect(await rejection(verify(none))).toBe("missing-artifact");
    const two = await signedRelease(signer, MODEL, {
      edit: (m) => {
        const artifacts = m["artifacts"] as Record<string, unknown>[];
        artifacts.push({ ...artifacts[1]!, name: "url_v3b.json" });
      },
    });
    expect(await rejection(verify(two))).toBe("missing-artifact");
  });

  it("taille annoncée démesurée : refusée avant toute lecture du modèle", async () => {
    const huge = await signedRelease(signer, MODEL, {
      edit: (m) => void ((m["artifacts"] as Record<string, unknown>[])[1]!["size"] = 64 * 1024 * 1024),
    });
    expect(await rejection(verify(huge))).toBe("malformed-manifest");
  });
});

describe("tailles bornées avant interprétation", () => {
  it("manifeste ou signature trop volumineux", async () => {
    expect(await rejection(verify({ ...good, manifest: new Uint8Array(MAX_MANIFEST_BYTES + 1) }))).toBe("too-large");
    expect(await rejection(verify({ ...good, signature: new Uint8Array(MAX_SIGNATURE_BYTES + 1) }))).toBe("too-large");
  });
});

// --------------------------------------------------------------------------- //
// Interopérabilité avec Python (phishguard.registry)
// --------------------------------------------------------------------------- //

const rawKey = (pem: string): Uint8Array => new Uint8Array(createPublicKey(pem).export({ format: "der", type: "spki" }).subarray(-32));

describe("publications signées par Python", () => {
  const fixture = join(ROOT, "test/fixtures/signed-release");

  it("la fixture produite par phishguard.registry est acceptée, et refusée au moindre octet", async () => {
    const files = {
      manifest: new Uint8Array(readFileSync(join(fixture, "manifest.json"))),
      signature: new Uint8Array(readFileSync(join(fixture, "manifest.json.sig"))),
      model: new Uint8Array(readFileSync(join(fixture, "url_v9.json"))),
    };
    const key = { publicKey: rawKey(readFileSync(join(fixture, "public.pem"), "utf-8")) };
    const verified = await verifyModelRelease(files, key, { notOlderThan: BUNDLED });
    expect(verified).toMatchObject({ release: "2026.12.01", modelVersion: "url_v9" });
    expect(await rejection(verifyModelRelease({ ...files, model: flip(files.model, 10) }, key, { notOlderThan: BUNDLED }))).toBe(
      "artifact-mismatch",
    );
  });

  const models = join(ROOT, "../models");
  it.skipIf(!existsSync(join(models, "manifest.json")))("le vrai manifeste du dépôt passe la vérification de l'extension", async () => {
    const manifest = new Uint8Array(readFileSync(join(models, "manifest.json")));
    const doc = JSON.parse(new TextDecoder().decode(manifest)) as { artifacts: { name: string; role: string }[] };
    const name = doc.artifacts.find((a) => a.role === "url-export")!.name;
    const files = {
      manifest,
      signature: new Uint8Array(readFileSync(join(models, "manifest.json.sig"))),
      model: new Uint8Array(readFileSync(join(models, name))),
    };
    const key = { publicKey: rawKey(readFileSync(join(ROOT, "../keys/model-signing.pub"), "utf-8")) };
    await expect(verifyModelRelease(files, key, { notOlderThan: null })).resolves.toMatchObject({ artifactName: name });
  });
});
