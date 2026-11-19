/**
 * Publications signées de test (étape 6.8) : même format que `phishguard.registry`
 * (JSON canonique, signature détachée Ed25519), avec une clé éphémère créée par le test.
 */

import { FEATURE_EXTRACTOR_VERSION, REFERENCE_DATA_SHA256 } from "../src/core/features";
import { keyId, sha256Hex } from "../src/core/signed-model";

const encoder = new TextEncoder();

/** `json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False)` de Python. */
export function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${canonicalJson(record[k])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

export interface TestSigner {
  publicKey: Uint8Array;
  sign: (bytes: Uint8Array) => Promise<Uint8Array>;
}

export async function newSigner(): Promise<TestSigner> {
  const pair = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const publicKey = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  return {
    publicKey,
    sign: async (bytes) => new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, pair.privateKey, bytes.slice())),
  };
}

export interface ReleaseOptions {
  release?: string;
  modelVersion?: string;
  extractorVersion?: string;
  referenceSha256?: string;
  /** Modifie le manifeste juste avant la signature (artefacts, champs…). */
  edit?: (manifest: Record<string, unknown>) => void;
}

export interface SignedRelease {
  manifest: Uint8Array;
  signature: Uint8Array;
  model: Uint8Array;
}

/** Signature détachée canonique, exactement comme `registry.sign_manifest`. */
export async function signatureFor(signer: TestSigner, manifest: Uint8Array): Promise<Uint8Array> {
  const raw = await signer.sign(manifest);
  const document = {
    algorithm: "ed25519",
    format_version: 1,
    key_id: await keyId(signer.publicKey),
    signature: btoa(String.fromCharCode(...raw)),
  };
  return encoder.encode(canonicalJson(document));
}

/** Publication complète : manifeste canonique signé, et le modèle qu'il décrit. */
export async function signedRelease(
  signer: TestSigner,
  model: Uint8Array,
  options: ReleaseOptions = {},
): Promise<SignedRelease> {
  const modelVersion = options.modelVersion ?? "url_v3";
  const manifestDoc: Record<string, unknown> = {
    format: "phishguard-model-manifest",
    format_version: 1,
    release: options.release ?? "2026.12.01",
    created_at: "2026-12-01T03:00:00Z",
    normalization_version: "1.0.0",
    models: {
      url: {
        version: modelVersion,
        trained_at: "2026-12-01T02:00:00+00:00",
        metrics: null,
        feature_extractor: {
          version: options.extractorVersion ?? FEATURE_EXTRACTOR_VERSION,
          reference_data_sha256: options.referenceSha256 ?? REFERENCE_DATA_SHA256,
          features: ["host_len"],
        },
      },
    },
    artifacts: [
      { name: `${modelVersion}.joblib`, role: "url-model", sha256: "0".repeat(64), size: 10 },
      { name: `${modelVersion}.json`, role: "url-export", sha256: await sha256Hex(model), size: model.length },
    ],
  };
  options.edit?.(manifestDoc);
  const manifest = encoder.encode(canonicalJson(manifestDoc));
  return { manifest, signature: await signatureFor(signer, manifest), model };
}
