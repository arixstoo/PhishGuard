/**
 * Publication de modèle signée (étape 6.8) : vérification d'un modèle **téléchargé**.
 *
 * MV3 interdit le code distant, pas les données : l'extension peut recevoir un nouveau
 * modèle URL (du JSON, jamais du code). Ce module décide si ces octets sont dignes de
 * confiance ; il ne fait aucune requête et ne touche à aucun stockage.
 *
 * Même contrat que `phishguard.registry.verify_manifest` (étape 4.12), même ordre :
 *
 * 1. **tailles bornées** avant toute interprétation ;
 * 2. **signature d'abord**, Ed25519, sur les octets exacts du manifeste, avec la clé
 *    publique **embarquée dans l'extension** au build. Le document de signature est
 *    validé en entier : champs exacts, JSON canonique, base64 canonique (deux défauts
 *    trouvés côté Python par le test « un octet », docs/model-registry.md) ;
 * 3. seulement ensuite, le manifeste : format, version de publication, extracteur de
 *    features **identique** à celui de l'extension, artefact `url-export` au nom plat ;
 * 4. le modèle : **taille puis SHA-256** signés ;
 * 5. **pas de retour arrière** : la publication doit être strictement plus récente que
 *    celle du paquet (et que la dernière acceptée) ; un ancien modèle correctement signé
 *    ne peut donc pas être rejoué.
 *
 * Ainsi, une compromission de l'hébergement (GitHub, CDN, réseau) ne suffit pas à
 * tromper l'extension : il faudrait la clé privée, qui ne quitte pas la machine de
 * publication. Le contenu du modèle est ensuite revérifié nœud par nœud par
 * `loadUrlModel` (défense en profondeur).
 */

import { FEATURE_EXTRACTOR_VERSION, REFERENCE_DATA_SHA256 } from "./features";
import { NORMALIZATION_VERSION } from "./normalize";

export const MANIFEST_FORMAT = "phishguard-model-manifest";
export const MANIFEST_FORMAT_VERSION = 1;
export const SIGNATURE_ALGORITHM = "ed25519";
export const MODEL_ROLE = "url-export";

/** Mêmes bornes que `phishguard.registry` (manifeste 1 Mio, signature 4 Kio). */
export const MAX_MANIFEST_BYTES = 1024 * 1024;
export const MAX_SIGNATURE_BYTES = 4096;
/** `url_v2.json` pèse 3,3 Mio ; au-delà de 16 Mio, le fichier est refusé sans être lu. */
export const MAX_MODEL_BYTES = 16 * 1024 * 1024;

const KEY_ID_HEX_CHARS = 16;
const ARTIFACT_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
/** Publication datée, totalement ordonnée : `2026.12.01`, ou `2026.12.01.2` le même jour. */
const RELEASE = /^(\d{4})\.(\d{2})\.(\d{2})(?:\.(\d{1,3}))?$/;
const SIGNATURE_FIELDS = ["algorithm", "format_version", "key_id", "signature"] as const;

export type RejectionCode =
  | "too-large"
  | "malformed-signature"
  | "unknown-key"
  | "bad-signature"
  | "malformed-manifest"
  | "incompatible-extractor"
  | "missing-artifact"
  | "artifact-mismatch"
  | "rollback";

/** Refus d'une publication ; `code` est stable (affiché, testé), le message est pour les humains. */
export class ModelReleaseError extends Error {
  override name = "ModelReleaseError";
  constructor(
    readonly code: RejectionCode,
    message: string,
  ) {
    super(message);
  }
}

/** Clé de confiance, embarquée dans l'extension au build (`keys/model-signing.pub`). */
export interface TrustAnchor {
  /** Clé publique Ed25519 brute, 32 octets. */
  publicKey: Uint8Array;
}

/** Ce qui a été téléchargé (ou relu depuis le stockage), octets exacts. */
export interface ModelReleaseFiles {
  manifest: Uint8Array;
  signature: Uint8Array;
  model: Uint8Array;
}

export interface VerifiedModelRelease {
  release: string;
  modelVersion: string;
  /** Nom de l'artefact `url-export` dans le manifeste (`url_v3.json`). */
  artifactName: string;
  sha256: string;
  /** Octets du modèle, ceux-là mêmes dont l'empreinte a été vérifiée. */
  model: Uint8Array;
}

const reject = (code: RejectionCode, message: string): never => {
  throw new ModelReleaseError(code, message);
};

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const hex = (bytes: ArrayBuffer | Uint8Array): string =>
  Array.from(bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes), (b) => b.toString(16).padStart(2, "0")).join(
    "",
  );

/** Copie dans un `ArrayBuffer` propre : WebCrypto refuse les vues partagées de certains moteurs. */
const buffer = (bytes: Uint8Array): ArrayBuffer => bytes.slice().buffer;

export async function sha256Hex(bytes: Uint8Array): Promise<string> {
  return hex(await crypto.subtle.digest("SHA-256", buffer(bytes)));
}

/** Identifiant de clé : 16 caractères hexadécimaux du SHA-256 de la clé brute (comme Python). */
export async function keyId(publicKey: Uint8Array): Promise<string> {
  return (await sha256Hex(publicKey)).slice(0, KEY_ID_HEX_CHARS);
}

const utf8 = (bytes: Uint8Array, what: string): string => {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return reject(what === "signature" ? "malformed-signature" : "malformed-manifest", `${what} : UTF-8 invalide`);
  }
};

/** Base64 décodé **et** canonique : réencodé, il doit redonner exactement le texte reçu. */
function canonicalBase64(text: string): Uint8Array | null {
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(text) || text.length % 4 !== 0) return null;
  let binary: string;
  try {
    binary = atob(text);
  } catch {
    return null;
  }
  const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
  return btoa(binary) === text ? bytes : null;
}

/** JSON canonique de Python (`sort_keys`, compact) pour le document de signature (ASCII plat). */
const canonicalFlat = (object: Record<string, unknown>): string =>
  `{${Object.keys(object)
    .sort()
    .map((k) => `${JSON.stringify(k)}:${JSON.stringify(object[k])}`)
    .join(",")}}`;

/**
 * Ordre total des publications : `[année, mois, jour, rang]`, ou `null` si la chaîne n'est
 * pas une publication datée valide.
 */
export function parseRelease(release: unknown): [number, number, number, number] | null {
  if (typeof release !== "string") return null;
  const match = RELEASE.exec(release);
  if (!match) return null;
  const [year, month, day, rank] = [match[1], match[2], match[3], match[4] ?? "0"].map(Number) as [
    number,
    number,
    number,
    number,
  ];
  if (month < 1 || month > 12 || day < 1 || day > 31) return null;
  return [year, month, day, rank];
}

/** `a` plus récente que `b` (strictement). Une publication illisible n'est jamais plus récente. */
export function isNewerRelease(a: string, b: string | null): boolean {
  const left = parseRelease(a);
  if (left === null) return false;
  const right = b === null || b === "" ? null : parseRelease(b);
  if (right === null) return true;
  for (let i = 0; i < 4; i++) if (left[i] !== right[i]) return left[i]! > right[i]!;
  return false;
}

async function verifySignature(manifest: Uint8Array, signatureBytes: Uint8Array, anchor: TrustAnchor): Promise<void> {
  const text = utf8(signatureBytes, "signature");
  let document: unknown;
  try {
    document = JSON.parse(text);
  } catch {
    return reject("malformed-signature", "signature : JSON invalide");
  }
  if (!isRecord(document) || Object.keys(document).sort().join() !== SIGNATURE_FIELDS.join()) {
    return reject("malformed-signature", "signature : champs inattendus");
  }
  if (document["algorithm"] !== SIGNATURE_ALGORITHM || document["format_version"] !== MANIFEST_FORMAT_VERSION) {
    return reject("malformed-signature", "signature : algorithme ou format inconnu");
  }
  if (typeof document["key_id"] !== "string" || typeof document["signature"] !== "string") {
    return reject("malformed-signature", "signature : types inattendus");
  }
  // Octets canoniques exigés : espaces, ordre des clés ou échappements différents refusés.
  if (canonicalFlat(document) !== text) return reject("malformed-signature", "signature : JSON non canonique");
  if (anchor.publicKey.length !== 32) return reject("unknown-key", "clé publique embarquée invalide");
  if (document["key_id"] !== (await keyId(anchor.publicKey))) {
    return reject("unknown-key", "manifeste signé par une autre clé que celle de l'extension");
  }
  const signature = canonicalBase64(document["signature"]);
  if (signature === null || signature.length !== 64) return reject("malformed-signature", "signature mal encodée");

  let key: CryptoKey;
  try {
    key = await crypto.subtle.importKey("raw", buffer(anchor.publicKey), { name: "Ed25519" }, false, ["verify"]);
  } catch {
    return reject("unknown-key", "Ed25519 indisponible ou clé embarquée invalide");
  }
  const valid = await crypto.subtle.verify({ name: "Ed25519" }, key, buffer(signature), buffer(manifest));
  if (!valid) reject("bad-signature", "signature du manifeste INVALIDE");
}

interface ModelArtifact {
  name: string;
  sha256: string;
  size: number;
}

/** Interprétation du manifeste, après la signature seulement. */
function parseManifest(manifestBytes: Uint8Array): { release: string; modelVersion: string; artifact: ModelArtifact } {
  let manifest: unknown;
  try {
    manifest = JSON.parse(utf8(manifestBytes, "manifeste"));
  } catch (error) {
    if (error instanceof ModelReleaseError) throw error;
    return reject("malformed-manifest", "manifeste : JSON invalide");
  }
  if (!isRecord(manifest)) return reject("malformed-manifest", "manifeste : objet attendu");
  if (manifest["format"] !== MANIFEST_FORMAT || manifest["format_version"] !== MANIFEST_FORMAT_VERSION) {
    return reject("malformed-manifest", "manifeste : format inconnu");
  }
  const release = manifest["release"];
  if (typeof release !== "string" || parseRelease(release) === null) {
    return reject("malformed-manifest", "manifeste : publication datée attendue (AAAA.MM.JJ[.N])");
  }

  const models = manifest["models"];
  const url = isRecord(models) ? models["url"] : undefined;
  if (!isRecord(url) || typeof url["version"] !== "string" || !/^url_v\d{1,4}$/.test(url["version"])) {
    return reject("malformed-manifest", "manifeste : modèle URL absent ou mal nommé");
  }
  const extractor = url["feature_extractor"];
  if (
    !isRecord(extractor) ||
    extractor["version"] !== FEATURE_EXTRACTOR_VERSION ||
    extractor["reference_data_sha256"] !== REFERENCE_DATA_SHA256
  ) {
    // Un modèle d'un autre extracteur donnerait des scores faux sans aucune erreur.
    return reject("incompatible-extractor", "modèle produit pour un autre extracteur de features");
  }
  if (manifest["normalization_version"] !== undefined && manifest["normalization_version"] !== NORMALIZATION_VERSION) {
    return reject("incompatible-extractor", "modèle produit pour une autre normalisation");
  }

  const artifacts = manifest["artifacts"];
  if (!Array.isArray(artifacts)) return reject("malformed-manifest", "manifeste : liste d'artefacts attendue");
  const exports = artifacts.filter((a) => isRecord(a) && a["role"] === MODEL_ROLE);
  if (exports.length !== 1) return reject("missing-artifact", `manifeste : un seul artefact « ${MODEL_ROLE} » attendu`);
  const entry = exports[0] as Record<string, unknown>;
  const { name, sha256, size } = entry;
  if (typeof name !== "string" || !ARTIFACT_NAME.test(name) || name.startsWith(".")) {
    return reject("malformed-manifest", "artefact : nom de fichier plat attendu");
  }
  if (name !== `${url["version"]}.json`) return reject("malformed-manifest", "artefact : nom différent du modèle URL");
  if (typeof sha256 !== "string" || !/^[0-9a-f]{64}$/.test(sha256)) {
    return reject("malformed-manifest", "artefact : empreinte SHA-256 attendue");
  }
  if (typeof size !== "number" || !Number.isInteger(size) || size <= 0 || size > MAX_MODEL_BYTES) {
    return reject("malformed-manifest", "artefact : taille invalide");
  }
  return { release, modelVersion: url["version"], artifact: { name, sha256, size } };
}

/**
 * Vérifie la signature, puis le manifeste, et rend l'artefact du modèle attendu
 * (nom, taille, empreinte), **avant** tout téléchargement du modèle lui-même.
 */
export async function verifySignedManifest(
  files: Pick<ModelReleaseFiles, "manifest" | "signature">,
  anchor: TrustAnchor,
  { notOlderThan }: { notOlderThan: string | null },
): Promise<{ release: string; modelVersion: string; artifact: ModelArtifact }> {
  if (files.manifest.length > MAX_MANIFEST_BYTES) reject("too-large", "manifeste trop volumineux");
  if (files.signature.length > MAX_SIGNATURE_BYTES) reject("too-large", "signature trop volumineuse");
  await verifySignature(files.manifest, files.signature, anchor);
  const parsed = parseManifest(files.manifest);
  if (!isNewerRelease(parsed.release, notOlderThan)) {
    reject("rollback", `publication ${parsed.release} pas plus récente que ${notOlderThan ?? "?"}`);
  }
  return parsed;
}

/**
 * Vérification complète d'une publication : signature, manifeste, retour arrière,
 * puis taille et empreinte du modèle. Lève {@link ModelReleaseError} au moindre écart.
 *
 * `notOlderThan` : publication du modèle embarqué (ou dernière acceptée) ; la publication
 * reçue doit être **strictement** plus récente.
 */
export async function verifyModelRelease(
  files: ModelReleaseFiles,
  anchor: TrustAnchor,
  options: { notOlderThan: string | null },
): Promise<VerifiedModelRelease> {
  const { release, modelVersion, artifact } = await verifySignedManifest(files, anchor, options);
  if (files.model.length !== artifact.size) reject("artifact-mismatch", "taille du modèle différente du manifeste");
  const digest = await sha256Hex(files.model);
  if (digest !== artifact.sha256) reject("artifact-mismatch", "empreinte du modèle différente du manifeste");
  return { release, modelVersion, artifactName: artifact.name, sha256: digest, model: files.model };
}

/** Clé publique brute depuis le base64 injecté au build (`""` : aucune clé, mises à jour impossibles). */
export function trustAnchorFromBase64(raw: string): TrustAnchor | null {
  const bytes = raw ? canonicalBase64(raw) : null;
  return bytes !== null && bytes.length === 32 ? { publicKey: bytes } : null;
}
