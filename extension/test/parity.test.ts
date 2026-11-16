/**
 * Parité avec Python, composant par composant (`test/fixtures/python-parity.json`).
 *
 * Chaque cas a été calculé par le code Python lui-même (`make extension-data`). Un écart
 * ici signifie que l'extension et l'API ne voient pas la même URL : le corriger dans le
 * port TypeScript, ou, s'il révèle un cas non couvert, l'ajouter au générateur.
 */

import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { skeleton, labelToAscii, labelToUnicode } from "../src/core/idn";
import {
  FEATURE_EXTRACTOR_VERSION,
  isIpHost,
  normalizeUrl,
  parseUrl,
  REFERENCE_DATA_SHA256,
  topLevelDomain,
  UrlFeatureExtractor,
} from "../src/core/features";
import { hostScriptAlert } from "../src/core/normalize";
import { extractDomain } from "../src/core/psl";
import { hostname, port, unquote, urlsplit } from "../src/core/pyurl";
import { UNIDATA_VERSION } from "../src/core/text";
import { expectFeatures } from "./helpers";

interface UrlCase {
  input: string;
  urlsplit: Record<string, unknown>;
  normalize_url: [string, string] | null;
  parsed: Record<string, unknown> | null;
  features?: Record<string, number>;
  host_alert?: string | null;
  top_level_domain?: string;
}

const parity = JSON.parse(
  readFileSync(new URL("./fixtures/python-parity.json", import.meta.url), "utf-8"),
) as {
  unidata_version: string;
  feature_extractor: { version: string; reference_data_sha256: string };
  feature_names: string[];
  unquote: { input: string; output: string }[];
  labels: { input: string; to_ascii: string; to_unicode: string }[];
  tldextract: { input: string; output: Record<string, unknown> }[];
  is_ip_host: { input: string; output: boolean }[];
  skeleton: { input: string; output: string }[];
  urls: UrlCase[];
  fuzz: UrlCase[];
};

const extractor = new UrlFeatureExtractor();

function splitResult(url: string): Record<string, unknown> {
  try {
    const parts = urlsplit(url);
    const p = port(parts);
    return { ...parts, hostname: hostname(parts), port: p };
  } catch {
    return { error: true };
  }
}

function parsedResult(url: string): Record<string, unknown> | null {
  try {
    const p = parseUrl(url);
    return {
      url: p.url,
      scheme: p.scheme,
      host: p.host,
      host_unicode: p.hostUnicode,
      is_ip: p.isIp,
      registered_domain: p.registeredDomain,
      domain_label: p.domainLabel,
      subdomains: p.subdomains,
      has_userinfo: p.hasUserinfo,
      port: p.port,
      path: p.path,
      query: p.query,
    };
  } catch {
    return null;
  }
}

function checkUrlCase(c: UrlCase): void {
  const label = JSON.stringify(c.input);
  expect(splitResult(c.input), `urlsplit(${label})`).toEqual(c.urlsplit);
  expect(normalizeUrl(c.input), `normalize_url(${label})`).toEqual(c.normalize_url);
  const parsed = parsedResult(c.input);
  expect(parsed, `parse_url(${label})`).toEqual(c.parsed);
  if (c.parsed === null || parsed === null) return;
  expectFeatures(extractor.extract(c.input), c.features!, `features(${label})`);
  expect(hostScriptAlert(parsed["host"] as string), `host_script_alert(${label})`).toBe(c.host_alert);
  expect(topLevelDomain(parsed["host"] as string), `top_level_domain(${label})`).toBe(
    c.top_level_domain,
  );
}

describe("données de référence", () => {
  it("viennent du même extracteur que les cas de parité", () => {
    expect(FEATURE_EXTRACTOR_VERSION).toBe(parity.feature_extractor.version);
    expect(REFERENCE_DATA_SHA256).toBe(parity.feature_extractor.reference_data_sha256);
    expect(extractor.featureNames).toEqual(parity.feature_names);
  });

  it("ont les tables Unicode de la même version que les cas", () => {
    expect(UNIDATA_VERSION).toBe(parity.unidata_version);
  });
});

describe("composants", () => {
  it.each(parity.unquote)("unquote($input)", ({ input, output }) => {
    expect(unquote(input)).toBe(output);
  });

  it.each(parity.labels)("label $input", ({ input, to_ascii, to_unicode }) => {
    expect(labelToAscii(input)).toBe(to_ascii);
    expect(labelToUnicode(input)).toBe(to_unicode);
  });

  it.each(parity.tldextract)("tldextract($input)", ({ input, output }) => {
    const r = extractDomain(input);
    expect({
      subdomain: r.subdomain,
      domain: r.domain,
      suffix: r.suffix,
      is_private: r.isPrivate,
      top_domain_under_public_suffix: r.topDomainUnderPublicSuffix,
    }).toEqual(output);
  });

  it.each(parity.is_ip_host)("is_ip_host($input)", ({ input, output }) => {
    expect(isIpHost(input)).toBe(output);
  });

  it.each(parity.skeleton)("skeleton($input)", ({ input, output }) => {
    expect(skeleton(input)).toBe(output);
  });
});

describe("URLs choisies", () => {
  it.each(parity.urls.map((c) => [JSON.stringify(c.input), c] as const))("%s", (_, c) => {
    checkUrlCase(c);
  });
});

describe("fuzzing différentiel", () => {
  it(`${parity.fuzz.length} URLs déterministes donnent les mêmes résultats`, () => {
    for (const c of parity.fuzz) checkUrlCase(c);
  });
});
