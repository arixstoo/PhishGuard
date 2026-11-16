/**
 * Liens et expéditeur d'un email : parité avec `phishguard.email` (étape 5.6).
 *
 * Les cas `mail` de `python-parity.json` sont calculés par `make_link`,
 * `unwrap_rewritten`, `registered_domain`, `display_name_domain` et `make_address`
 * eux-mêmes. Un écart ici : l'extension et l'API ne jugeraient pas le même lien de la
 * même façon.
 */

import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  collapseSpaces,
  displayNameDomain,
  makeAddress,
  makeLink,
  parseQs,
  registeredDomainOf,
  unwrapGoogleRedirect,
  unwrapRewritten,
} from "../src/core/mail";

interface LinkCase {
  href: string;
  text: string;
  scheme: string;
  href_domain: string | null;
  text_domain: string | null;
  mismatch: boolean;
  rewritten_by: string | null;
  target: string;
}

const { mail } = JSON.parse(readFileSync(new URL("./fixtures/python-parity.json", import.meta.url), "utf-8")) as {
  mail: {
    links: LinkCase[];
    unwrap: { input: string; output: [string, string] | null }[];
    registered_domain: { input: string; output: string | null }[];
    display_name_domain: { input: string; output: string | null }[];
    senders: {
      name: string;
      address: string;
      domain: string | null;
      registered_domain: string | null;
      display_name_domain: string | null;
    }[];
  };
};

describe("parité : make_link", () => {
  it(`${mail.links.length} liens, dont ${mail.links.filter((c) => c.mismatch).length} trompeurs`, () => {
    for (const c of mail.links) {
      const link = makeLink(c.href, c.text);
      expect(
        {
          scheme: link.scheme,
          href_domain: link.hrefDomain,
          text_domain: link.textDomain,
          mismatch: link.mismatch,
          rewritten_by: link.rewrittenBy,
          target: link.target,
        },
        JSON.stringify([c.href, c.text]),
      ).toEqual({
        scheme: c.scheme,
        href_domain: c.href_domain,
        text_domain: c.text_domain,
        mismatch: c.mismatch,
        rewritten_by: c.rewritten_by,
        target: c.target,
      });
    }
  });

  it.each(mail.unwrap)("unwrap_rewritten(%j)", ({ input, output }) => {
    expect(unwrapRewritten(input)).toEqual(output);
  });

  it.each(mail.registered_domain)("registered_domain(%j)", ({ input, output }) => {
    expect(registeredDomainOf(input)).toBe(output);
  });
});

describe("parité : expéditeur", () => {
  it.each(mail.display_name_domain)("display_name_domain(%j)", ({ input, output }) => {
    expect(displayNameDomain(input)).toBe(output);
  });

  it.each(mail.senders)("make_address(%j)", (c) => {
    const address = makeAddress(c.name, c.address);
    expect([address?.domain ?? null, address?.registeredDomain ?? null]).toEqual([c.domain, c.registered_domain]);
    expect(displayNameDomain(c.name)).toBe(c.display_name_domain);
  });
});

describe("chaînes à la Python", () => {
  it("réduit les espaces de Python, pas ceux de JavaScript", () => {
    expect(collapseSpaces("  a   b\n\tc  ")).toBe("a b c");
    expect(collapseSpaces("a\u001cb")).toBe("a b"); // séparateur de fichier : espace pour Python
    expect(collapseSpaces("a﻿b")).toBe("a﻿b"); // BOM : pas un espace pour Python
  });

  it("lit une requête comme parse_qs", () => {
    const q = parseQs("a=1&a=2&b=%41+c&vide=&sans&=x&&c=%");
    expect(Object.fromEntries(q)).toEqual({ a: ["1", "2"], b: ["A c"], "": ["x"], c: ["%"] });
  });
});

describe("redirection de Google (Gmail)", () => {
  it.each([
    ["https://www.google.com/url?q=https://evil.example/login&sa=D", "https://evil.example/login", true],
    ["https://google.com/url?url=http%3A%2F%2Fevil.example%2F", "http://evil.example/", true],
    ["HTTPS://WWW.GOOGLE.COM/url?q=https://a.example/", "https://a.example/", true],
    // Imbriquées : Google Docs dans un email.
    [
      "https://www.google.com/url?q=https://www.google.com/url?q%3Dhttps://evil.example/%26sa%3DD&sa=D",
      "https://evil.example/",
      true,
    ],
    // Pas une redirection de Google : rendu tel quel.
    ["https://www.google.com/search?q=https://evil.example/", "https://www.google.com/search?q=https://evil.example/", false],
    ["https://www.google.evil/url?q=https://banque.fr/", "https://www.google.evil/url?q=https://banque.fr/", false],
    ["https://google.com.evil.example/url?q=https://banque.fr/", "https://google.com.evil.example/url?q=https://banque.fr/", false],
    ["https://www.google.com/url?q=javascript:alert(1)", "https://www.google.com/url?q=javascript:alert(1)", false],
    ["https://www.google.com/url?sa=D", "https://www.google.com/url?sa=D", false],
    ["mailto:x@google.com", "mailto:x@google.com", false],
  ])("%s", (href, target, unwrapped) => {
    expect(unwrapGoogleRedirect(href)).toEqual({ target, unwrapped });
  });

  it("borne les redirections imbriquées", () => {
    let href = "https://evil.example/";
    for (let i = 0; i < 20; i++) href = `https://www.google.com/url?q=${encodeURIComponent(href)}`;
    const { target } = unwrapGoogleRedirect(href);
    expect(target.startsWith("https://www.google.com/url?q=")).toBe(true);
  });
});
