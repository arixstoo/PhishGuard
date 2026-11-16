/**
 * Verdict d'un message Gmail (étape 5.6) et requêtes du script de contenu.
 *
 * Le modèle est un des petits modèles synthétiques des cas de parité : il suffit à
 * exercer la décision, la liste blanche et les règles propres aux emails.
 */

import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { UrlAnalyzer } from "../src/core/analyze";
import { inspectLink, inspectMail, inspectSender } from "../src/core/inspect";
import { loadUrlModel } from "../src/core/model";
import { MAX_LINK_HREF_CHARS, MAX_MAIL_LINKS } from "../src/limits";
import { parseMailRequest, parseRequest } from "../src/messages";

const parity = JSON.parse(readFileSync(new URL("./fixtures/python-parity.json", import.meta.url), "utf-8")) as {
  synthetic_models: { model: unknown }[];
};
const analyzer = new UrlAnalyzer(loadUrlModel(parity.synthetic_models[0]!.model));
const none = () => false;
const link = (href: string, text = "") => inspectLink(analyzer, { href, text }, none);

describe("un lien", () => {
  it("« le texte affiche un domaine, la cible en est un autre » : au moins suspect", () => {
    const v = link("https://evil-login.example.com/", "www.paypal.com");
    expect(v.reasons[0]).toBe("text_domain_mismatch");
    expect(["suspicious", "phishing"]).toContain(v.verdict);
    expect(v.score).toBeGreaterThanOrEqual(30);
  });

  it("même domaine enregistré affiché et visé : pas de règle", () => {
    expect(link("https://www.paypal.com/signin", "paypal.com").reasons).not.toContain("text_domain_mismatch");
  });

  it("déballe la redirection de Google avant tout", () => {
    const v = link("https://www.google.com/url?q=https://evil-login.example.com/&sa=D", "www.paypal.com");
    expect(v.host).toBe("evil-login.example.com");
    expect(v.reasons).toContain("text_domain_mismatch");
  });

  it("déballe une passerelle de sécurité (Safe Links) comme l'API", () => {
    const v = link(
      "https://nam12.safelinks.protection.outlook.com/?url=https%3A%2F%2Fwww.paypal.com%2F&data=x",
      "www.paypal.com",
    );
    expect(v.host).toBe("www.paypal.com");
    expect(v.reasons).not.toContain("text_domain_mismatch");
  });

  it.each(["javascript:alert(1)", "data:text/html,<script>", "vbscript:x", "file:///C:/x.exe"])(
    "%s : suspect (le lien exécute du code)",
    (href) => {
      expect(link(href)).toMatchObject({ verdict: "suspicious", reasons: ["non_web_link"] });
    },
  );

  it.each(["mailto:a@b.fr", "tel:+33100000000", "#ancre", "/aide", "page.html"])("%s : rien à juger", (href) => {
    expect(link(href).verdict).toBeNull();
  });

  it("hôte imitateur : phishing, même sur liste blanche", () => {
    const v = inspectLink(analyzer, { href: "http://xn--pple-43d.com/", text: "" }, () => true);
    expect(v.verdict).toBe("phishing");
    expect(v.reasons).toContain("lookalike_host");
  });

  it("cible de confiance : sûre, même si le texte diffère", () => {
    const v = inspectLink(analyzer, { href: "https://shop.example.com/", text: "www.boutique.fr" }, (d) => d === "example.com");
    expect(v.verdict).toBe("safe");
  });

  it("une cible trop longue est signalée, jamais ignorée", () => {
    expect(link(`https://x.fr/?${"a".repeat(MAX_LINK_HREF_CHARS)}`).verdict).toBe("suspicious");
  });
});

describe("l'expéditeur", () => {
  it("nom affiché qui imite une autre adresse : display_name_spoof (comme l'API)", () => {
    expect(inspectSender({ name: "service@paypal.com", email: "x@evil-mail.co.uk" })).toEqual(["display_name_spoof"]);
    expect(inspectSender({ name: "PayPal", email: "service@paypal.com" })).toEqual([]);
    expect(inspectSender({ name: "service@paypal.com", email: "service@intl.paypal.com" })).toEqual([]);
  });

  it("nom affiché qui ne cite qu'un domaine : raison informative, jamais déclencheur", () => {
    // Cas réel : « impots.gouv.fr » <ne-pas-repondre@dgfip.finances.gouv.fr>. L'API ne
    // donne que 25 points à cette règle, sous le seuil « suspect » : l'extension non plus.
    const sender = { name: "impots.gouv.fr", email: "ne-pas-repondre@dgfip.finances.gouv.fr" };
    expect(inspectSender(sender)).toEqual(["display_name_domain"]);
    expect(inspectMail(analyzer, [], sender, none).verdict).toBe("safe");
  });

  it("domaine qui imite des lettres latines : sender_lookalike", () => {
    expect(inspectSender({ name: "Apple", email: "id@аpple.com" })).toContain("sender_lookalike");
  });

  it("expéditeur absent ou illisible : rien", () => {
    expect(inspectSender(null)).toEqual([]);
    expect(inspectSender({ name: "", email: "" })).toEqual([]);
  });
});

describe("le message", () => {
  it("prend le pire verdict, compte les liens signalés", () => {
    const result = inspectMail(
      analyzer,
      [
        { href: "https://www.paypal.com/", text: "paypal.com" },
        { href: "https://evil-login.example.com/", text: "www.paypal.com" },
        { href: "mailto:x@y.fr", text: "écrire" },
      ],
      { name: "PayPal", email: "service@paypal.com" },
      none,
    );
    expect(result.links).toHaveLength(3);
    expect(result.flagged).toBeGreaterThanOrEqual(1);
    expect(result.verdict).not.toBe("safe");
  });

  it("expéditeur imitateur : phishing, même sans lien", () => {
    expect(inspectMail(analyzer, [], { name: "Apple", email: "id@аpple.com" }, none).verdict).toBe("phishing");
  });

  it("message sans lien ni expéditeur douteux : sûr", () => {
    expect(inspectMail(analyzer, [], { name: "Jean", email: "jean@exemple.fr" }, none)).toMatchObject({
      verdict: "safe",
      flagged: 0,
    });
  });
});

describe("requête du script Gmail", () => {
  const ok = { type: "mail-inspect", links: [{ href: "https://x.fr", text: "x" }], sender: { name: "a", email: "a@b.fr" } };

  it("accepte la forme attendue, ignore les champs en trop", () => {
    expect(parseMailRequest({ ...ok, extra: 1 })).toEqual({
      type: "mail-inspect",
      links: [{ href: "https://x.fr", text: "x" }],
      sender: { name: "a", email: "a@b.fr" },
    });
    expect(parseMailRequest({ ...ok, sender: null })?.sender).toBeNull();
  });

  it.each([
    ["trop de liens", { ...ok, links: Array(MAX_MAIL_LINKS + 1).fill(ok.links[0]) }],
    ["cible trop longue", { ...ok, links: [{ href: "a".repeat(MAX_LINK_HREF_CHARS + 1), text: "" }] }],
    ["texte trop long", { ...ok, links: [{ href: "https://x.fr", text: "a".repeat(5000) }] }],
    ["lien mal formé", { ...ok, links: [{ href: 1, text: "" }] }],
    ["liens absents", { type: "mail-inspect" }],
    ["expéditeur mal formé", { ...ok, sender: { name: "a" } }],
    ["autre type", { ...ok, type: "analyze-tab" }],
  ])("refuse : %s", (_, message) => {
    expect(parseMailRequest(message)).toBeNull();
  });

  it("le script Gmail ne peut pas emprunter le protocole des pages, ni l'inverse", () => {
    // Ce sont deux analyseurs distincts : une requête de page n'est pas une requête Gmail.
    expect(parseMailRequest({ type: "allowlist-add-domain", domain: "evil.example" })).toBeNull();
    expect(parseRequest(ok)).toBeNull();
  });
});

describe("requêtes des pages", () => {
  it.each([
    [{ type: "analyze-tab-online", tabId: 2 }, { type: "analyze-tab-online", tabId: 2 }],
    [{ type: "allowlist-add-domain", domain: "exemple.fr" }, { type: "allowlist-add-domain", domain: "exemple.fr" }],
    [{ type: "allowlist-get", x: 1 }, { type: "allowlist-get" }],
    [
      { type: "feedback", domain: "x.fr", verdict: "phishing", judgement: "false_positive" },
      { type: "feedback", domain: "x.fr", verdict: "phishing", judgement: "false_positive" },
    ],
  ])("accepte %j", (message, expected) => {
    expect(parseRequest(message)).toEqual(expected);
  });

  it.each([
    { type: "feedback", domain: "x.fr", verdict: "evil", judgement: "false_positive" },
    { type: "feedback", domain: "x.fr", verdict: "safe", judgement: "maybe" },
    { type: "feedback", domain: "", verdict: "safe", judgement: "false_negative" },
    { type: "allowlist-add-domain", domain: "" },
    { type: "allowlist-add-domain", domain: ["x.fr"] },
  ])("refuse %j", (message) => {
    expect(parseRequest(message)).toBeNull();
  });
});
