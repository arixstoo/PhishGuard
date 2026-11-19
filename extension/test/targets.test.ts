/**
 * Manifeste Firefox (étape 6.10) : dérivé de celui de Chrome par `targets.mjs`, il ne doit
 * changer que ce que Firefox exige. Une autorisation, la CSP ou le script de contenu qui
 * divergeraient rendraient fausses la politique de confidentialité et la fiche d'AMO.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { archiveName, browserFromArgs, browserManifest, FIREFOX_MIN_VERSION, GECKO_ID } from "../targets.mjs";

const ROOT = new URL("..", import.meta.url).pathname.replace(/^\/([A-Z]:)/, "$1");
const chrome = JSON.parse(readFileSync(join(ROOT, "static/manifest.json"), "utf-8")) as Record<string, unknown>;
const firefox = browserManifest(chrome, "firefox");

describe("manifeste Firefox", () => {
  it("garde à l'identique tout ce qui touche à la vie privée et à la sécurité", () => {
    for (const key of [
      "manifest_version",
      "name",
      "description",
      "default_locale",
      "permissions",
      "optional_permissions",
      "optional_host_permissions",
      "content_scripts",
      "content_security_policy",
      "action",
      "options_ui",
      "icons",
    ]) {
      expect(firefox[key], key).toEqual(chrome[key]);
    }
    for (const key of ["host_permissions", "web_accessible_resources", "externally_connectable"]) {
      expect(firefox[key], key).toBeUndefined();
    }
  });

  it("ne diffère que par l'arrière-plan, l'identité et la version minimale", () => {
    const changed = new Set([...Object.keys(chrome), ...Object.keys(firefox)].filter((k) => JSON.stringify(chrome[k]) !== JSON.stringify(firefox[k])));
    expect([...changed].sort()).toEqual(["background", "browser_specific_settings", "minimum_chrome_version"]);
  });

  it("charge le même module en page d'événements", () => {
    expect(firefox["background"]).toEqual({ scripts: ["background.js"], type: "module" });
  });

  it("déclare un identifiant stable et aucune collecte de données", () => {
    const settings = firefox["browser_specific_settings"] as { gecko: Record<string, unknown>; gecko_android: Record<string, unknown> };
    expect(settings.gecko["id"]).toBe(GECKO_ID);
    expect(GECKO_ID).toBe("phishguard@arixstoo.github.io"); // ne jamais le changer
    expect(settings.gecko["strict_min_version"]).toBe(FIREFOX_MIN_VERSION);
    expect(Number.parseFloat(FIREFOX_MIN_VERSION)).toBeGreaterThanOrEqual(140);
    expect(settings.gecko["data_collection_permissions"]).toEqual({ required: ["none"] });
    expect(Number.parseFloat(settings.gecko_android["strict_min_version"] as string)).toBeGreaterThanOrEqual(142);
  });

  it("ne modifie pas le manifeste de Chrome", () => {
    const before = JSON.stringify(chrome);
    browserManifest(chrome, "firefox");
    expect(JSON.stringify(chrome)).toBe(before);
    expect(browserManifest(chrome, "chrome")).toEqual(chrome);
  });

  it("refuse un arrière-plan inattendu plutôt que de le deviner", () => {
    expect(() => browserManifest({ ...chrome, background: { page: "bg.html" } }, "firefox")).toThrow(/service_worker/);
  });
});

describe("arguments et noms", () => {
  it("lit --browser sous ses deux formes, Chrome par défaut", () => {
    expect(browserFromArgs([])).toBe("chrome");
    expect(browserFromArgs(["--browser=firefox"])).toBe("firefox");
    expect(browserFromArgs(["--test", "--browser", "firefox"])).toBe("firefox");
    expect(() => browserFromArgs(["--browser=safari"])).toThrow(/inconnu/);
  });

  it("garde le nom d'archive de Chrome de l'étape 5.14", () => {
    expect(archiveName("chrome", "1.0.0")).toBe("phishguard-extension-1.0.0.zip");
    expect(archiveName("firefox", "1.0.0")).toBe("phishguard-firefox-1.0.0.zip");
  });
});
