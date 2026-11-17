/**
 * Page d'options (étape 5.7) : par défaut rien ne part, chaque réglage dit quelles données
 * partent où, serveur en clair refusé, liste blanche sur le domaine enregistré.
 */

import { expect, test } from "./fixtures";

test("par défaut : Gmail analysé sur l'appareil, rien en ligne", async ({ openExtensionPage }) => {
  const options = await openExtensionPage("options.html");
  await expect(options.locator("#gmail")).toBeChecked();
  await expect(options.locator("#auto")).not.toBeChecked();
  await expect(options.locator("#enrichment")).not.toBeChecked();
  await expect(options.locator("#enrichment")).toBeDisabled(); // pas de serveur : impossible
  await expect(options.locator("#feedback")).not.toBeChecked();
  await expect(options.locator("#feedback")).toBeDisabled();
});

test("chaque réglage est relié à sa phrase sur les données", async ({ openExtensionPage }) => {
  const options = await openExtensionPage("options.html");
  await expect(options.locator("body")).toContainText("lire votre historique de navigation");
  for (const id of ["language", "gmail", "auto", "enrichment", "feedback"]) {
    const described = await options.locator(`#${id}`).getAttribute("aria-describedby");
    expect(described, id).toBeTruthy();
    for (const ref of described!.split(" ")) {
      await expect(options.locator(`#${ref}`), `${id} → ${ref}`).toHaveCount(1);
    }
  }
});

test("serveur en http refusé : erreur annoncée, focus sur le champ", async ({ openExtensionPage }) => {
  const options = await openExtensionPage("options.html");
  await options.locator("#server").fill("http://evil.example");
  await options.locator("#server-form button").click();
  await expect(options.locator("#server")).toHaveAttribute("aria-invalid", "true");
  await expect(options.locator("#server-error")).toBeVisible();
  await expect(options.locator("#server")).toBeFocused();
});

test("serveur local enregistré : l'analyse en ligne reste éteinte", async ({ openExtensionPage, sw }) => {
  const options = await openExtensionPage("options.html");
  await options.locator("#server").fill("http://127.0.0.1:8000");
  await options.locator("#server-form button").click();
  await expect(options.locator("#enrichment")).toBeEnabled();
  await expect(options.locator("#enrichment")).not.toBeChecked();
  // Enregistrer un serveur n'accorde aucune permission d'hôte.
  const origins = await sw.evaluate(async () => (await chrome.permissions.getAll()).origins);
  expect(origins).toEqual(["https://mail.google.com/*"]);
});

test("liste blanche : le domaine enregistré, jamais l'URL", async ({ openExtensionPage, sw }) => {
  const options = await openExtensionPage("options.html");
  await options.locator("#allowlist-input").fill("https://www.Exemple.fr/page?jeton=secret");
  await options.locator("#allowlist-form button").click();
  await expect(options.locator("#allowlist")).toContainText("exemple.fr");
  const stored = await sw.evaluate(() => chrome.storage.local.get("allowlist"));
  expect(stored).toEqual({ allowlist: ["exemple.fr"] });
});
