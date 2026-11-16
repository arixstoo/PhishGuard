/**
 * Sélecteurs de l'interface de Gmail (étape 5.6) : **le seul endroit à corriger** quand
 * Gmail change son HTML. Les classes de Gmail sont générées et non documentées ; celles-ci
 * sont stables depuis des années, mais rien ne le garantit.
 *
 * La maquette `test/fixtures/gmail-mock.html` reproduit exactement cette structure : la
 * modifier en même temps que ce fichier.
 */

export const GMAIL = {
  /** Zone de lecture : liste ou conversation ouverte. */
  main: 'div[role="main"]',
  /** Un message **déplié** d'une conversation (les messages repliés n'ont pas de corps). */
  message: "div.adn",
  /** Corps d'un message déplié : le seul contenu d'email que lit le script. */
  body: "div.a3s",
  /** Expéditeur d'un message : attributs `email` (adresse) et `name` (nom affiché). */
  sender: "span.gD[email]",
  /** Liens du corps. */
  link: "a[href]",
} as const;
