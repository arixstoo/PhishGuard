/**
 * Bornes partagées par le script Gmail, le protocole de messages et l'analyse. Module sans
 * dépendance : importer `core/inspect` pour trois constantes embarquerait tout
 * l'extracteur (et ses 216 Kio de données) dans le script de contenu.
 */

/** Liens distincts analysés par message ; au-delà, la bannière le signale. */
export const MAX_MAIL_LINKS = 500;
/** Texte affiché d'un lien, au-delà tronqué. */
export const MAX_LINK_TEXT_CHARS = 2048;
/** Cible d'un lien : `MAX_ANALYZED_URL_CHARS + 1`, jugée « trop longue », jamais ignorée. */
export const MAX_LINK_HREF_CHARS = 65_537;
