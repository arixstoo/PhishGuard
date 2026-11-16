/**
 * Dernier lien analysé par le menu contextuel, transmis à la fenêtre contextuelle.
 *
 * `chrome.storage.session` : en mémoire seulement, effacé à la fermeture du navigateur.
 * Seuls l'hôte et le domaine enregistré sont gardés, jamais l'URL entière, et l'entrée
 * est effacée dès sa lecture. Module séparé de `storage.ts` : la fenêtre contextuelle
 * n'embarque pas l'extracteur.
 */

const LINK_KEY = "lastLinkAnalysis";

/** Durée pendant laquelle la fenêtre contextuelle affiche le résultat d'un lien. */
export const LINK_RESULT_TTL_MS = 2 * 60 * 1000;

export interface LinkAnalysis {
  at: number;
  /** Hôte affichable, jamais l'URL entière. */
  host: string;
  /** Domaine enregistré (forme ASCII) : liste blanche et signalement. */
  registeredDomain: string;
  verdict: string;
  score: number;
  reasons: string[];
  hardRule: string | null;
}

export async function setLastLink(result: LinkAnalysis): Promise<void> {
  await chrome.storage.session.set({ [LINK_KEY]: result });
}

/** Lit **et efface** le dernier lien analysé, s'il est récent. */
export async function takeLastLink(now = Date.now()): Promise<LinkAnalysis | null> {
  const stored = await chrome.storage.session.get(LINK_KEY);
  await chrome.storage.session.remove(LINK_KEY);
  const value = stored[LINK_KEY] as LinkAnalysis | undefined;
  return value && now - value.at <= LINK_RESULT_TTL_MS ? value : null;
}
