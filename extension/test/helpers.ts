import { expect } from "vitest";

/**
 * Mêmes noms, dans le même ordre, mêmes valeurs. Les comptes sont des entiers exacts ;
 * seule l'entropie passe par `log2`, dont la dernière décimale peut différer d'une
 * bibliothèque mathématique à l'autre : 1e-12 près, bien sous la tolérance publiée (1e-6).
 */
export function expectFeatures(
  actual: Record<string, number>,
  expected: Record<string, number>,
  label: string,
): void {
  expect(Object.keys(actual), label).toEqual(Object.keys(expected));
  for (const [name, value] of Object.entries(expected)) {
    const delta = Math.abs(actual[name]! - value);
    expect(delta, `${label}.${name} = ${actual[name]} ≠ ${value}`).toBeLessThanOrEqual(1e-12);
  }
}

/** Les features de `actual` restreintes aux colonnes de `expected`, dans leur ordre. */
export const pick = (actual: Record<string, number>, expected: Record<string, number>) =>
  Object.fromEntries(Object.keys(expected).map((name) => [name, actual[name]!]));
