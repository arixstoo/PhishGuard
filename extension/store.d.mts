import type { Buffer } from "node:buffer";

export const LIMITS: { name: number; summary: number; description: number; justification: number; singlePurpose: number };
export const IMAGE_SIZES: Record<string, [number, number]>;
export const DATA_CATEGORIES: string[];
export function manifestPermissions(manifest: Record<string, unknown>): string[];
export function quotedLabels(text: string): string[];
export function pngSize(bytes: Buffer): [number, number] | null;
export function imageKind(name: string): string | null;
export function validateListing(input: {
  listing: Record<string, any>;
  manifest: Record<string, any>;
  catalogs: Record<string, Record<string, { message: string }>>;
  descriptions: Record<string, string>;
}): string[];
export function validateAssets(assetsDir: string, listing: Record<string, any>): string[];
