export type Browser = "chrome" | "firefox";
export const BROWSERS: readonly Browser[];
export const GECKO_ID: string;
export const FIREFOX_MIN_VERSION: string;
export const FIREFOX_ANDROID_MIN_VERSION: string;
export const DIST_DIRS: Record<Browser, string>;
export function archiveName(browser: Browser, version: string): string;
export function browserFromArgs(argv: readonly string[]): Browser;
export function browserManifest(manifest: Record<string, unknown>, browser: Browser): Record<string, unknown>;
