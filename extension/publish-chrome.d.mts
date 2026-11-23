import type { Buffer } from "node:buffer";

export class PublishError extends Error {}
export interface CwsConfig {
  clientId: string;
  clientSecret: string;
  refreshToken: string;
  publisherId: string;
  extensionId: string;
}
type Fetch = (url: string, init?: Record<string, unknown>) => Promise<{ ok: boolean; status: number; statusText: string; text(): Promise<string> }>;
export function manifestFromZip(zip: Buffer): Record<string, any>;
export function readConfig(env: Record<string, string | undefined>): CwsConfig;
export function accessToken(config: CwsConfig, fetchImpl?: Fetch): Promise<string>;
export function upload(
  config: CwsConfig,
  token: string,
  zip: Buffer,
  expectedVersion: string,
  options?: { fetchImpl?: Fetch; sleep?: (ms: number) => Promise<void>; attempts?: number },
): Promise<{ version: string }>;
export function publish(config: CwsConfig, token: string, options?: { staged?: boolean; fetchImpl?: Fetch }): Promise<{ state: string; warnings: string[] }>;
