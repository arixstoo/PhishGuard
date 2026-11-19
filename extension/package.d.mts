import type { Buffer } from "node:buffer";

/** Archive ZIP déterministe de `entries` ([nom, octets]). */
export function zip(entries: [string, Buffer][]): Buffer;
