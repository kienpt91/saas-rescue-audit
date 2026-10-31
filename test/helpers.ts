import { audit } from "../src/audit.js";
import { DEFAULT_CONFIG } from "../src/config.js";
import { projectFromFiles } from "../src/project.js";
import type { AuditResult, Config, Finding } from "../src/types.js";

export interface RunOptions {
  config?: Partial<Config>;
  tracked?: string[];
}

/** Audits an in-memory project. */
export function run(files: Record<string, string>, options: RunOptions = {}): AuditResult {
  return audit(projectFromFiles(files, options.tracked ? { tracked: options.tracked } : {}), { ...DEFAULT_CONFIG, ...options.config });
}

/** Findings of one rule. */
export function of(result: AuditResult, rule: string): Finding[] {
  return result.findings.filter((f) => f.rule === rule);
}

/** `rule@file:line` for every finding, sorted. */
export function keys(result: AuditResult): string[] {
  return result.findings.map((f) => `${f.rule}@${f.file}:${f.line}`).sort();
}

export function ruleSet(result: AuditResult): string[] {
  return [...new Set(result.findings.map((f) => f.rule))].sort();
}

/** Deterministic pseudo-random alphanumeric string, so fixtures never contain a literal key. */
export function randomToken(length: number, seed = 1): string {
  const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let state = seed * 2654435761;
  let out = "";
  for (let i = 0; i < length; i++) {
    state = (state * 1664525 + 1013904223) % 4294967296;
    out += alphabet[Math.floor((state / 4294967296) * alphabet.length)];
  }
  return out;
}

/** Builds a credential-shaped value from parts at runtime. */
export function fakeKey(...parts: string[]): string {
  return parts.join("");
}

export function base64url(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

export const ROUTE = "app/api/items/route.ts";
