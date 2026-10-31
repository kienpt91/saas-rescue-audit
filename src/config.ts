import { RULE_IDS } from "./catalog.js";
import type { Config } from "./types.js";

export const CONFIG_FILE = "saas-audit.config.json";
export const MAX_CONFIG_BYTES = 1024 * 1024;

export class ConfigError extends Error {
  override name = "ConfigError";
}

export const DEFAULT_CONFIG: Config = {
  ignoreRules: [],
  ignorePaths: [],
  authHelpers: [],
  publicRoutes: [],
  tenantColumns: [],
  sanitizers: [],
  dataAccessRoots: [],
  idempotencyHelpers: [],
  rateLimiters: [],
};

const LIST_KEYS = Object.keys(DEFAULT_CONFIG) as (keyof Config)[];

/** Parses and strictly validates the JSON config. It is data only and cannot load code. */
export function parseConfig(text: string, source = CONFIG_FILE): Config {
  if (text.length > MAX_CONFIG_BYTES) throw new ConfigError(`${source}: larger than ${MAX_CONFIG_BYTES} bytes`);
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch (e) {
    throw new ConfigError(`${source}: invalid JSON (${(e as Error).message})`);
  }
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) throw new ConfigError(`${source}: expected a JSON object`);
  const config: Config = { ...DEFAULT_CONFIG };
  for (const [key, value] of Object.entries(raw)) {
    if (key === "$schema") continue;
    if (!(LIST_KEYS as string[]).includes(key)) throw new ConfigError(`${source}: unknown key "${key}" (allowed: ${LIST_KEYS.join(", ")})`);
    if (!Array.isArray(value) || value.some((v) => typeof v !== "string" || v.trim() === "")) {
      throw new ConfigError(`${source}: "${key}" must be an array of non-empty strings`);
    }
    config[key as keyof Config] = (value as string[]).map((v) => v.trim());
  }
  for (const id of config.ignoreRules) {
    if (!RULE_IDS.has(id)) throw new ConfigError(`${source}: "ignoreRules" contains unknown rule "${id}"`);
  }
  return config;
}
