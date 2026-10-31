import { readFileSync } from "node:fs";

export const TOOL_NAME = "saas-audit";

const pkg: unknown = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));

/** Read from package.json at runtime so the version has one source of truth. */
export const TOOL_VERSION: string = typeof pkg === "object" && pkg !== null && "version" in pkg && typeof pkg.version === "string" ? pkg.version : "0.0.0";
