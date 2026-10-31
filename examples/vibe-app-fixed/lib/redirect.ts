/** Accepts only same-site relative paths; everything else falls back to the dashboard. */
export function safeNextPath(value: string | null): string {
  if (value && value.startsWith("/") && !value.startsWith("//") && !value.includes("\\")) return value;
  return "/dashboard";
}
