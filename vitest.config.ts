import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["test/**/*.test.ts"],
    coverage: {
      provider: "v8",
      include: ["src/**/*.ts"],
      reporter: ["text", "json-summary"],
      thresholds: {
        "src/report/**": { lines: 98, statements: 98, functions: 98 },
        lines: 95,
        statements: 92,
        functions: 95,
        branches: 85,
      },
    },
  },
});
