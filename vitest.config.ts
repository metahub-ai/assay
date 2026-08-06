import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    name: "@metahub-ai/assay",
    include: ["tests/**/*.test.ts"],
    environment: "node",
    // Every test starts from a blank machine. See tests/setup-env.ts.
    setupFiles: ["./tests/setup-env.ts"],
    passWithNoTests: false,
    coverage: {
      provider: "v8",
      reporter: ["text", "lcov", "json-summary"],
      reportsDirectory: "./coverage",
      // Branches sits lower than the rest on purpose, and the reason is
      // recorded rather than left as an unexplained number.
      //
      // The ported MCP and plugin harnesses are dense with defensive
      // branches for third-party shapes we do not control — malformed
      // JSON-RPC frames, exotic manifest layouts, servers that die
      // mid-handshake. Exercising every one of those offline would mean
      // asserting that our fake matches our own fake. They are covered
      // by contract tests against real vendors, which need credentials
      // and are not part of the default run.
      //
      // Statements, functions and lines stay at 85. The measured figures
      // are published in docs/COVERAGE.md rather than restated here,
      // where they go stale silently.
      thresholds: { statements: 85, branches: 75, functions: 85, lines: 85 },
      include: ["src/**/*.ts"],
      exclude: [
        "**/*.d.ts",
        "**/*.test.ts",
        "tests/**",
        // Pure re-export barrel.
        "src/index.ts",
        // Type-only modules — compile to empty JS.
        "src/types.ts",
        // Vendor adapters. Each is a thin translation layer over a
        // third-party SDK (e2b, openai, podman's CLI), so a unit test
        // would assert only that our mock matches our own mock. They
        // are verified by contract tests against the real vendor,
        // which need credentials and are therefore not part of the
        // default run.
        //
        // This exclusion is a real gap and is recorded as one in
        // docs/COVERAGE.md rather than left implicit — the whole
        // point of that document is that hidden exclusions are how
        // coverage numbers start lying.
        "src/adapters/**",
      ],
    },
  },
});
