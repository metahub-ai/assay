/**
 * Isolate the suite from the machine it runs on.
 *
 * `assay` reads `~/.assay/config.json` on every command, and applies
 * whatever it finds to the environment. That is correct behaviour for
 * the product and poison for a test suite: a developer who has run
 * `assay setup` has an OpenRouter key in scope, so a test asserting
 * "no provider is configured, exit 2" gets exit 1 instead.
 *
 * The failure is invisible in CI — a fresh runner has no config — and
 * shows up only on the machines of people who actually use the tool.
 * That is the worst shape a flaky test can have.
 *
 * `ASSAY_HOME` is the documented override, so pointing it at an empty
 * directory gives every test the same blank machine.
 */
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

process.env["ASSAY_HOME"] = mkdtempSync(join(tmpdir(), "assay-test-home-"));

// Provider credentials leak in the same way, and for the same reason:
// a test that asserts on "nothing is configured" must not inherit the
// developer's shell.
for (const k of [
  "ANTHROPIC_API_KEY",
  "OPENAI_API_KEY",
  "OPENROUTER_API_KEY",
  "LOCAL_LLM_BASE_URL",
  "E2B_API_KEY",
]) {
  delete process.env[k];
}
