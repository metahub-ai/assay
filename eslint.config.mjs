// @ts-check
/**
 * Lint rules.
 *
 * `package.json` declared `"lint": "eslint ."` for months with no
 * eslint dependency, no config file, and no CI step invoking it — so
 * `npm run lint` answered `eslint: command not found` and CONTRIBUTING
 * described rules nothing enforced.
 *
 * That gap had a cost. `assay replay` shipped printing the source text
 * of a function on every result line, because a `const glyph = mark(…)`
 * was computed and `${mark}` interpolated instead. Two default rules —
 * `no-unused-vars` and `no-base-to-string` — each catch it outright.
 * The command that justifies the whole replayable determinism tier had
 * its default output broken, and 832 passing unit tests never looked at
 * it, because none of them render.
 *
 * The set below is deliberately small: rules that catch a class of
 * mistake this codebase has actually made.
 */
import js from "@eslint/js";
import tseslint from "typescript-eslint";

export default tseslint.config(
  {
    // Build scripts are plain ESM, outside the TS project the typed
    // rules need.
    ignores: ["dist/**", "coverage/**", "node_modules/**", "*.config.mjs", "scripts/**"],
  },
  // Deliberately NOT `recommendedTypeChecked` wholesale. That set
  // reports 226 problems here, almost all of them stylistic
  // (`unbound-method` on every destructured theme helper,
  // `no-unnecessary-type-assertion` on defensive casts), and a lint
  // nobody can get to zero is a lint that gets skipped — which is how
  // this project arrived at a `lint` script that could not run at all.
  //
  // The rules below are the ones that catch a class of mistake this
  // codebase has actually shipped. Tightening the set later is easy;
  // starting from red is not.
  js.configs.recommended,
  tseslint.configs.base,
  {
    // Required, not optional. In flat config `eslint .` expands a
    // directory to `**/*.js` only, so without this glob the lint ran
    // against zero TypeScript files and reported success — the same
    // "configured but not actually wired" failure this file was added
    // to fix. Verify with `eslint . --debug` if it ever goes quiet.
    files: ["**/*.ts"],
    languageOptions: {
      parserOptions: {
        project: "./tsconfig.lint.json",
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      // The replay bug, exactly: a value computed and then dropped at
      // the call site. This codebase's single most repeated defect —
      // `caseCache`, `providedEvalFiles`, `allowedTools`, `infraHint`
      // and `glyph` were all built, correct, and read by nothing.
      "@typescript-eslint/no-unused-vars": [
        "error",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
      ],
      // Interpolating a function, object or array into a template
      // literal. The other half of the same bug.
      "@typescript-eslint/no-base-to-string": "error",
      "@typescript-eslint/restrict-template-expressions": [
        "error",
        { allowNumber: true, allowBoolean: true, allowNullish: false },
      ],

      // A floating promise in a check is a result that never lands.
      "@typescript-eslint/no-floating-promises": "error",
      "@typescript-eslint/await-thenable": "error",

      // Silence is how a policy file gets ignored. An empty catch must
      // say, in a comment, why swallowing is right here.
      "no-empty": ["error", { allowEmptyCatch: false }],

      // Tests reach into internals deliberately; production code should
      // not need to.
      // TypeScript already resolves every identifier, including type-only
      // ones that `no-undef` cannot see (it reported `CheckStatus` as
      // undefined). typescript-eslint's own guidance is to turn it off.
      "no-undef": "off",
      // Superseded by the typescript-eslint version, which understands
      // type parameters and `_`-prefixed intentional discards.
      "no-unused-vars": "off",
      "@typescript-eslint/no-explicit-any": "warn",
      // A literal ESC byte in a regex is how this codebase strips ANSI.
      "no-control-regex": "off",
      "@typescript-eslint/no-unsafe-assignment": "off",
      "@typescript-eslint/no-unsafe-member-access": "off",
      "@typescript-eslint/no-unsafe-call": "off",
      "@typescript-eslint/no-unsafe-return": "off",
      "@typescript-eslint/no-unsafe-argument": "off",
    },
  },
  {
    files: ["tests/**/*.ts"],
    rules: {
      "@typescript-eslint/no-explicit-any": "off",
      "@typescript-eslint/no-non-null-assertion": "off",
    },
  },
);
