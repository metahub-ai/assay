## What and why

<!-- Explain the rationale, not just the diff. -->

## Does this change a published verdict?

- [ ] No
- [ ] Yes — I bumped the check `version` and added a changelog entry

<!-- If a verdict changes on unchanged input, that's the signal downstream
     caches and diffs key on. A substantive change in what a check MEANS
     needs a NEW id, not a version bump. -->

## Checklist

- [ ] `npm test` passes
- [ ] `npm run typecheck` passes
- [ ] `npm run format:check` passes
- [ ] New checks are testable from a `MemorySource` literal
- [ ] Any coverage exclusion is documented in `docs/COVERAGE.md`
