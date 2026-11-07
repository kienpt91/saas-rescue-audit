# Changelog

Notable changes. Earlier history is in the git log; release notes are generated from commit subjects (see [RELEASING.md](RELEASING.md)).

## Unreleased

### Added

- `--findings` prints the audit as records in the `findings.json` shape published by Cloudflare's open source security-audit-skill (not affiliated; the shape is re-implemented, see [docs/findings-export.md](docs/findings-export.md)). Every counted finding is a `needs_validation` record with blockers that start with "Static analysis only" and a per-rule `validation_plan`; a finding the project silenced itself is a `rejected` record whose reason says nothing was disproved; no record is ever `confirmed`. Fingerprints are `saas-audit/<rule>:<path>:<subject>`, built from names and never from line numbers. Findings the format cannot hold (unrepresentable file name, more than 1000 records or 5 MiB) are counted on stderr.
- Findings in `--json` carry optional `subject`, `entry` and `sink` fields (the names that identify a finding, and where it enters and where it lands, for the rules that know them).
- `examples/sample-findings.json` and `npm run sample:findings`.
- `npm run coverage` (V8 coverage with thresholds) and the pinned `@vitest/coverage-v8` development dependency.

### Changed

- `deps-unpinned` and the other findings located through `package.json` keys now find the line of a key that is written with JSON escapes (before, such a key fell back to line 1). A key that the line map does not hold (for example one longer than 214 characters) falls back to the line of its section (`dependencies` and so on) instead of line 1.
