# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.1] - 2026-05-22

### Added

- Performance benchmark runner (`npm run benchmark`) and real-project validator (`npm run validate:real`)
- [BENCHMARKS.md](./BENCHMARKS.md) with recorded timings and validation on `sdc-svt-demo`
- Sandbox static pre-analysis of install scripts before Docker execution
- Docker hardening flags (`no-new-privileges`, `cap-drop ALL`)

### Fixed

- pnpm v9 lockfile parsing (`'@scope/pkg@1.0.0':` and `lodash@1.0.0:` formats)
- pnpm `.pnpm` store path resolution for package scanning
- Windows CRLF handling in yarn/pnpm lock parsers

## [1.0.0] - 2026-05-22

### Added

- 16 static security rules (R001–R016) covering eval, network requests, sensitive file access, child_process, blacklist, README heuristics, registry validation, and metadata checks
- Reputation scoring with weekly downloads, maintainers, recency, dependency depth/complexity, funding, and license signals
- Optional Docker sandbox for low-reputation or high-risk packages
- Terminal table, JSON (`--json`), and HTML (`--html`) reporting
- Exit codes: `0` clean, `1` blocking issues, `2` runtime errors
- Config support via `.sentryrc.json` and `sentry.config.json`
- Lock file parsing for npm, pnpm, and Yarn
- Integration tests with malicious and safe fixtures
- FAQ, privacy policy, and CI integration docs

### Changed

- Install lifecycle scripts are now scanned alongside main entry files
- JSON output defaults to stdout for CI piping
- HTML report is opt-in instead of always enabled

### Fixed

- R008 now reads hooks from `package.json` `scripts` instead of top-level fields
- R001 now evaluates the package name instead of filesystem path
- npm registry metadata normalization for latest version fields

[1.0.0]: https://github.com/lichen-zhang/supplychain-sentry/releases/tag/v1.0.0
