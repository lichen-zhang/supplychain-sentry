# Benchmarks & Real-Project Validation

Recorded on **2026-05-22** using Node.js v22.22.0 on **Windows 11 (win32 x64)**.

Run locally:

```bash
npm run benchmark      # performance timings → test-results/benchmark.json
npm run validate:real  # scan 3 real projects → test-results/validation.json
```

## Performance Targets

| Metric | Target | Latest Result | Status |
|--------|--------|---------------|--------|
| Cold start (`--version`) | < 500 ms | **104 ms** | PASS |
| Medium project static scan | < 30 s | **3.1 s** (282 packages) | PASS |
| Large monorepo static scan | < 60 s | **19.0 s** (1566 packages) | PASS |
| Lock file parse (fixture) | < 100 ms | **< 5 ms** | PASS |

Static scans use `--no-reputation --no-sandbox` (no network). Full scans with reputation add ~200–500 ms per package depending on npm API latency.

## Benchmark Projects

| Project | Profile | Lock entries | Packages scanned | Static scan time |
|---------|---------|--------------|------------------|------------------|
| `supplychain-sentry` | Small CLI | ~328 | 282 | 3.05 s |
| `test/fixtures/fixture-project` | Controlled sample | 2 | 2 | 0.13 s |
| `D:/Mine/Code/sdc-svt-demo` | Vue/pnpm monorepo | ~776 | **1566** | 18.98 s |

## Real-Project Validation (2026-05-22)

Static validation (`--no-reputation --no-sandbox`, `--fail-on-severity critical`):

| Project | Packages | Critical | High | Medium | Low | Exit |
|---------|----------|----------|------|--------|-----|------|
| supplychain-sentry | 282 | 1 | 341 | 79 | 215 | 1 |
| fixture-project | 2 | 0 | 1 | 1 | 1 | 0 |
| **sdc-svt-demo** | **1566** | 3 | 218 | 428 | 1273 | 1 |

### sdc-svt-demo notes

- **Lock file**: pnpm v9 (`pnpm-lock.yaml`, lockfileVersion 9.0)
- **Scanner completed successfully** — parsed 1566 unique packages from the monorepo lockfile
- Most High/Medium findings are **heuristic warnings** (lifecycle hooks R008, metadata R015, missing README R010) common in large Vue/webpack ecosystems — review with `--verbose` and tune `.sentryrc.json` ignore rules for known-safe internal packages
- No scanner crashes or lockfile parse failures

### Recommended config for large monorepos

```json
{
  "ignoreRules": ["R010"],
  "ignorePackages": ["@sdc/preference", "@sdc/svt-core"],
  "thresholds": { "severity": "critical" },
  "sandbox": { "enabled": true, "timeout": 45 }
}
```

## Test Coverage

Core module coverage (vitest v8): **82.4%** lines/statements, **84.5%** functions.

```bash
npm run test:coverage
```

## Publish Dry-Run

```bash
npm publish --dry-run
```

Latest dry-run tarball: **~110 KB** packed, **~431 KB** unpacked, 11 files — no unexpected dependencies.
