# SupplyChain Sentry

Scan npm dependencies for supply chain security risks — detect malicious install scripts, suspicious packages, and weak reputation signals before they compromise your project.

[![npm version](https://img.shields.io/npm/v/supplychain-sentry.svg)](https://www.npmjs.com/package/supplychain-sentry)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node >= 18](https://img.shields.io/badge/node-%3E%3D18-green.svg)](https://nodejs.org/)
[![CI](https://github.com/lichen-zhang/supplychain-sentry/actions/workflows/ci.yml/badge.svg)](https://github.com/lichen-zhang/supplychain-sentry/actions/workflows/ci.yml)
[![coverage](https://img.shields.io/badge/coverage-82%25-brightgreen)](./BENCHMARKS.md)

## Why SupplyChain Sentry?

> Run `sentry-scan` and if the report shows no Critical/High issues, your dependencies' install scripts should not perform obviously malicious actions (dynamic code execution, unexpected outbound requests, or sensitive file access).

## Installation

```bash
npm install -g supplychain-sentry
```

Or run without installing:

```bash
npx supplychain-sentry
```

## Quick Start

```bash
sentry-scan
sentry-scan --verbose
sentry-scan --json > report.json
sentry-scan --html sentry-report.html
```

## Rules (16)

| Rule ID | Name | Severity | False positive risk | Description |
|---------|------|----------|---------------------|-------------|
| R001 | Suspicious Package Name | Critical | Low | Malicious keywords in package name |
| R002 | Eval Usage | High | Medium | `eval()` / `new Function()` in code or install scripts |
| R003 | Timer with String | Medium | Medium | `setTimeout/setInterval` with string args |
| R004 | Child Process Execution | High | Medium | `child_process` exec/spawn usage |
| R005 | Unencrypted Network | Medium | Low | Plain `http://` URLs |
| R006 | Obfuscated Code | High | Medium | Suspicious base64 payloads |
| R007 | Network Requests | Medium | Medium | `fetch`, `http(s).request`, `axios`, `curl` |
| R008 | Lifecycle Hooks | High/Medium | Low | `preinstall` / `install` / `postinstall` scripts |
| R009 | Excessive Dependencies | Low | Low | More than 50 direct dependencies |
| R010 | Missing Documentation | Low | High | No README present |
| R011 | Sensitive File Access | High | Medium | `~/.npmrc`, `~/.aws/credentials`, `/etc/passwd`, `.env` |
| R012 | Malicious Package Blacklist | Critical | Low | Known community-reported malicious names |
| R013 | Suspicious README | Medium | High | Padded or low-information README heuristics |
| R014 | Non-Official Registry | High | Medium | Resolved outside `registry.npmjs.org` |
| R015 | Suspicious Metadata | Low/Medium | Medium | Missing or mismatched author/repository |
| R016 | Environment Export | Medium | Medium | `process.env` mutation in scripts |

### Ignore a rule or package

```json
{
  "ignorePackages": ["debug"],
  "ignoreRules": ["R010"]
}
```

## Configuration

Create `.sentryrc.json` or `sentry.config.json`:

```json
{
  "ignorePackages": ["lodash"],
  "ignoreRules": ["R010"],
  "thresholds": {
    "reputation": 40,
    "severity": "high"
  },
  "sandbox": {
    "enabled": true,
    "timeout": 30
  },
  "output": {
    "json": false,
    "html": false
  }
}
```

## Reputation Score (0–100)

| Factor | Weight | Source |
|--------|--------|--------|
| Weekly downloads | 25% | npm downloads API |
| Maintainers | 20% | npm registry metadata |
| Recency | 20% | Last publish date |
| Complexity / depth | 15% | Dependency count + lockfile depth |
| Security indicators | 20% | License, scripts, repository |

Packages below the reputation threshold (default `30`) are flagged automatically.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No blocking severity issues |
| 1 | Critical/High (or configured threshold) issues found |
| 2 | Runtime error (missing lock file, invalid config, etc.) |

## FAQ

### My package was flagged as high risk — what should I do?

1. Run `sentry-scan --verbose` to inspect rule evidence.
2. If it is a false positive, add the package or rule to `.sentryrc.json`:

```json
{
  "ignorePackages": ["my-internal-lib"],
  "ignoreRules": ["R004"]
}
```

### Why does SupplyChain Sentry use Docker?

Docker runs install scripts in an isolated container with `--network=none` and read-only mounts to observe risky behavior without affecting your host. If Docker is unavailable, sandbox analysis is skipped with a clear warning and all other checks still run.

Disable sandbox entirely with:

```bash
sentry-scan --no-sandbox
```

### How is the reputation score calculated?

The score combines public npm metadata and lockfile-derived dependency depth. See the table above. Sub-scores are included in verbose and JSON output.

## Privacy Policy

SupplyChain Sentry:

- Does **not** collect telemetry
- Does **not** upload scan results to any remote server
- Only performs outbound requests to public npm APIs for package metadata and download counts
- Stores reports locally only when you pass `--json` or `--html`

Your dependency list never leaves your machine except for public npm metadata lookups.

## CI Integration

### GitHub Actions

```yaml
name: Supply Chain Scan
on: [push, pull_request]

jobs:
  sentry:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      - run: npm ci
      - run: npx supplychain-sentry --json report.json
      - uses: actions/upload-artifact@v4
        with:
          name: sentry-report
          path: report.json
```

### GitLab CI

```yaml
supplychain-scan:
  image: node:20
  script:
    - npm ci
    - npx supplychain-sentry --json report.json
  artifacts:
    paths:
      - report.json
```

### CircleCI

```yaml
jobs:
  scan:
    docker:
      - image: cimg/node:20.0
    steps:
      - checkout
      - run: npm ci
      - run: npx supplychain-sentry --json report.json
      - store_artifacts:
          path: report.json
```

## Contributing

- Report false positives via GitHub Issues with rule ID and package name
- Propose new rules in `src/rules/index.ts` and add tests under `test/`

## Development

```bash
npm install
npm run build
npm test
npm run test:coverage
npm run benchmark
npm run validate:real
```

See [BENCHMARKS.md](./BENCHMARKS.md) for recorded performance data and real-project validation results.

## License

MIT — see [LICENSE](LICENSE).
