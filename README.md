# SupplyChain Sentry

🛡️ **Scan npm dependencies for supply chain security risks - detect malicious packages before they compromise your project**

[![npm version](https://img.shields.io/npm/v/supplychain-sentry.svg)](https://www.npmjs.com/package/supplychain-sentry)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node >= 18](https://img.shields.io/badge/node-%3E%3D18-green.svg)](https://nodejs.org/)

## Features

- 🔍 **Static Rule Engine** - Detect suspicious patterns in package code
- 📊 **Reputation Scoring** - Analyze package health based on maintainers, downloads, and activity
- 🚨 **Severity-Based Reporting** - Critical, High, Medium, Low risk levels
- 📄 **Multiple Output Formats** - Terminal, JSON, HTML reports
- ⚙️ **Configurable** - Fine-tune rules, thresholds, and ignored packages
- 🌐 **Lock File Support** - Parse `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`

## Installation

```bash
npm install -g supplychain-sentry
```

Or use directly with npx:

```bash
npx supplychain-sentry
```

## Usage

### Basic Scan

```bash
sentry-scan
```

### Scan Specific Path

```bash
sentry-scan -p /path/to/project
```

### Output Options

```bash
# JSON report
sentry-scan --json

# HTML report
sentry-scan --html report.html

# Verbose output
sentry-scan -v
```

### Disable Components

```bash
# Skip reputation scoring
sentry-scan --no-reputation

# Skip static rules
sentry-scan --no-static-rules

# Skip sandbox analysis
sentry-scan --no-sandbox
```

### Threshold Configuration

```bash
# Fail on medium severity or above
sentry-scan --fail-on-severity medium

# Set minimum reputation score threshold
sentry-scan --threshold 50
```

## Rules

| Rule ID | Name | Severity | Description |
|---------|------|----------|-------------|
| R001 | Suspicious Package Name | Critical | Detects package names containing malicious keywords |
| R002 | Eval Usage | High | Detects use of `eval()` or `new Function()` |
| R003 | Timer with String | Medium | Detects `setTimeout/setInterval` with string arguments |
| R004 | Child Process Execution | High | Detects execution of shell commands |
| R005 | Unencrypted Network | Medium | Detects unencrypted HTTP URLs |
| R006 | Obfuscated Code | High | Detects suspicious base64-encoded strings |
| R007 | Remote Code Download | Medium | Detects downloading code from remote sources |
| R008 | Lifecycle Hooks | Medium/High | Detects package.json lifecycle hooks |
| R009 | Excessive Dependencies | Low | Detects packages with too many dependencies |
| R010 | Missing Documentation | Low | Detects packages without README |

## Configuration

Create a `.sentryrc.json` file in your project root:

```json
{
  "ignorePackages": ["lodash", "debug"],
  "ignoreRules": ["R010"],
  "thresholds": {
    "reputation": 40,
    "severity": "medium"
  },
  "sandbox": {
    "enabled": true,
    "timeout": 30
  }
}
```

## Reputation Score

The reputation score (0-100) is calculated based on:

| Factor | Weight | Description |
|--------|--------|-------------|
| Maintainers | 20% | Number of active maintainers/contributors |
| Recency | 20% | How recently the package was updated |
| Popularity | 25% | Weekly download count |
| Complexity | 15% | Number of dependencies |
| Security | 20% | Security indicators (scripts, license, etc.) |

### Grade Scale

| Score | Grade |
|-------|-------|
| 95-100 | A+ |
| 85-94 | A |
| 70-84 | B |
| 55-69 | C |
| 40-54 | D |
| 0-39 | F |

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '18'
      - run: npm ci
      - run: npx supplychain-scan --json
      - name: Upload Report
        uses: actions/upload-artifact@v3
        with:
          name: security-report
          path: report.json
```

## Development

```bash
# Clone the repository
git clone <repository-url>
cd supplychain-sentry

# Install dependencies
npm install

# Build
npm run build

# Run tests
npm test

# Watch mode
npm run dev
```

## License

MIT
