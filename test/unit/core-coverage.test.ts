import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { writeFileSync, mkdirSync, rmSync, readFileSync } from 'node:fs';
import { parseDependencies, getMaxDependencyDepth, getDirectDependencyCount } from '../../src/utils/dependency-parser';
import { JsonReporter } from '../../src/reporters/json';
import { shouldRunSandbox } from '../../src/sandbox/index';
import { normalizePackument } from '../../src/reputation/npm-api';
import { shouldFailScan, hasCriticalOrHigh } from '../../src/orchestrator';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const locksDir = path.join(__dirname, '../fixtures/locks');
const tempDir = path.join(__dirname, '../fixtures/temp-lock-project');

describe('lock file parsers', () => {
  beforeEach(() => {
    mkdirSync(tempDir, { recursive: true });
  });

  afterEach(() => {
    rmSync(tempDir, { recursive: true, force: true });
  });

  it('parses pnpm v9 lock files', () => {
    writeFileSync(path.join(tempDir, 'pnpm-lock.yaml'), read('pnpm-lock.v9.yaml'));
    const deps = parseDependencies(tempDir);
    expect(deps.map((d) => d.name).sort()).toEqual(['@scope/demo', 'lodash']);
    expect(deps.find((d) => d.name === 'lodash')?.resolved || deps.find((d) => d.name === 'lodash')?.integrity).toBeTruthy();
  });

  it('parses pnpm lock files with scoped packages', () => {
    writeFileSync(path.join(tempDir, 'pnpm-lock.yaml'), read('pnpm-lock.yaml'));
    const deps = parseDependencies(tempDir);
    expect(deps[0].name).toBe('safe-package');
  });

  it('parses yarn lock files', () => {
    writeFileSync(path.join(tempDir, 'yarn.lock'), read('yarn.lock'));
    const deps = parseDependencies(tempDir);
    expect(deps.map((d) => d.name).sort()).toEqual(['@scope/pkg', 'safe-package']);
  });

  it('parses npm v1 lock files with nested dependencies', () => {
    writeFileSync(path.join(tempDir, 'package-lock.json'), read('package-lock.v1.json'));
    const deps = parseDependencies(tempDir);
    expect(deps.map((d) => d.name).sort()).toEqual(['nested-dep', 'safe-package']);
    expect(getMaxDependencyDepth(deps)).toBeGreaterThan(0);
    expect(getDirectDependencyCount(deps)).toBeGreaterThan(0);
  });
});

describe('JsonReporter', () => {
  it('serializes scan results', () => {
    const reporter = new JsonReporter();
    const json = reporter.render(
      [
        {
          packageName: 'lodash',
          packageVersion: '4.17.21',
          reputationScore: {
            total: 90,
            maintainerScore: 90,
            recencyScore: 90,
            popularityScore: 90,
            complexityScore: 90,
            securityScore: 90,
          },
          issues: [],
          riskLevel: 'Info',
        },
      ],
      { projectPath: '/tmp/project' }
    );

    const parsed = JSON.parse(json);
    expect(parsed.totalPackages).toBe(1);
    expect(parsed.packages[0].packageName).toBe('lodash');
  });
});

describe('sandbox helpers', () => {
  it('decides when sandbox should run', () => {
    expect(shouldRunSandbox(20, [], 30)).toBe(true);
    expect(shouldRunSandbox(80, [{ severity: 'high' }], 30)).toBe(true);
    expect(shouldRunSandbox(80, [{ severity: 'low' }], 30)).toBe(false);
  });
});

describe('npm packument normalization', () => {
  it('extracts latest version fields', () => {
    const metadata = normalizePackument({
      name: 'demo',
      'dist-tags': { latest: '2.0.0' },
      maintainers: [{ name: 'dev' }],
      time: { created: '2020-01-01', modified: '2025-01-01', '2.0.0': '2025-01-01' },
      versions: {
        '2.0.0': {
          license: 'MIT',
          dependencies: { ms: '2.0.0' },
          scripts: { postinstall: 'node setup.js' },
        },
      },
    });

    expect(metadata.version).toBe('2.0.0');
    expect(metadata.license).toBe('MIT');
    expect(metadata.dependencies?.ms).toBe('2.0.0');
  });
});

describe('scan summary helpers', () => {
  it('detects blocking packages', () => {
    const summary = {
      results: [
        {
          packageName: 'bad',
          packageVersion: '1.0.0',
          reputationScore: {
            total: 10,
            maintainerScore: 0,
            recencyScore: 0,
            popularityScore: 0,
            complexityScore: 0,
            securityScore: 0,
          },
          issues: [{ ruleId: 'R002', severity: 'high', packageName: 'bad', message: 'bad' }],
          riskLevel: 'High' as const,
        },
      ],
      criticalPackages: 0,
      highPackages: 1,
      mediumPackages: 0,
      lowPackages: 0,
      durationSeconds: 1,
      dockerAvailable: false,
    };

    expect(hasCriticalOrHigh(summary)).toBe(true);
    expect(shouldFailScan(summary, 'high')).toBe(true);
    expect(shouldFailScan(summary, 'critical')).toBe(false);
  });
});

function read(name: string): string {
  return readFileSync(path.join(locksDir, name), 'utf-8');
}
