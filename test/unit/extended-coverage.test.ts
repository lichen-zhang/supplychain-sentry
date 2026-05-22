import { describe, it, expect, vi, afterEach } from 'vitest';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { mkdirSync, writeFileSync, rmSync, readFileSync } from 'node:fs';
import { orchestrate } from '../../src/orchestrator';
import { fetchPackageMetadata, fetchDownloadCount } from '../../src/reputation/npm-api';
import { runSandboxAnalysis, isDockerAvailable } from '../../src/sandbox/index';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const fixtureProject = path.join(__dirname, '../fixtures/fixture-project');
const tempOut = path.join(__dirname, '../fixtures/temp-output');

describe('orchestrator outputs', () => {
  afterEach(() => {
    rmSync(tempOut, { recursive: true, force: true });
  });

  it('writes JSON and HTML reports to disk', async () => {
    mkdirSync(tempOut, { recursive: true });
    const jsonPath = path.join(tempOut, 'report.json');
    const htmlPath = path.join(tempOut, 'report.html');

    await orchestrate({
      path: fixtureProject,
      enableReputation: false,
      enableSandbox: false,
      quiet: true,
      outputJson: jsonPath,
      outputHtml: htmlPath,
    });

    expect(readFileSync(jsonPath, 'utf-8')).toContain('malicious-eval');
    expect(readFileSync(htmlPath, 'utf-8')).toContain('SupplyChain Sentry');
  });
});

describe('npm api', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('fetches and normalizes registry metadata', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => ({
        ok: true,
        json: async () => ({
          name: 'lodash',
          'dist-tags': { latest: '4.17.21' },
          maintainers: [{ name: 'jdalton' }],
          time: { modified: '2024-01-01', created: '2010-01-01' },
          versions: {
            '4.17.21': {
              license: 'MIT',
              dependencies: {},
            },
          },
        }),
      }))
    );

    const metadata = await fetchPackageMetadata('lodash');
    expect(metadata.version).toBe('4.17.21');
    expect(metadata.license).toBe('MIT');
  });

  it('returns zero downloads when API fails', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => ({
        ok: false,
      }))
    );

    expect(await fetchDownloadCount('unknown')).toBe(0);
  });
});

describe('sandbox', () => {
  it('skips packages without install scripts', async () => {
    const result = await runSandboxAnalysis(
      path.join(__dirname, '../fixtures/safe-package'),
      'safe-package',
      '1.0.0'
    );
    expect(result.skipped).toBe(true);
  });

  it('reports docker availability status', async () => {
    const available = await isDockerAvailable();
    expect(typeof available).toBe('boolean');
  });

  it('evaluates reputation during scan when enabled', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string) => {
        if (url.includes('downloads')) {
          return { ok: true, json: async () => ({ downloads: 10 }) };
        }
        return {
          ok: true,
          json: async () => ({
            name: 'safe-package',
            'dist-tags': { latest: '1.0.0' },
            maintainers: [],
            time: { modified: '2020-01-01', created: '2020-01-01' },
            versions: { '1.0.0': { license: 'MIT' } },
          }),
        };
      })
    );

    const summary = await orchestrate({
      path: fixtureProject,
      enableSandbox: false,
      quiet: true,
      reputationThreshold: 90,
    });

    const safe = summary.results.find((r) => r.packageName === 'safe-package');
    expect(safe?.issues.some((i) => i.ruleId === 'REP')).toBe(true);
  });
});
