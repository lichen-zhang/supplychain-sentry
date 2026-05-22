import { describe, it, expect } from 'vitest';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { validateConfig, loadConfig } from '../../../src/config/loader';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const tempConfigDir = path.join(__dirname, '../../fixtures/temp-config');

describe('config loader', () => {
  it('validates reputation threshold range', () => {
    const warnings = validateConfig({ thresholds: { reputation: 150 } });
    expect(warnings.some((w) => w.includes('Reputation threshold'))).toBe(true);
  });

  it('accepts valid severity threshold', () => {
    const warnings = validateConfig({ thresholds: { severity: 'high' } });
    expect(warnings).toHaveLength(0);
  });

  it('loads .sentryrc.json and sentry.config.json', async () => {
    mkdirSync(tempConfigDir, { recursive: true });
    writeFileSync(
      path.join(tempConfigDir, '.sentryrc.json'),
      JSON.stringify({ ignorePackages: ['debug'] })
    );

    const config = await loadConfig(tempConfigDir);
    expect(config.ignorePackages).toEqual(['debug']);

    rmSync(tempConfigDir, { recursive: true, force: true });
  });
});
