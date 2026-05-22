import { describe, it, expect } from 'vitest';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  getAllScannableSources,
  getInstallScriptSources,
  readPackageJson,
} from '../../../src/rules/helpers';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const fixtures = path.join(__dirname, '../../fixtures');

describe('rules helpers', () => {
  it('reads package.json and install script sources', () => {
    const pkgPath = path.join(fixtures, 'malicious-postinstall');
    const pkg = readPackageJson(pkgPath);
    expect(pkg?.scripts?.postinstall).toContain('postinstall.js');

    const scripts = getInstallScriptSources(pkgPath);
    expect(scripts.some((s) => s.content.includes('new Function'))).toBe(true);
  });

  it('collects main entry and bin sources', () => {
    const sources = getAllScannableSources(path.join(fixtures, 'malicious-eval'));
    expect(sources.length).toBeGreaterThan(0);
    expect(sources[0].content).toContain('eval');
  });
});
