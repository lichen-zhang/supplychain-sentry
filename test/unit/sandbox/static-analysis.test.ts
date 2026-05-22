import { describe, it, expect } from 'vitest';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { analyzeInstallScriptStatically } from '../../../src/sandbox/static-analysis';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const fixtures = path.join(__dirname, '../../fixtures');

describe('sandbox static analysis', () => {
  it('flags network usage in postinstall script', () => {
    const findings = analyzeInstallScriptStatically(path.join(fixtures, 'malicious-network'));
    expect(findings.some((f) => f.type === 'network')).toBe(true);
  });

  it('returns empty findings for packages without install scripts', () => {
    const findings = analyzeInstallScriptStatically(path.join(fixtures, 'safe-package'));
    expect(findings).toHaveLength(0);
  });
});
