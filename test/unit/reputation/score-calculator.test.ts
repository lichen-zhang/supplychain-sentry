import { describe, it, expect } from 'vitest';
import { calculateReputationScore } from '../../../src/reputation/score-calculator';
import type { PackageMetadata } from '../../../src/reputation/npm-api';

const baseMetadata: PackageMetadata = {
  name: 'example',
  version: '1.0.0',
  maintainers: [{ name: 'a' }, { name: 'b' }],
  time: { created: '2025-01-01', modified: new Date().toISOString() },
  dist: { tarball: '', shasum: '' },
  license: 'MIT',
  repository: { type: 'git', url: 'https://github.com/example/pkg' },
  dependencies: { lodash: '^4.0.0' },
  funding: { type: 'github', url: 'https://github.com/sponsors/example' },
};

describe('calculateReputationScore', () => {
  it('returns total and sub-scores between 0 and 100', () => {
    const score = calculateReputationScore(baseMetadata, { downloads: 50000, start: '', end: '' });
    expect(score.total).toBeGreaterThanOrEqual(0);
    expect(score.total).toBeLessThanOrEqual(100);
    expect(score.maintainerScore).toBeGreaterThan(0);
    expect(score.popularityScore).toBeGreaterThan(0);
  });

  it('penalizes deep dependency nesting', () => {
    const shallow = calculateReputationScore(baseMetadata, undefined, { dependencyDepth: 1 });
    const deep = calculateReputationScore(baseMetadata, undefined, { dependencyDepth: 5 });
    expect(deep.complexityScore).toBeLessThanOrEqual(shallow.complexityScore);
  });
});
