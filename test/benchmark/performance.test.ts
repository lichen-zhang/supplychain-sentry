import { describe, it, expect } from 'vitest';
import { performance } from 'node:perf_hooks';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseDependencies } from '../../src/utils/dependency-parser';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, '../..');
const cli = path.join(root, 'dist', 'cli.js');

describe('performance benchmarks', () => {
  it('cold starts in under 500ms', () => {
    const start = performance.now();
    const result = spawnSync(process.execPath, [cli, '--version'], { encoding: 'utf-8' });
    const elapsed = performance.now() - start;
    expect(result.status).toBe(0);
    expect(elapsed).toBeLessThan(500);
  });

  it('parses fixture lock file in under 100ms', () => {
    const fixtureProject = path.join(root, 'test/fixtures/fixture-project');
    const start = performance.now();
    const deps = parseDependencies(fixtureProject);
    const elapsed = performance.now() - start;
    expect(deps.length).toBeGreaterThan(0);
    expect(elapsed).toBeLessThan(100);
  });
});
