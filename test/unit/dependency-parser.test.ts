import { describe, it, expect } from 'vitest';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseDependencies, getPackagePath } from '../../src/utils/dependency-parser';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const fixtureProject = path.join(__dirname, '../fixtures/fixture-project');

describe('dependency-parser', () => {
  it('parses package-lock.json dependencies', () => {
    const deps = parseDependencies(fixtureProject);
    const names = deps.map((dep) => dep.name).sort();
    expect(names).toEqual(['malicious-eval', 'safe-package']);
  });

  it('resolves scoped package paths', () => {
    expect(getPackagePath('/project', '@babel/core')).toBe(path.join('/project', 'node_modules', '@babel', 'core'));
  });
});
