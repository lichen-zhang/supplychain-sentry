import { describe, it, expect } from 'vitest';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { mkdirSync, symlinkSync, existsSync } from 'node:fs';
import { orchestrate } from '../../src/orchestrator';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const fixtureProject = path.join(__dirname, '../fixtures/fixture-project');

function ensureNodeModulesLinks() {
  const nodeModules = path.join(fixtureProject, 'node_modules');
  if (!existsSync(nodeModules)) {
    mkdirSync(nodeModules, { recursive: true });
  }

  const links = [
    ['malicious-eval', path.join(__dirname, '../fixtures/malicious-eval')],
    ['safe-package', path.join(__dirname, '../fixtures/safe-package')],
  ] as const;

  for (const [name, target] of links) {
    const linkPath = path.join(nodeModules, name);
    if (existsSync(linkPath)) continue;
    try {
      symlinkSync(target, linkPath, 'junction');
    } catch {
      // link may already exist from a previous run
    }
  }
}

describe('integration scan', () => {
  it('flags malicious fixture and keeps safe fixture clean', async () => {
    ensureNodeModulesLinks();

    const summary = await orchestrate({
      path: fixtureProject,
      enableReputation: false,
      enableSandbox: false,
      quiet: true,
    });

    const malicious = summary.results.find((r) => r.packageName === 'malicious-eval');
    const safe = summary.results.find((r) => r.packageName === 'safe-package');

    expect(malicious?.issues.some((i) => i.ruleId === 'R002')).toBe(true);
    expect(safe?.issues.filter((i) => ['R001', 'R002', 'R004', 'R011', 'R012'].includes(i.ruleId))).toHaveLength(0);
  });
});
