#!/usr/bin/env node
/**
 * Validates SupplyChain Sentry against real-world project paths.
 */
import { spawnSync } from 'node:child_process';
import { writeFileSync, mkdirSync, existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, '..');
const cli = path.join(root, 'dist', 'cli.js');
const resultsDir = path.join(root, 'test-results');

const projects = [
  {
    id: 'supplychain-sentry',
    path: root,
    description: 'Small CLI tool (~260 dev deps in lock)',
  },
  {
    id: 'fixture-project',
    path: path.join(root, 'test', 'fixtures', 'fixture-project'),
    description: 'Controlled malicious fixture',
  },
  {
    id: 'sdc-svt-demo',
    path: 'D:/Mine/Code/sdc-svt-demo',
    description: 'Large Vue/pnpm monorepo (production demo app)',
  },
];

function scanProject(project) {
  const reportPath = path.join(resultsDir, `${project.id}-report.json`);
  const result = spawnSync(
    process.execPath,
    [
      cli,
      '--path',
      project.path,
      '--no-sandbox',
      '--no-reputation',
      '--quiet',
      '--json',
      reportPath,
      '--fail-on-severity',
      'critical',
    ],
    { encoding: 'utf-8', cwd: root }
  );

  let report = null;
  if (existsSync(reportPath)) {
    report = JSON.parse(readFileSync(reportPath, 'utf-8'));
  }

  return {
    exitCode: result.status,
    reportPath,
    report,
    stderr: result.stderr || '',
  };
}

function main() {
  mkdirSync(resultsDir, { recursive: true });
  const outcomes = [];

  for (const project of projects) {
    if (!existsSync(project.path)) {
      outcomes.push({ ...project, status: 'skipped', reason: 'path missing' });
      continue;
    }

    const { exitCode, report, reportPath, stderr } = scanProject(project);
    outcomes.push({
      ...project,
      status: exitCode === 0 || exitCode === 1 ? 'completed' : 'failed',
      exitCode,
      reportPath,
      totalPackages: report?.totalPackages ?? 0,
      summary: report?.summary ?? null,
      stderr: stderr.slice(0, 500),
    });
  }

  const validationPath = path.join(resultsDir, 'validation.json');
  writeFileSync(
    validationPath,
    JSON.stringify({ generatedAt: new Date().toISOString(), outcomes }, null, 2)
  );

  console.log('Real project validation complete');
  for (const outcome of outcomes) {
    console.log(
      `- ${outcome.id}: ${outcome.status}, packages=${outcome.totalPackages ?? 0}, exit=${outcome.exitCode ?? 'n/a'}`
    );
  }
  console.log(`Saved: ${validationPath}`);
}

main();
