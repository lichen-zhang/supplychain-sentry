#!/usr/bin/env node
/**
 * Performance benchmark runner for SupplyChain Sentry.
 * Records cold-start latency and static scan duration (no network reputation).
 */
import { spawnSync } from 'node:child_process';
import { performance } from 'node:perf_hooks';
import { writeFileSync, mkdirSync, readFileSync, existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, '..');
const cli = path.join(root, 'dist', 'cli.js');
const resultsDir = path.join(root, 'test-results');

const projects = [
  {
    id: 'supplychain-sentry',
    label: 'SupplyChain Sentry (self, small CLI)',
    path: root,
    profile: 'small-cli',
  },
  {
    id: 'fixture-project',
    label: 'Fixture project (malicious sample)',
    path: path.join(root, 'test', 'fixtures', 'fixture-project'),
    profile: 'small-web',
  },
  {
    id: 'sdc-svt-demo',
    label: 'sdc-svt-demo (pnpm monorepo)',
    path: 'D:/Mine/Code/sdc-svt-demo',
    profile: 'large-monorepo',
  },
];

function runCli(args, options = {}) {
  const start = performance.now();
  const jsonFlagIndex = args.indexOf('--json');
  const jsonPath =
    jsonFlagIndex >= 0 && args[jsonFlagIndex + 1] && !args[jsonFlagIndex + 1].startsWith('-')
      ? args[jsonFlagIndex + 1]
      : null;

  const result = spawnSync(process.execPath, [cli, ...args], {
    cwd: options.cwd || root,
    encoding: 'utf-8',
    stdio: ['ignore', 'pipe', 'pipe'],
    maxBuffer: 64 * 1024 * 1024,
    env: { ...process.env, NODE_ENV: 'production' },
  });

  const stdout =
    jsonPath && existsSync(jsonPath) ? readFileSync(jsonPath, 'utf-8') : result.stdout || '';

  return {
    ms: performance.now() - start,
    status: result.status,
    stdout,
    stderr: result.stderr || '',
  };
}

function countLockPackages(projectPath) {
  const lockCandidates = ['pnpm-lock.yaml', 'package-lock.json', 'yarn.lock'];
  for (const file of lockCandidates) {
    const lockPath = path.join(projectPath, file);
    if (!existsSync(lockPath)) continue;
    const content = readFileSync(lockPath, 'utf-8');
    if (file.endsWith('pnpm-lock.yaml')) {
      return (content.match(/^ {2}['"][^'"]+['"]:\s*$/gm) || []).length +
        (content.match(/^ {2}\/[^@]+@[^:]+:$/gm) || []).length;
    }
    if (file.endsWith('package-lock.json')) {
      try {
        const json = JSON.parse(content);
        if (json.packages) {
          return Object.keys(json.packages).filter((k) => k.includes('node_modules')).length;
        }
      } catch {
        return 0;
      }
    }
    if (file.endsWith('yarn.lock')) {
      return (content.match(/^[^#\s].+@.+:$/gm) || []).length;
    }
  }
  return 0;
}

function main() {
  if (!existsSync(cli)) {
    console.error('Build required: run npm run build first');
    process.exit(2);
  }

  mkdirSync(resultsDir, { recursive: true });

  const cold = runCli(['--version']);
  const help = runCli(['--help']);

  const rows = [];
  for (const project of projects) {
    if (!existsSync(project.path)) {
      rows.push({
        ...project,
        skipped: true,
        reason: 'path not found',
      });
      continue;
    }

    const lockPackages = countLockPackages(project.path);
    const scan = runCli(
      ['--path', project.path, '--no-reputation', '--no-sandbox', '--quiet', '--json', path.join(resultsDir, `${project.id}-bench.json`)],
      { cwd: root }
    );

    let summary = {};
    try {
      summary = JSON.parse(scan.stdout);
    } catch {
      summary = { parseError: true, stderr: scan.stderr.slice(0, 300) };
    }

    rows.push({
      ...project,
      lockPackages,
      scannedPackages: summary.totalPackages ?? 0,
      critical: summary.summary?.critical ?? 0,
      high: summary.summary?.high ?? 0,
      scanMs: Math.round(scan.ms),
      exitCode: scan.status,
    });
  }

  const report = {
    generatedAt: new Date().toISOString(),
    platform: `${process.platform} ${process.arch}`,
    node: process.version,
    coldStartMs: Math.round(cold.ms),
    helpMs: Math.round(help.ms),
    targets: {
      coldStartMs: 500,
      mediumScanMs: 30000,
      monorepoScanMs: 60000,
    },
    projects: rows,
  };

  const jsonPath = path.join(resultsDir, 'benchmark.json');
  writeFileSync(jsonPath, JSON.stringify(report, null, 2));

  console.log('SupplyChain Sentry Benchmark');
  console.log('============================');
  console.log(`Cold start (--version): ${report.coldStartMs}ms (target < ${report.targets.coldStartMs}ms)`);
  console.log(`Help render:            ${report.helpMs}ms`);
  console.log('');
  for (const row of rows) {
    if (row.skipped) {
      console.log(`- ${row.label}: SKIPPED (${row.reason})`);
      continue;
    }
    const target =
      row.profile === 'large-monorepo' ? report.targets.monorepoScanMs : report.targets.mediumScanMs;
    const ok = row.scanMs <= target ? 'PASS' : 'SLOW';
    console.log(
      `- ${row.label}: ${row.scannedPackages} packages, ${row.scanMs}ms static scan [${ok}] (lock ~${row.lockPackages})`
    );
  }
  console.log(`\nSaved: ${jsonPath}`);
}

main();
