#!/usr/bin/env node

import { Command } from 'commander';
import { orchestrate, ScanOptions, shouldFailScan, hasCriticalOrHigh } from './orchestrator.js';
import { loadConfig } from './config/loader.js';

type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'none';

interface CommanderOpts {
  path: string;
  json?: boolean;
  html?: string | boolean;
  sandbox: boolean;
  reputation: boolean;
  staticRules: boolean;
  verbose: boolean;
  quiet: boolean;
  detail: boolean;
  ignorePaths: string;
  threshold: string;
  failOnSeverity: SeverityLevel;
}

const program = new Command();

program
  .name('sentry-scan')
  .description(
    'Scan npm dependencies for supply chain security risks - detect malicious packages before they compromise your project'
  )
  .version('1.0.1', '-v, --version', 'output the version number')
  .option('-p, --path <path>', 'path to project root (default: current directory)', process.cwd())
  .option('--json [file]', 'output JSON report to stdout or file')
  .option('--html [file]', 'output HTML report (default: sentry-report.html)')
  .option('--no-sandbox', 'disable behavioral sandbox analysis')
  .option('--no-reputation', 'disable reputation scoring')
  .option('--no-static-rules', 'disable static rule analysis')
  .option('--verbose', 'enable verbose logging')
  .option('--detail', 'alias for --verbose with full rule evidence')
  .option('--quiet', 'suppress non-essential output')
  .option('--ignore-paths <paths>', 'comma-separated paths to ignore', 'node_modules')
  .option('--threshold <score>', 'minimum reputation score threshold (0-100, default: 30)', '30')
  .option(
    '--fail-on-severity <level>',
    'fail scan if severity level detected (critical|high|medium|low|none)',
    'high'
  )
  .parse(process.argv);

const opts = program.opts() as CommanderOpts;

async function main() {
  try {
    const config = await loadConfig(opts.path);
    const verbose = opts.verbose || opts.detail || config.logging?.verbose || false;
    const quiet = opts.quiet || config.logging?.quiet || false;
    const jsonRequested = opts.json !== undefined || config.output?.json === true;
    const htmlRequested = opts.html !== undefined || config.output?.html === true;

    const finalOptions: ScanOptions = {
      path: opts.path,
      outputJson: jsonRequested ? (typeof opts.json === 'string' ? opts.json : true) : false,
      outputHtml: htmlRequested
        ? typeof opts.html === 'string'
          ? opts.html
          : typeof config.output?.html === 'string'
            ? config.output.html
            : true
        : false,
      enableSandbox: opts.sandbox !== false && config.sandbox?.enabled !== false,
      enableReputation: opts.reputation !== false && config.reputation?.enabled !== false,
      enableStaticRules: opts.staticRules !== false && config.staticRules?.enabled !== false,
      verbose,
      quiet: quiet || jsonRequested,
      ignorePaths: opts.ignorePaths.split(',').map((p: string) => p.trim()),
      reputationThreshold: parseInt(opts.threshold, 10) || config.thresholds?.reputation || 30,
      failOnSeverity: opts.failOnSeverity || config.thresholds?.severity || 'high',
      ignorePackages: config.ignorePackages || [],
      ignoreRules: config.ignoreRules || [],
      sandboxTimeout: config.sandbox?.timeout ?? 30,
    };

    if (!quiet && !jsonRequested) {
      console.log('\nSupplyChain Sentry - Security Scanner');
      console.log('Scanning for supply chain risks...\n');
    }

    const summary = await orchestrate(finalOptions);

    if (!quiet && !jsonRequested) {
      console.log('\nSUMMARY');
      console.log(`Total packages scanned: ${summary.results.length}`);
      console.log(`Critical: ${summary.criticalPackages}`);
      console.log(`High: ${summary.highPackages}`);
      console.log(`Medium: ${summary.mediumPackages}`);
      console.log(`Low: ${summary.lowPackages}`);

      if (summary.sandboxSkippedReason) {
        console.log(`Sandbox: ${summary.sandboxSkippedReason}`);
      }

      if (hasCriticalOrHigh(summary)) {
        console.log('\nRecommendation: run `sentry-scan --verbose` for full evidence.');
      }
    }

    if (shouldFailScan(summary, finalOptions.failOnSeverity)) {
      if (!quiet && !jsonRequested) {
        console.log('\nScan failed due to detected security issues.');
      }
      process.exit(1);
    }

    if (!quiet && !jsonRequested) {
      console.log('\nScan completed successfully. No blocking issues detected.');
    }
    process.exit(0);
  } catch (error) {
    console.error('\nError during scan:', error instanceof Error ? error.message : String(error));
    process.exit(2);
  }
}

main();
