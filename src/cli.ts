#!/usr/bin/env node

import { Command } from 'commander';
import { orchestrate, ScanOptions } from './orchestrator.js';
import { loadConfig } from './config/loader.js';

/** Commander option names differ from ScanOptions names, so we define a separate interface */
type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'none';

interface CommanderOpts {
  path: string;
  json: boolean;
  html: string;
  sandbox: boolean;
  reputation: boolean;
  staticRules: boolean;
  verbose: boolean;
  quiet: boolean;
  ignorePaths: string;
  threshold: string;
  failOnSeverity: SeverityLevel;
}

const program = new Command();

program
  .name('sentry-scan')
  .description('Scan npm dependencies for supply chain security risks - detect malicious packages before they compromise your project')
  .version('0.1.0', '-v, --version', 'output the version number')
  .option('-p, --path <path>', 'path to project root (default: current directory)', process.cwd())
  .option('--json', 'output JSON report instead of terminal table')
  .option('--html [file]', 'output HTML report (optional filename)', 'report.html')
  .option('--no-sandbox', 'disable behavioral sandbox analysis')
  .option('--no-reputation', 'disable reputation scoring')
  .option('--no-static-rules', 'disable static rule analysis')
  .option('--verbose', 'enable verbose logging')
  .option('--quiet', 'suppress non-essential output')
  .option('--ignore-paths <paths>', 'comma-separated paths to ignore (e.g., node_modules,dist)', 'node_modules')
  .option('--threshold <score>', 'minimum reputation score threshold (0-100, default: 30)', '30')
  .option('--fail-on-severity <level>', 'fail scan if severity level detected (critical|high|medium|low|none)', 'high')
  .parse(process.argv);

const opts = program.opts() as CommanderOpts;

async function main() {
  try {
    // Load configuration from .sentryrc.json if exists
    const config = await loadConfig(opts.path);
    
    // Merge CLI options with config file — map Commander names to ScanOptions names
    const finalOptions: ScanOptions = {
      path: opts.path,
      outputJson: opts.json || config.output?.json,
      outputHtml: opts.html !== undefined ? opts.html : config.output?.html,
      enableSandbox: opts.sandbox !== false && config.sandbox?.enabled !== false,
      enableReputation: opts.reputation !== false && config.reputation?.enabled !== false,
      enableStaticRules: opts.staticRules !== false && config.staticRules?.enabled !== false,
      verbose: opts.verbose || config.logging?.verbose || false,
      quiet: opts.quiet || config.logging?.quiet || false,
      ignorePaths: opts.ignorePaths.split(',').map((p: string) => p.trim()),
      reputationThreshold: parseInt(opts.threshold, 10) || config.thresholds?.reputation || 30,
      failOnSeverity: opts.failOnSeverity || config.thresholds?.severity || 'high',
      ignorePackages: config.ignorePackages || [],
      ignoreRules: config.ignoreRules || [],
    };

    console.log('\n╔═══════════════════════════════════════════════════════════╗');
    console.log('║         SupplyChain Sentry - Security Scanner             ║');
    console.log('║         Scanning for supply chain risks...                ║');
    console.log('╚═══════════════════════════════════════════════════════════╝\n');

    const results = await orchestrate(finalOptions);

    // Output summary
    const criticalCount = results.filter(r => r.issues.some(i => i.severity === 'critical')).length;
    const highCount = results.filter(r => r.issues.some(i => i.severity === 'high')).length;
    const mediumCount = results.filter(r => r.issues.some(i => i.severity === 'medium')).length;
    const lowCount = results.filter(r => r.issues.some(i => i.severity === 'low')).length;

    console.log('\n═══════════════════════════════════════════════════════════');
    console.log('                         SUMMARY                            ');
    console.log('═══════════════════════════════════════════════════════════');
    console.log(`Total packages scanned: ${results.length}`);
    console.log(`Issues found: ${results.length > 0 ? results.length : 'None'}`);
    console.log(`  ┌─ Critical: ${String(criticalCount).padStart(3)} ─┐`);
    console.log(`  ├─ High:     ${String(highCount).padStart(3)} ─┤`);
    console.log(`  ├─ Medium:   ${String(mediumCount).padStart(3)} ┤`);
    console.log(`  └─ Low:      ${String(lowCount).padStart(3)} ┘`);
    console.log('═══════════════════════════════════════════════════════════\n');

    // Determine exit code based on severity threshold
    const failLevels: Record<string, number> = { none: 0, low: 1, medium: 2, high: 3, critical: 4 };
    const failLevel = failLevels[finalOptions.failOnSeverity || 'high'] || 3;
    const issueLevel = criticalCount > 0 ? 4 : highCount > 0 ? 3 : mediumCount > 0 ? 2 : lowCount > 0 ? 1 : 0;

    if (issueLevel >= failLevel) {
      console.log('⚠️  Scan failed due to detected security issues.');
      process.exit(1);
    } else {
      console.log('✅ Scan completed successfully. No critical issues detected.');
      process.exit(0);
    }
  } catch (error) {
    console.error('\n❌ Error during scan:', error instanceof Error ? error.message : String(error));
    process.exit(1);
  }
}

main();
