import { writeFileSync } from 'node:fs';
import {
  parseDependencies,
  DependencyInfo,
  getPackagePath,
  getDirectDependencyCount,
} from './utils/dependency-parser.js';
import { rules, RuleResult, getHighestSeverity } from './rules/index.js';
import { fetchPackageMetadata, fetchDownloadCount } from './reputation/npm-api.js';
import { calculateReputationScore, ReputationScore } from './reputation/score-calculator.js';
import { ConsoleReporter, ScanResult as ConsoleScanResult } from './reporters/console.js';
import { JsonReporter, ScanResult as JsonScanResult } from './reporters/json.js';
import { HtmlReporter, ScanResult as HtmlScanResult } from './reporters/html.js';
import { SentryConfig, validateConfig } from './config/loader.js';
import {
  runSandboxAnalysis,
  shouldRunSandbox,
  isDockerAvailable,
  SandboxResult,
} from './sandbox/index.js';

export interface ScanOptions {
  path: string;
  outputJson?: boolean | string;
  outputHtml?: boolean | string;
  enableSandbox?: boolean;
  enableReputation?: boolean;
  enableStaticRules?: boolean;
  verbose?: boolean;
  quiet?: boolean;
  ignorePaths?: string[];
  reputationThreshold?: number;
  failOnSeverity?: 'critical' | 'high' | 'medium' | 'low' | 'none';
  ignorePackages?: string[];
  ignoreRules?: string[];
  sandboxTimeout?: number;
}

export interface ScanResult {
  packageName: string;
  packageVersion: string;
  reputationScore: ReputationScore;
  issues: RuleResult[];
  riskLevel: 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';
  sandbox?: SandboxResult;
  lowReputation?: boolean;
}

export interface ScanSummary {
  results: ScanResult[];
  criticalPackages: number;
  highPackages: number;
  mediumPackages: number;
  lowPackages: number;
  durationSeconds: number;
  dockerAvailable: boolean;
  sandboxSkippedReason?: string;
}

const severityRank: Record<string, number> = {
  none: 0,
  info: 1,
  low: 2,
  medium: 3,
  high: 4,
  critical: 5,
};

function toRiskLevel(issues: RuleResult[], lowReputation: boolean): ScanResult['riskLevel'] {
  const highest = getHighestSeverity(issues);
  if (highest === 'critical') return 'Critical';
  if (highest === 'high') return 'High';
  if (highest === 'medium') return 'Medium';
  if (highest === 'low') return 'Low';
  if (lowReputation) return 'Info';
  return 'Info';
}

export async function orchestrate(options: ScanOptions): Promise<ScanSummary> {
  const startTime = Date.now();

  const config = await import('./config/loader.js').then((m) => m.loadConfig(options.path));
  const warnings = validateConfig(config);

  for (const warning of warnings) {
    if (!options.quiet) {
      console.warn(`Config warning: ${warning}`);
    }
  }

  if (!options.quiet) {
    console.log(`\nParsing dependencies from ${options.path}...`);
  }

  const deps = parseDependencies(options.path);
  const directDependencyCount = getDirectDependencyCount(deps);

  if (!options.quiet) {
    console.log(`Found ${deps.length} packages in lock file`);
  }

  const ignorePackages = [...(options.ignorePackages || []), ...(config.ignorePackages || [])];
  const filteredDeps = deps.filter((dep) => !ignorePackages.includes(dep.name));

  if (!options.quiet) {
    console.log(`Scanning ${filteredDeps.length} packages after ignore list`);
  }

  const reputationThreshold =
    options.reputationThreshold ?? config.thresholds?.reputation ?? 30;
  const sandboxTimeout = options.sandboxTimeout ?? config.sandbox?.timeout ?? 30;
  const enableSandbox = options.enableSandbox !== false && config.sandbox?.enabled !== false;

  const dockerAvailable = enableSandbox ? await isDockerAvailable() : false;
  let sandboxSkippedReason: string | undefined;
  if (enableSandbox && !dockerAvailable) {
    sandboxSkippedReason =
      'Docker unavailable — sandbox analysis skipped. Other checks continue normally.';
    if (!options.quiet) {
      console.warn(`\n${sandboxSkippedReason}`);
    }
  }

  const results: ScanResult[] = [];
  const totalDeps = filteredDeps.length;
  let processed = 0;

  for (const dep of filteredDeps) {
    processed++;
    if (!options.quiet && processed % 10 === 0) {
      const progress = Math.round((processed / totalDeps) * 100);
      process.stdout.write(`\rScanning... ${progress}% (${processed}/${totalDeps})`);
    }

    try {
      const result = await scanPackage(dep, options, config, {
        reputationThreshold,
        sandboxTimeout,
        enableSandbox,
        dockerAvailable,
        directDependencyCount,
      });
      results.push(result);
    } catch (error) {
      if (!options.quiet) {
        console.error(
          `\nFailed to scan ${dep.name}: ${error instanceof Error ? error.message : String(error)}`
        );
      }
      results.push({
        packageName: dep.name,
        packageVersion: dep.version,
        reputationScore: {
          total: 0,
          maintainerScore: 0,
          recencyScore: 0,
          popularityScore: 0,
          complexityScore: 0,
          securityScore: 0,
        },
        issues: [],
        riskLevel: 'Info',
        lowReputation: true,
      });
    }
  }

  if (!options.quiet) {
    process.stdout.write('\n');
  }

  const jsonResults: JsonScanResult[] = results.map((r) => ({
    packageName: r.packageName,
    packageVersion: r.packageVersion,
    reputationScore: r.reputationScore,
    issues: r.issues,
    riskLevel: r.riskLevel,
    sandbox: r.sandbox,
    lowReputation: r.lowReputation,
  }));

  if (options.outputJson) {
    const jsonReporter = new JsonReporter();
    const jsonReport = jsonReporter.render(jsonResults, { projectPath: options.path });
    const outputPath = typeof options.outputJson === 'string' ? options.outputJson : undefined;

    if (outputPath) {
      writeFileSync(outputPath, jsonReport, 'utf-8');
      if (!options.quiet) {
        console.log(`JSON report saved to: ${outputPath}`);
      }
    } else {
      console.log(jsonReport);
    }
  }

  if (options.outputHtml) {
    const htmlReporter = new HtmlReporter();
    const htmlResults: HtmlScanResult[] = jsonResults;
    const htmlReport = htmlReporter.render(htmlResults, {
      projectPath: options.path,
      outputFile: typeof options.outputHtml === 'string' ? options.outputHtml : 'sentry-report.html',
    });
    const outputPath =
      typeof options.outputHtml === 'string' ? options.outputHtml : 'sentry-report.html';
    writeFileSync(outputPath, htmlReport, 'utf-8');
    if (!options.quiet) {
      console.log(`HTML report saved to: ${outputPath}`);
    }
  }

  if (!options.outputJson) {
    const consoleReporter = new ConsoleReporter(options.verbose);
    const consoleResults: ConsoleScanResult[] = jsonResults;
    consoleReporter.render(consoleResults);
  }

  const durationSeconds = (Date.now() - startTime) / 1000;

  if (!options.quiet && !options.outputJson) {
    console.log(`\nScan completed in ${durationSeconds.toFixed(2)}s`);
    console.log('Run `sentry-scan --detail` or `sentry-scan --verbose` for full rule evidence.');
  }

  return {
    results,
    criticalPackages: results.filter((r) => r.riskLevel === 'Critical').length,
    highPackages: results.filter((r) => r.riskLevel === 'High').length,
    mediumPackages: results.filter((r) => r.riskLevel === 'Medium').length,
    lowPackages: results.filter((r) => r.riskLevel === 'Low').length,
    durationSeconds,
    dockerAvailable,
    sandboxSkippedReason,
  };
}

async function scanPackage(
  dep: DependencyInfo,
  options: ScanOptions,
  config: SentryConfig,
  runtime: {
    reputationThreshold: number;
    sandboxTimeout: number;
    enableSandbox: boolean;
    dockerAvailable: boolean;
    directDependencyCount: number;
  }
): Promise<ScanResult> {
  const pkgPath = getPackagePath(options.path, dep.name, dep.version);
  const issues: RuleResult[] = [];
  const ignoreRules = [...(options.ignoreRules || []), ...(config.ignoreRules || [])];

  if (options.enableStaticRules !== false) {
    for (const [ruleId, ruleFn] of Object.entries(rules)) {
      if (ignoreRules.includes(ruleId)) continue;

      try {
        const result = await ruleFn(pkgPath, dep.name, {
          resolved: dep.resolved,
          dependencyDepth: dep.depth,
        });
        if (result) issues.push(result);
      } catch (error) {
        if (options.verbose) {
          console.error(
            `Rule ${ruleId} failed for ${dep.name}: ${error instanceof Error ? error.message : String(error)}`
          );
        }
      }
    }
  }

  let reputationScore: ReputationScore = {
    total: 50,
    maintainerScore: 50,
    recencyScore: 50,
    popularityScore: 50,
    complexityScore: 50,
    securityScore: 50,
  };

  if (options.enableReputation !== false) {
    try {
      const [metadata, downloadCount] = await Promise.all([
        fetchPackageMetadata(dep.name).catch(() => null),
        fetchDownloadCount(dep.name).catch(() => 0),
      ]);

      if (metadata) {
        const scoreData = calculateReputationScore(
          metadata,
          { downloads: downloadCount, start: '', end: '' },
          {
            dependencyDepth: dep.depth,
            directDependencyCount: runtime.directDependencyCount,
          }
        );
        reputationScore = {
          total: scoreData.total,
          maintainerScore: scoreData.maintainerScore,
          recencyScore: scoreData.recencyScore,
          popularityScore: scoreData.popularityScore,
          complexityScore: scoreData.complexityScore,
          securityScore: scoreData.securityScore,
        };
      }
    } catch (error) {
      if (options.verbose) {
        console.error(
          `Reputation check failed for ${dep.name}: ${error instanceof Error ? error.message : String(error)}`
        );
      }
    }
  }

  const lowReputation = reputationScore.total < runtime.reputationThreshold;
  if (lowReputation) {
    issues.push({
      ruleId: 'REP',
      severity: 'medium',
      packageName: dep.name,
      message: `Reputation score ${reputationScore.total} is below threshold ${runtime.reputationThreshold}`,
      recommendation: 'Review package provenance, maintainers, and recent activity.',
    });
  }

  let sandbox: SandboxResult | undefined;
  if (
    runtime.enableSandbox &&
    runtime.dockerAvailable &&
    shouldRunSandbox(reputationScore.total, issues, runtime.reputationThreshold)
  ) {
    sandbox = await runSandboxAnalysis(pkgPath, dep.name, dep.version, {
      timeoutSeconds: runtime.sandboxTimeout,
      verbose: options.verbose,
    });

    for (const finding of sandbox.findings) {
      if (finding.type === 'info') continue;
      issues.push({
        ruleId: 'SBX',
        severity: finding.type === 'error' ? 'high' : 'medium',
        packageName: dep.name,
        message: `[Sandbox] ${finding.message}`,
        evidence: finding.detail,
      });
    }
  }

  return {
    packageName: dep.name,
    packageVersion: dep.version,
    reputationScore,
    issues,
    riskLevel: toRiskLevel(issues.filter((i) => i.ruleId !== 'REP'), lowReputation),
    sandbox,
    lowReputation,
  };
}

export function shouldFailScan(
  summary: ScanSummary,
  failOnSeverity: ScanOptions['failOnSeverity']
): boolean {
  const threshold = severityRank[failOnSeverity || 'high'] ?? severityRank.high;

  for (const result of summary.results) {
    const highest = getHighestSeverity(result.issues);
    if (severityRank[highest] >= threshold && highest !== 'none') {
      return true;
    }
  }

  return false;
}

export function hasCriticalOrHigh(summary: ScanSummary): boolean {
  return summary.criticalPackages > 0 || summary.highPackages > 0;
}
