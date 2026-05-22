import { readFileSync, existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { parseDependencies, DependencyInfo, getPackagePath } from './utils/dependency-parser.js';
import { rules, RuleResult, ruleMetadata } from './rules/index.js';
import { fetchPackageMetadata, fetchDownloadCount, PackageMetadata } from './reputation/npm-api.js';
import { calculateReputationScore, ReputationScore, getScoreGrade } from './reputation/score-calculator.js';
import { ConsoleReporter, ScanResult as ConsoleScanResult } from './reporters/console.js';
import { JsonReporter, ScanResult as JsonScanResult } from './reporters/json.js';
import { HtmlReporter, ScanResult as HtmlScanResult } from './reporters/html.js';
import { SentryConfig, validateConfig } from './config/loader.js';

export interface ScanOptions {
  path: string;
  outputJson?: boolean;
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
}

export interface ScanResult {
  packageName: string;
  packageVersion: string;
  reputationScore: ReputationScore;
  issues: RuleResult[];
}

export async function orchestrate(options: ScanOptions): Promise<ScanResult[]> {
  const startTime = Date.now();
  
  // Load and validate config
  const config = await import('./config/loader.js').then(m => m.loadConfig(options.path));
  const warnings = validateConfig(config);
  
  for (const warning of warnings) {
    console.warn(`⚠️  Config warning: ${warning}`);
  }

  // Parse dependencies
  console.log(`\n📦 Parsing dependencies from ${options.path}...`);
  let deps: DependencyInfo[];
  try {
    deps = parseDependencies(options.path);
    console.log(`   Found ${deps.length} packages in lock file`);
  } catch (error) {
    throw new Error(`Failed to parse dependencies: ${error instanceof Error ? error.message : String(error)}`);
  }

  // Filter ignored packages
  const ignorePackages = [...(options.ignorePackages || []), ...(config.ignorePackages || [])];
  deps = deps.filter(dep => !ignorePackages.includes(dep.name));
  console.log(`   After filtering ignored packages: ${deps.length} packages to scan`);

  // Run scans
  const results: ScanResult[] = [];
  const totalDeps = deps.length;
  let processed = 0;

  for (const dep of deps) {
    processed++;
    
    if (!options.quiet && processed % 10 === 0) {
      const progress = Math.round((processed / totalDeps) * 100);
      process.stdout.write(`\r   Scanning... ${progress}% (${processed}/${totalDeps})`);
    }

    try {
      const result = await scanPackage(dep, options, config);
      results.push(result);
    } catch (error) {
      console.error(`\n   ⚠️  Failed to scan ${dep.name}: ${error instanceof Error ? error.message : String(error)}`);
      // Add a result with no issues but mark it as failed
      results.push({
        packageName: dep.name,
        packageVersion: dep.version,
        reputationScore: { total: 0, maintainerScore: 0, recencyScore: 0, popularityScore: 0, complexityScore: 0, securityScore: 0 },
        issues: [],
      });
    }
  }

  if (!options.quiet) {
    process.stdout.write('\n');
  }

  // Generate reports
  if (options.outputJson) {
    const jsonReporter = new JsonReporter();
    const jsonResults: JsonScanResult[] = results.map(r => ({
      packageName: r.packageName,
      packageVersion: r.packageVersion,
      reputationScore: r.reputationScore,
      issues: r.issues,
    }));
    const jsonReport = jsonReporter.render(jsonResults, { projectPath: options.path });
    
    const outputPath = typeof options.outputJson === 'string' ? options.outputJson : 'report.json';
    writeFileSync(outputPath, jsonReport, 'utf-8');
    console.log(`\n📄 JSON report saved to: ${outputPath}`);
  }

  if (options.outputHtml) {
    const htmlReporter = new HtmlReporter();
    const htmlResults: HtmlScanResult[] = results.map(r => ({
      packageName: r.packageName,
      packageVersion: r.packageVersion,
      reputationScore: r.reputationScore,
      issues: r.issues,
    }));
    const htmlReport = htmlReporter.render(htmlResults, { 
      projectPath: options.path,
      outputFile: typeof options.outputHtml === 'string' ? options.outputHtml : 'report.html',
    });
    
    const outputPath = typeof options.outputHtml === 'string' ? options.outputHtml : 'report.html';
    writeFileSync(outputPath, htmlReport, 'utf-8');
    console.log(`\n📄 HTML report saved to: ${outputPath}`);
  }

  // Print console report
  if (!options.outputJson && !options.outputHtml) {
    const consoleReporter = new ConsoleReporter(options.verbose);
    const consoleResults: ConsoleScanResult[] = results.map(r => ({
      packageName: r.packageName,
      packageVersion: r.packageVersion,
      reputationScore: r.reputationScore,
      issues: r.issues,
    }));
    consoleReporter.render(consoleResults);
  }

  const endTime = Date.now();
  const duration = ((endTime - startTime) / 1000).toFixed(2);
  
  console.log(`\n⏱️  Scan completed in ${duration}s`);

  return results;
}

async function scanPackage(
  dep: DependencyInfo,
  options: ScanOptions,
  config: SentryConfig
): Promise<ScanResult> {
  const pkgPath = getPackagePath(options.path, dep.name);
  const issues: RuleResult[] = [];
  const ignoreRules = [...(options.ignoreRules || []), ...(config.ignoreRules || [])];

  // Run static rules
  if (options.enableStaticRules !== false) {
    for (const [ruleId, ruleFn] of Object.entries(rules)) {
      if (ignoreRules.includes(ruleId)) {
        continue;
      }
      
      try {
        const result = await ruleFn(pkgPath, dep.name);
        if (result) {
          issues.push(result);
        }
      } catch (error) {
        // Skip rules that fail
        if (options.verbose) {
          console.error(`   Rule ${ruleId} failed for ${dep.name}: ${error instanceof Error ? error.message : String(error)}`);
        }
      }
    }
  }

  // Calculate reputation score
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
        const scoreData = calculateReputationScore(metadata, { downloads: downloadCount, start: '', end: '' });
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
        console.error(`   Reputation check failed for ${dep.name}: ${error instanceof Error ? error.message : String(error)}`);
      }
    }
  }

  return {
    packageName: dep.name,
    packageVersion: dep.version,
    reputationScore,
    issues,
  };
}
