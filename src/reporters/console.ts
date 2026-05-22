import { RuleResult } from '../rules/index.js';
import { ReputationScore } from '../reputation/score-calculator.js';
import { getScoreGrade, getScoreColor, resetColor } from '../reputation/score-calculator.js';

export interface ScanResult {
  packageName: string;
  packageVersion: string;
  reputationScore: ReputationScore;
  issues: RuleResult[];
}

export class ConsoleReporter {
  private verbose: boolean;

  constructor(verbose: boolean = false) {
    this.verbose = verbose;
  }

  render(results: ScanResult[]): void {
    if (results.length === 0) {
      console.log('No packages to scan.');
      return;
    }

    // Group results by severity
    const criticalResults: ScanResult[] = [];
    const highResults: ScanResult[] = [];
    const mediumResults: ScanResult[] = [];
    const lowResults: ScanResult[] = [];
    const cleanResults: ScanResult[] = [];

    for (const result of results) {
      const hasCritical = result.issues.some(i => i.severity === 'critical');
      const hasHigh = result.issues.some(i => i.severity === 'high');
      const hasMedium = result.issues.some(i => i.severity === 'medium');
      const hasLow = result.issues.some(i => i.severity === 'low');

      if (hasCritical) {
        criticalResults.push(result);
      } else if (hasHigh) {
        highResults.push(result);
      } else if (hasMedium) {
        mediumResults.push(result);
      } else if (hasLow) {
        lowResults.push(result);
      } else {
        cleanResults.push(result);
      }
    }

    // Print summary table
    this.printSummaryTable(results, criticalResults, highResults, mediumResults, lowResults, cleanResults);

    // Print detailed results for problematic packages
    if (criticalResults.length > 0) {
      console.log('\n' + '='.repeat(70));
      console.log('\x1b[31m🚨 CRITICAL ISSUES\x1b[0m');
      console.log('='.repeat(70));
      for (const result of criticalResults) {
        this.printPackageDetails(result, '\x1b[31m');
      }
    }

    if (highResults.length > 0) {
      console.log('\n' + '='.repeat(70));
      console.log('\x1b[33m⚠️  HIGH SEVERITY ISSUES\x1b[0m');
      console.log('='.repeat(70));
      for (const result of highResults) {
        this.printPackageDetails(result, '\x1b[33m');
      }
    }

    if (mediumResults.length > 0) {
      console.log('\n' + '='.repeat(70));
      console.log('\x1b[33m📋 MEDIUM SEVERITY ISSUES\x1b[0m');
      console.log('='.repeat(70));
      for (const result of mediumResults) {
        this.printPackageDetails(result, '\x1b[33m');
      }
    }

    if (lowResults.length > 0) {
      console.log('\n' + '='.repeat(70));
      console.log('\x1b[36mℹ️  LOW SEVERITY ISSUES\x1b[0m');
      console.log('='.repeat(70));
      for (const result of lowResults) {
        this.printPackageDetails(result, '\x1b[36m');
      }
    }

    // Print clean packages summary
    if (cleanResults.length > 0 && !this.verbose) {
      console.log(`\n\x1b[32m✓ ${cleanResults.length} package(s) passed all checks.\x1b[0m`);
    }
  }

  private printSummaryTable(
    allResults: ScanResult[],
    critical: ScanResult[],
    high: ScanResult[],
    medium: ScanResult[],
    low: ScanResult[],
    clean: ScanResult[]
  ): void {
    console.log('\n\x1b[1m═══════════════════════════════════════════════════════════════════\x1b[0m');
    console.log('\x1b[1m                    SCAN RESULTS SUMMARY                          \x1b[0m');
    console.log('\x1b[1m═══════════════════════════════════════════════════════════════════\x1b[0m\n');

    console.log(`\x1b[1mTotal Packages:\x1b[0m ${allResults.length}`);
    console.log(`\x1b[1mClean Packages:\x1b[0m ${clean.length}`);
    
    if (critical.length > 0) {
      console.log(`\x1b[31m┌─ Critical Issues:\x1b[0m ${critical.length}`);
    }
    if (high.length > 0) {
      console.log(`\x1b[33m├─ High Issues:\x1b[0m   ${high.length}`);
    }
    if (medium.length > 0) {
      console.log(`\x1b[33m├─ Medium Issues:\x1b[0m ${medium.length}`);
    }
    if (low.length > 0) {
      console.log(`\x1b[36m└─ Low Issues:\x1b[0m    ${low.length}`);
    }

    console.log('\n' + '─'.repeat(70));
    console.log('\x1b[1mPackage Name\x1b[0m'.padEnd(40) + '\x1b[1mReputation\x1b[0m'.padEnd(15) + '\x1b[1mStatus\x1b[0m');
    console.log('─'.repeat(70));

    for (const result of allResults) {
      const grade = getScoreGrade(result.reputationScore.total);
      const color = getScoreColor(result.reputationScore.total);
      const status = result.issues.length > 0 ? 
        `\x1b[31m${result.issues.length} issue(s)\x1b[0m` : 
        `\x1b[32m✓ Clean\x1b[0m`;
      
      const namePadded = result.packageName.padEnd(38);
      const scorePadded = `${color}${grade}\x1b[0m`.padEnd(15);
      
      console.log(`${namePadded}${scorePadded}${status}`);
    }

    console.log('─'.repeat(70) + '\n');
  }

  private printPackageDetails(result: ScanResult, headerColor: string): void {
    const grade = getScoreGrade(result.reputationScore.total);
    const color = getScoreColor(result.reputationScore.total);

    console.log(`\n${headerColor}Package: ${result.packageName}@${result.packageVersion}\x1b[0m`);
    console.log(`${headerColor}Reputation Score: ${color}${grade} (${result.reputationScore.total}/100)\x1b[0m`);
    console.log(`${headerColor}───────────────────────────────────────────────────────────────\x1b[0m\n`);

    for (const issue of result.issues) {
      const severityIcon = this.getSeverityIcon(issue.severity);
      const severityColor = this.getSeverityColor(issue.severity);
      
      console.log(`  ${severityColor}${severityIcon} [${issue.ruleId}] ${issue.message}\x1b[0m`);
      
      if (issue.evidence) {
        console.log(`     Evidence: ${issue.evidence.substring(0, 100)}${issue.evidence.length > 100 ? '...' : ''}`);
      }
      
      if (issue.recommendation) {
        console.log(`     Recommendation: ${issue.recommendation}`);
      }
      
      console.log('');
    }

    // Print reputation breakdown
    if (this.verbose) {
      console.log(`  \x1b[90mReputation Breakdown:\x1b[0m`);
      console.log(`    - Maintainers:    ${result.reputationScore.maintainerScore}/100`);
      console.log(`    - Recency:        ${result.reputationScore.recencyScore}/100`);
      console.log(`    - Popularity:     ${result.reputationScore.popularityScore}/100`);
      console.log(`    - Complexity:     ${result.reputationScore.complexityScore}/100`);
      console.log(`    - Security:       ${result.reputationScore.securityScore}/100`);
      console.log('');
    }
  }

  private getSeverityIcon(severity: string): string {
    switch (severity) {
      case 'critical': return '🚨';
      case 'high': return '⚠️';
      case 'medium': return '📋';
      case 'low': return 'ℹ️';
      default: return '•';
    }
  }

  private getSeverityColor(severity: string): string {
    switch (severity) {
      case 'critical': return '\x1b[31m';
      case 'high': return '\x1b[33m';
      case 'medium': return '\x1b[33m';
      case 'low': return '\x1b[36m';
      default: return '\x1b[0m';
    }
  }
}
