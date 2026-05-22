import { RuleResult } from '../rules/index.js';
import { ReputationScore } from '../reputation/score-calculator.js';
import { getScoreGrade, getScoreColor } from '../reputation/score-calculator.js';
import { SandboxResult } from '../sandbox/index.js';

export interface ScanResult {
  packageName: string;
  packageVersion: string;
  reputationScore: ReputationScore;
  issues: RuleResult[];
  riskLevel: 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';
  sandbox?: SandboxResult;
  lowReputation?: boolean;
}

export class ConsoleReporter {
  private verbose: boolean;

  constructor(verbose = false) {
    this.verbose = verbose;
  }

  render(results: ScanResult[]): void {
    if (results.length === 0) {
      console.log('No packages to scan.');
      return;
    }

    console.log('\nPackage'.padEnd(34) + 'Version'.padEnd(14) + 'Risk'.padEnd(12) + 'Rules / Status');
    console.log('-'.repeat(90));

    for (const result of results) {
      const color = this.getRiskColor(result.riskLevel);
      const ruleIds = [...new Set(result.issues.map((i) => i.ruleId))];
      const status =
        ruleIds.length > 0
          ? `${color}${ruleIds.join(', ')}\x1b[0m`
          : `\x1b[32mClean\x1b[0m (${getScoreGrade(result.reputationScore.total)})`;

      console.log(
        result.packageName.padEnd(34) +
          result.packageVersion.padEnd(14) +
          `${color}${result.riskLevel.padEnd(12)}\x1b[0m` +
          status
      );
    }

    console.log('-'.repeat(90));

    const critical = results.filter((r) => r.riskLevel === 'Critical');
    const high = results.filter((r) => r.riskLevel === 'High');

    for (const result of [...critical, ...high]) {
      this.printPackageDetails(result);
    }

    if (this.verbose) {
      const others = results.filter((r) => !['Critical', 'High'].includes(r.riskLevel) && r.issues.length > 0);
      for (const result of others) {
        this.printPackageDetails(result);
      }
    }
  }

  private printPackageDetails(result: ScanResult): void {
    const color = this.getRiskColor(result.riskLevel);
    console.log(`\n${color}${result.packageName}@${result.packageVersion} [${result.riskLevel}]\x1b[0m`);
    console.log(`Reputation: ${getScoreColor(result.reputationScore.total)}${result.reputationScore.total}/100\x1b[0m`);

    for (const issue of result.issues) {
      console.log(`  [${issue.ruleId}] ${issue.message}`);
      if (issue.evidence) {
        console.log(`    Evidence: ${issue.evidence.substring(0, 120)}`);
      }
    }

    if (result.sandbox?.findings.length) {
      console.log('  Sandbox findings:');
      for (const finding of result.sandbox.findings) {
        console.log(`    - ${finding.message}`);
      }
    }
  }

  private getRiskColor(level: ScanResult['riskLevel']): string {
    switch (level) {
      case 'Critical':
      case 'High':
        return '\x1b[31m';
      case 'Medium':
        return '\x1b[33m';
      case 'Low':
        return '\x1b[36m';
      default:
        return '\x1b[0m';
    }
  }
}
