import { RuleResult } from '../rules/index.js';
import { ReputationScore } from '../reputation/score-calculator.js';
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

export interface ReportData {
  scanDate: string;
  projectPath: string;
  totalPackages: number;
  cleanPackages: number;
  packagesWithIssues: number;
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  packages: ScanResult[];
}

export class JsonReporter {
  render(results: ScanResult[], options: { projectPath?: string }): string {
    const now = new Date().toISOString();

    let critical = 0;
    let high = 0;
    let medium = 0;
    let low = 0;
    for (const result of results) {
      for (const issue of result.issues) {
        switch (issue.severity) {
          case 'critical':
            critical++;
            break;
          case 'high':
            high++;
            break;
          case 'medium':
            medium++;
            break;
          case 'low':
            low++;
            break;
        }
      }
    }

    const report: ReportData = {
      scanDate: now,
      projectPath: options.projectPath || process.cwd(),
      totalPackages: results.length,
      cleanPackages: results.filter((r) => r.issues.length === 0).length,
      packagesWithIssues: results.filter((r) => r.issues.length > 0).length,
      summary: { critical, high, medium, low },
      packages: results,
    };

    return JSON.stringify(report, null, 2);
  }
}
