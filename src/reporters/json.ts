import { RuleResult } from '../rules/index.js';
import { ReputationScore } from '../reputation/score-calculator.js';

export interface ScanResult {
  packageName: string;
  packageVersion: string;
  reputationScore: ReputationScore;
  issues: RuleResult[];
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
    
    // Count by severity
    let critical = 0, high = 0, medium = 0, low = 0;
    for (const result of results) {
      for (const issue of result.issues) {
        switch (issue.severity) {
          case 'critical': critical++; break;
          case 'high': high++; break;
          case 'medium': medium++; break;
          case 'low': low++; break;
        }
      }
    }

    const report: ReportData = {
      scanDate: now,
      projectPath: options.projectPath || process.cwd(),
      totalPackages: results.length,
      cleanPackages: results.filter(r => r.issues.length === 0).length,
      packagesWithIssues: results.filter(r => r.issues.length > 0).length,
      summary: { critical, high, medium, low },
      packages: results,
    };

    return JSON.stringify(report, null, 2);
  }
}
