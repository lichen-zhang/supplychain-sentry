import { RuleResult } from '../rules/index.js';
import { ReputationScore, getScoreGrade } from '../reputation/score-calculator.js';

export interface ScanResult {
  packageName: string;
  packageVersion: string;
  reputationScore: ReputationScore;
  issues: RuleResult[];
}

const AMP = '&' + 'amp;';
const LT = '&' + 'lt;';
const GT = '&' + 'gt;';
const QUOT = '&' + 'quot;';
const APOS = '&' + '#39;';

export class HtmlReporter {
  render(results: ScanResult[], options: { projectPath?: string; outputFile?: string }): string {
    const now = new Date();
    
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

    const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SupplyChain Sentry - Security Report</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
      background: #f5f5f5;
      color: #333;
      line-height: 1.6;
    }
    .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
    header {
      background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
      color: white;
      padding: 40px 20px;
      text-align: center;
    }
    header h1 { font-size: 2.5em; margin-bottom: 10px; }
    header p { opacity: 0.9; }
    .summary {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 20px;
      margin: 30px 0;
    }
    .summary-card {
      background: white;
      border-radius: 10px;
      padding: 25px;
      text-align: center;
      box-shadow: 0 2px 10px rgba(0,0,0,0.1);
    }
    .summary-card.critical { border-top: 4px solid #e74c3c; }
    .summary-card.high { border-top: 4px solid #f39c12; }
    .summary-card.medium { border-top: 4px solid #f1c40f; }
    .summary-card.low { border-top: 4px solid #3498db; }
    .summary-card.clean { border-top: 4px solid #27ae60; }
    .summary-card h3 { font-size: 2em; margin-bottom: 5px; }
    .summary-card span { color: #666; font-size: 0.9em; }
    .section {
      background: white;
      border-radius: 10px;
      padding: 25px;
      margin: 20px 0;
      box-shadow: 0 2px 10px rgba(0,0,0,0.1);
    }
    .section h2 {
      border-bottom: 2px solid #eee;
      padding-bottom: 15px;
      margin-bottom: 20px;
      color: #1a1a2e;
    }
    .package-item {
      border: 1px solid #eee;
      border-radius: 8px;
      padding: 20px;
      margin: 15px 0;
    }
    .package-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 10px;
    }
    .package-name { font-size: 1.2em; font-weight: 600; color: #1a1a2e; }
    .package-version { color: #666; font-size: 0.9em; }
    .score-badge {
      padding: 8px 16px;
      border-radius: 20px;
      font-weight: 600;
      font-size: 0.9em;
    }
    .score-a-plus { background: #27ae60; color: white; }
    .score-a { background: #2ecc71; color: white; }
    .score-b { background: #3498db; color: white; }
    .score-c { background: #f39c12; color: white; }
    .score-d { background: #e67e22; color: white; }
    .score-f { background: #e74c3c; color: white; }
    .issues-list { margin-top: 15px; }
    .issue-item {
      background: #fff5f5;
      border-left: 4px solid #e74c3c;
      padding: 15px;
      margin: 10px 0;
      border-radius: 0 8px 8px 0;
    }
    .issue-item.high { border-left-color: #f39c12; background: #fffbf0; }
    .issue-item.medium { border-left-color: #f1c40f; background: #fffff0; }
    .issue-item.low { border-left-color: #3498db; background: #f0f8ff; }
    .issue-header {
      display: flex;
      align-items: center;
      gap: 10px;
      margin-bottom: 8px;
    }
    .severity-badge {
      padding: 3px 10px;
      border-radius: 4px;
      font-size: 0.8em;
      font-weight: 600;
      text-transform: uppercase;
    }
    .severity-critical { background: #e74c3c; color: white; }
    .severity-high { background: #f39c12; color: white; }
    .severity-medium { background: #f1c40f; color: #333; }
    .severity-low { background: #3498db; color: white; }
    .issue-message { font-weight: 500; }
    .issue-evidence {
      background: #f8f9fa;
      padding: 10px;
      border-radius: 4px;
      font-family: monospace;
      font-size: 0.85em;
      margin: 10px 0;
      overflow-x: auto;
    }
    .issue-recommendation {
      background: #e8f5e9;
      padding: 10px;
      border-radius: 4px;
      font-size: 0.9em;
      margin-top: 10px;
    }
    .recommendation-label {
      color: #27ae60;
      font-weight: 600;
      margin-right: 5px;
    }
    footer {
      text-align: center;
      padding: 30px;
      color: #666;
      font-size: 0.9em;
    }
    @media (max-width: 768px) {
      header h1 { font-size: 1.8em; }
      .summary { grid-template-columns: repeat(2, 1fr); }
      .package-header { flex-direction: column; align-items: flex-start; }
    }
  </style>
</head>
<body>
  <header>
    <h1>SupplyChain Sentry</h1>
    <p>Security Scan Report</p>
    <p style="margin-top: 10px; font-size: 0.9em;">Generated: ${this.escapeHtml(now.toLocaleString())}</p>
  </header>

  <div class="container">
    <div class="summary">
      <div class="summary-card clean">
        <h3>${results.filter(r => r.issues.length === 0).length}</h3>
        <span>Clean Packages</span>
      </div>
      <div class="summary-card critical">
        <h3 style="color: #e74c3c;">${critical}</h3>
        <span>Critical Issues</span>
      </div>
      <div class="summary-card high">
        <h3 style="color: #f39c12;">${high}</h3>
        <span>High Severity</span>
      </div>
      <div class="summary-card medium">
        <h3 style="color: #f1c40f;">${medium}</h3>
        <span>Medium Severity</span>
      </div>
      <div class="summary-card low">
        <h3 style="color: #3498db;">${low}</h3>
        <span>Low Severity</span>
      </div>
    </div>

    <div class="section">
      <h2>Package Details</h2>
      ${this.renderPackages(results)}
    </div>
  </div>

  <footer>
    <p>Generated by SupplyChain Sentry v0.1.0</p>
    <p>Scan completed at ${this.escapeHtml(now.toISOString())}</p>
  </footer>
</body>
</html>`;

    return html;
  }

  private renderPackages(results: ScanResult[]): string {
    return results.map(result => {
      const grade = getScoreGrade(result.reputationScore.total);
      const scoreClass = this.getScoreClass(grade);
      
      const issuesHtml = result.issues.length > 0 
        ? `<div class="issues-list">${result.issues.map(issue => this.renderIssue(issue)).join('')}</div>`
        : '<p style="color: #27ae60; margin-top: 10px;">No issues detected</p>';

      return `
      <div class="package-item">
        <div class="package-header">
          <div>
            <span class="package-name">${this.escapeHtml(result.packageName)}</span>
            <span class="package-version">@${this.escapeHtml(result.packageVersion)}</span>
          </div>
          <span class="score-badge ${scoreClass}">${grade} (${result.reputationScore.total}/100)</span>
        </div>
        ${issuesHtml}
      </div>`;
    }).join('');
  }

  private renderIssue(issue: RuleResult): string {
    const severityClass = `severity-${issue.severity}`;
    const itemClass = `issue-item ${issue.severity}`;
    
    return `
    <div class="${itemClass}">
      <div class="issue-header">
        <span class="severity-badge ${severityClass}">${issue.severity}</span>
        <span style="font-weight: 600; color: #666;">[${this.escapeHtml(issue.ruleId)}]</span>
      </div>
      <p class="issue-message">${this.escapeHtml(issue.message)}</p>
      ${issue.evidence ? `<div class="issue-evidence">${this.escapeHtml(issue.evidence)}</div>` : ''}
      ${issue.recommendation ? `<div class="issue-recommendation"><span class="recommendation-label">Recommendation:</span> ${this.escapeHtml(issue.recommendation)}</div>` : ''}
    </div>`;
  }

  private escapeHtml(text: string): string {
    return text
      .replace(/&/g, AMP)
      .replace(/</g, LT)
      .replace(/>/g, GT)
      .replace(/"/g, QUOT)
      .replace(/'/g, APOS);
  }

  private getScoreClass(grade: string): string {
    switch (grade) {
      case 'A+': return 'score-a-plus';
      case 'A': return 'score-a';
      case 'B': return 'score-b';
      case 'C': return 'score-c';
      case 'D': return 'score-d';
      default: return 'score-f';
    }
  }
}
