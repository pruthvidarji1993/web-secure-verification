import * as fs from 'fs';
import { Report, Issue, Severity } from '../types';

const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

const SEVERITY_COLORS: Record<Severity, { bg: string; text: string; border: string; badge: string }> = {
  critical: { bg: '#fee2e2', text: '#991b1b', border: '#f87171', badge: '#dc2626' },
  high: { bg: '#ffedd5', text: '#9a3412', border: '#fb923c', badge: '#ea580c' },
  medium: { bg: '#fef9c3', text: '#854d0e', border: '#facc15', badge: '#ca8a04' },
  low: { bg: '#dbeafe', text: '#1e40af', border: '#60a5fa', badge: '#2563eb' },
  info: { bg: '#f3f4f6', text: '#374151', border: '#9ca3af', badge: '#6b7280' },
};

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;')
    .replace(/\n/g, '<br>');
}

function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

function renderIssueCard(issue: Issue): string {
  const colors = SEVERITY_COLORS[issue.severity];
  const location = issue.file
    ? `<span class="issue-location">${escapeHtml(issue.file)}${issue.line ? `:${issue.line}` : ''}</span>`
    : '';

  const references = issue.references && issue.references.length > 0
    ? `<div class="issue-refs"><strong>References:</strong> ${issue.references.map(r => `<a href="${escapeHtml(r)}" target="_blank" rel="noopener noreferrer">${escapeHtml(r)}</a>`).join(', ')}</div>`
    : '';

  const fix = issue.fix
    ? `<div class="issue-fix"><strong>Fix:</strong> ${escapeHtml(issue.fix)}</div>`
    : '';

  return `
    <div class="issue-card" style="border-left-color: ${colors.border}; background: ${colors.bg}">
      <div class="issue-header">
        <span class="severity-badge" style="background: ${colors.badge}">${issue.severity.toUpperCase()}</span>
        <span class="issue-title">${escapeHtml(issue.title)}</span>
        ${location}
      </div>
      <div class="issue-body">
        <p class="issue-description">${escapeHtml(issue.description)}</p>
        ${fix}
        ${references}
        <div class="issue-meta">
          <span>Scanner: <code>${escapeHtml(issue.scanner)}</code></span>
          <span>ID: <code>${escapeHtml(issue.id)}</code></span>
        </div>
      </div>
    </div>
  `;
}

function renderScannerTable(report: Report): string {
  const rows = report.results.map((r) => {
    const status = r.error
      ? '<span class="status-error">⚠ Error</span>'
      : r.issues.length === 0
      ? '<span class="status-clean">✓ Clean</span>'
      : `<span class="status-issues">✗ ${r.issues.length} issues</span>`;

    return `<tr>
      <td>${escapeHtml(r.scanner)}</td>
      <td>${r.issues.length}</td>
      <td>${formatDuration(r.duration)}</td>
      <td>${status}</td>
    </tr>`;
  });

  return `<table class="scanner-table">
    <thead>
      <tr><th>Scanner</th><th>Issues</th><th>Duration</th><th>Status</th></tr>
    </thead>
    <tbody>${rows.join('')}</tbody>
  </table>`;
}

function renderSeveritySections(report: Report): string {
  const allIssues: Issue[] = report.results.flatMap((r) => r.issues);
  if (allIssues.length === 0) {
    return '<div class="no-issues">✓ No security issues found!</div>';
  }

  const sections: string[] = [];

  for (const severity of SEVERITY_ORDER) {
    const sevIssues = allIssues.filter((i) => i.severity === severity);
    if (sevIssues.length === 0) continue;

    const colors = SEVERITY_COLORS[severity];
    const sectionId = `section-${severity}`;

    sections.push(`
      <details class="severity-section" open>
        <summary class="severity-summary" style="background: ${colors.badge}">
          <span>${severity.toUpperCase()}</span>
          <span class="issue-count">${sevIssues.length} issue${sevIssues.length > 1 ? 's' : ''}</span>
        </summary>
        <div class="issues-list">
          ${sevIssues.map(renderIssueCard).join('')}
        </div>
      </details>
    `);
  }

  return sections.join('');
}

export function renderHtmlReport(report: Report, outputPath?: string): string {
  const { summary } = report;
  const verdictClass =
    summary.critical > 0 || summary.high > 0
      ? 'verdict-fail'
      : summary.medium > 0 || summary.low > 0
      ? 'verdict-warn'
      : 'verdict-pass';

  const verdictText =
    summary.critical > 0 || summary.high > 0
      ? '✗ SCAN FAILED — Critical or high severity issues must be addressed'
      : summary.medium > 0 || summary.low > 0
      ? '⚠ SCAN PASSED WITH WARNINGS — Issues found that should be reviewed'
      : '✓ SCAN PASSED — No critical issues found';

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Security Scan Report — ${escapeHtml(report.projectName)}</title>
  <style>
    :root {
      --bg-primary: #0f172a;
      --bg-secondary: #1e293b;
      --bg-card: #1e293b;
      --text-primary: #f1f5f9;
      --text-secondary: #94a3b8;
      --text-muted: #64748b;
      --border: #334155;
      --accent: #3b82f6;
      --success: #22c55e;
      --warning: #f59e0b;
      --danger: #ef4444;
      --radius: 8px;
    }

    @media (prefers-color-scheme: light) {
      :root {
        --bg-primary: #f8fafc;
        --bg-secondary: #ffffff;
        --bg-card: #ffffff;
        --text-primary: #0f172a;
        --text-secondary: #475569;
        --text-muted: #94a3b8;
        --border: #e2e8f0;
        --accent: #2563eb;
      }
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
      background: var(--bg-primary);
      color: var(--text-primary);
      line-height: 1.6;
      font-size: 14px;
    }

    .container {
      max-width: 1200px;
      margin: 0 auto;
      padding: 24px;
    }

    .header {
      background: linear-gradient(135deg, #1a237e 0%, #0d47a1 50%, #1565c0 100%);
      color: white;
      padding: 40px;
      border-radius: var(--radius);
      margin-bottom: 24px;
    }

    .header h1 { font-size: 28px; margin-bottom: 8px; }
    .header .subtitle { opacity: 0.8; font-size: 14px; }

    .meta-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 12px;
      margin-top: 20px;
    }

    .meta-item {
      background: rgba(255,255,255,0.1);
      padding: 12px;
      border-radius: 6px;
    }

    .meta-item .label { font-size: 11px; opacity: 0.7; text-transform: uppercase; letter-spacing: 0.5px; }
    .meta-item .value { font-size: 14px; font-weight: 600; margin-top: 4px; word-break: break-all; }

    .summary-cards {
      display: grid;
      grid-template-columns: repeat(5, 1fr);
      gap: 12px;
      margin-bottom: 24px;
    }

    @media (max-width: 600px) {
      .summary-cards { grid-template-columns: repeat(3, 1fr); }
    }

    .summary-card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 20px 16px;
      text-align: center;
      position: relative;
      overflow: hidden;
    }

    .summary-card::before {
      content: '';
      position: absolute;
      top: 0; left: 0; right: 0;
      height: 4px;
    }

    .summary-card.critical::before { background: #dc2626; }
    .summary-card.high::before { background: #ea580c; }
    .summary-card.medium::before { background: #ca8a04; }
    .summary-card.low::before { background: #2563eb; }
    .summary-card.info::before { background: #6b7280; }

    .summary-card .count {
      font-size: 36px;
      font-weight: 700;
      line-height: 1;
    }

    .summary-card.critical .count { color: #dc2626; }
    .summary-card.high .count { color: #ea580c; }
    .summary-card.medium .count { color: #ca8a04; }
    .summary-card.low .count { color: #2563eb; }
    .summary-card.info .count { color: #6b7280; }

    .summary-card .label {
      font-size: 12px;
      color: var(--text-secondary);
      margin-top: 8px;
      font-weight: 500;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

    .verdict {
      padding: 16px 20px;
      border-radius: var(--radius);
      margin-bottom: 24px;
      font-weight: 600;
      font-size: 15px;
    }

    .verdict-pass { background: #14532d; color: #86efac; border: 1px solid #166534; }
    .verdict-warn { background: #451a03; color: #fde68a; border: 1px solid #78350f; }
    .verdict-fail { background: #450a0a; color: #fca5a5; border: 1px solid #7f1d1d; }

    @media (prefers-color-scheme: light) {
      .verdict-pass { background: #f0fdf4; color: #166534; border-color: #86efac; }
      .verdict-warn { background: #fffbeb; color: #92400e; border-color: #fcd34d; }
      .verdict-fail { background: #fff1f2; color: #9f1239; border-color: #fca5a5; }
    }

    .section-title {
      font-size: 18px;
      font-weight: 700;
      margin-bottom: 16px;
      padding-bottom: 8px;
      border-bottom: 2px solid var(--border);
    }

    .scanner-table {
      width: 100%;
      border-collapse: collapse;
      background: var(--bg-card);
      border-radius: var(--radius);
      overflow: hidden;
      margin-bottom: 24px;
      border: 1px solid var(--border);
    }

    .scanner-table th {
      background: var(--bg-secondary);
      padding: 12px 16px;
      text-align: left;
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      color: var(--text-secondary);
    }

    .scanner-table td {
      padding: 10px 16px;
      border-top: 1px solid var(--border);
      color: var(--text-primary);
    }

    .status-clean { color: #22c55e; }
    .status-issues { color: #ef4444; }
    .status-error { color: #f59e0b; }

    .severity-section {
      margin-bottom: 16px;
      border: 1px solid var(--border);
      border-radius: var(--radius);
      overflow: hidden;
    }

    .severity-summary {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 14px 20px;
      cursor: pointer;
      color: white;
      font-weight: 700;
      font-size: 15px;
      list-style: none;
      user-select: none;
    }

    .severity-summary::-webkit-details-marker { display: none; }
    .severity-summary::before { content: '▸'; margin-right: 8px; transition: transform 0.2s; }
    details[open] .severity-summary::before { transform: rotate(90deg); }

    .issue-count {
      font-size: 13px;
      opacity: 0.9;
      font-weight: 500;
    }

    .issues-list { padding: 16px; background: var(--bg-primary); }

    .issue-card {
      border: 1px solid var(--border);
      border-left: 4px solid;
      border-radius: var(--radius);
      margin-bottom: 12px;
      overflow: hidden;
    }

    .issue-header {
      display: flex;
      align-items: center;
      gap: 10px;
      padding: 12px 16px;
      flex-wrap: wrap;
    }

    .severity-badge {
      font-size: 10px;
      font-weight: 700;
      padding: 2px 8px;
      border-radius: 4px;
      color: white;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      white-space: nowrap;
    }

    .issue-title {
      font-weight: 600;
      font-size: 14px;
      flex: 1;
    }

    .issue-location {
      font-family: 'Courier New', monospace;
      font-size: 12px;
      color: var(--text-secondary);
      background: var(--bg-secondary);
      padding: 2px 6px;
      border-radius: 4px;
    }

    .issue-body {
      padding: 0 16px 14px;
    }

    .issue-description {
      color: var(--text-secondary);
      font-size: 13px;
      margin-bottom: 8px;
    }

    .issue-fix {
      background: var(--bg-secondary);
      border: 1px solid var(--border);
      border-radius: 4px;
      padding: 10px 12px;
      font-size: 13px;
      margin-bottom: 8px;
    }

    .issue-refs {
      font-size: 12px;
      color: var(--text-muted);
      margin-bottom: 8px;
    }

    .issue-refs a {
      color: var(--accent);
      text-decoration: none;
    }

    .issue-refs a:hover { text-decoration: underline; }

    .issue-meta {
      display: flex;
      gap: 16px;
      font-size: 11px;
      color: var(--text-muted);
    }

    .issue-meta code {
      font-family: 'Courier New', monospace;
      background: var(--bg-secondary);
      padding: 1px 4px;
      border-radius: 3px;
    }

    .no-issues {
      text-align: center;
      padding: 40px;
      color: #22c55e;
      font-size: 20px;
      font-weight: 600;
    }

    .footer {
      text-align: center;
      color: var(--text-muted);
      font-size: 12px;
      margin-top: 40px;
      padding-top: 20px;
      border-top: 1px solid var(--border);
    }

    code { font-family: 'Courier New', monospace; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>🔒 Security Scan Report</h1>
      <div class="subtitle">web-secure-verification</div>
      <div class="meta-grid">
        <div class="meta-item">
          <div class="label">Project</div>
          <div class="value">${escapeHtml(report.projectName)}</div>
        </div>
        <div class="meta-item">
          <div class="label">Path</div>
          <div class="value">${escapeHtml(report.projectPath)}</div>
        </div>
        <div class="meta-item">
          <div class="label">Scanned At</div>
          <div class="value">${new Date(report.scannedAt).toLocaleString()}</div>
        </div>
        <div class="meta-item">
          <div class="label">Duration</div>
          <div class="value">${formatDuration(report.duration)}</div>
        </div>
        <div class="meta-item">
          <div class="label">Total Issues</div>
          <div class="value">${report.summary.total}</div>
        </div>
      </div>
    </div>

    <div class="summary-cards">
      <div class="summary-card critical">
        <div class="count">${report.summary.critical}</div>
        <div class="label">Critical</div>
      </div>
      <div class="summary-card high">
        <div class="count">${report.summary.high}</div>
        <div class="label">High</div>
      </div>
      <div class="summary-card medium">
        <div class="count">${report.summary.medium}</div>
        <div class="label">Medium</div>
      </div>
      <div class="summary-card low">
        <div class="count">${report.summary.low}</div>
        <div class="label">Low</div>
      </div>
      <div class="summary-card info">
        <div class="count">${report.summary.info}</div>
        <div class="label">Info</div>
      </div>
    </div>

    <div class="verdict ${verdictClass}">${verdictText}</div>

    <div class="section-title">Scanner Results</div>
    ${renderScannerTable(report)}

    <div class="section-title">Security Issues</div>
    ${renderSeveritySections(report)}

    <div class="footer">
      Generated by <a href="https://www.npmjs.com/package/web-secure-verification" style="color: var(--accent)">web-secure-verification</a>
      on ${new Date(report.scannedAt).toISOString()}
    </div>
  </div>
</body>
</html>`;

  if (outputPath) {
    fs.writeFileSync(outputPath, html, 'utf8');
  }

  return html;
}
