import chalk from 'chalk';
import { Report, Issue, Severity } from '../types';

const SEVERITY_COLORS: Record<Severity, chalk.Chalk> = {
  critical: chalk.bgRed.white.bold,
  high: chalk.red.bold,
  medium: chalk.yellow.bold,
  low: chalk.cyan,
  info: chalk.gray,
};

const SEVERITY_BADGES: Record<Severity, string> = {
  critical: chalk.bgRed.white.bold(' CRITICAL '),
  high: chalk.bgYellow.black.bold('  HIGH   '),
  medium: chalk.bgCyanBright.black.bold(' MEDIUM  '),
  low: chalk.bgBlue.white.bold('   LOW   '),
  info: chalk.bgGray.white.bold('  INFO   '),
};

const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

function severityColor(severity: Severity): chalk.Chalk {
  return SEVERITY_COLORS[severity] || chalk.white;
}

function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

function printSeparator(char = '─', width = 80): void {
  console.log(chalk.gray(char.repeat(width)));
}

function printHeader(report: Report): void {
  console.log('');
  console.log(chalk.bold.blue('╔══════════════════════════════════════════════════════════════════════════════╗'));
  console.log(chalk.bold.blue('║') + chalk.bold.white('          🔒  Web Secure Verification — Security Scan Report              ') + chalk.bold.blue('║'));
  console.log(chalk.bold.blue('╚══════════════════════════════════════════════════════════════════════════════╝'));
  console.log('');
  console.log(chalk.gray('  Project:  ') + chalk.white(report.projectName));
  console.log(chalk.gray('  Path:     ') + chalk.white(report.projectPath));
  console.log(chalk.gray('  Scanned:  ') + chalk.white(new Date(report.scannedAt).toLocaleString()));
  console.log(chalk.gray('  Duration: ') + chalk.white(formatDuration(report.duration)));
  console.log('');
}

function printSummary(report: Report): void {
  printSeparator();
  console.log(chalk.bold.white('  SUMMARY'));
  printSeparator();
  console.log('');

  const { summary } = report;
  const total = summary.total;

  if (total === 0) {
    console.log(chalk.green.bold('  ✓ No security issues found!'));
    console.log('');
    return;
  }

  // Summary table
  const cols = [
    { label: 'Critical', count: summary.critical, color: chalk.red.bold },
    { label: 'High', count: summary.high, color: chalk.yellow.bold },
    { label: 'Medium', count: summary.medium, color: chalk.cyan.bold },
    { label: 'Low', count: summary.low, color: chalk.blue.bold },
    { label: 'Info', count: summary.info, color: chalk.gray },
  ];

  console.log('  ' + cols.map((c) => c.color(c.label.padEnd(10))).join('  '));
  console.log('  ' + cols.map((c) => c.color(String(c.count).padEnd(10))).join('  '));
  console.log('');
  console.log(chalk.gray('  Total issues: ') + chalk.bold.white(String(total)));
  console.log('');
}

function printIssue(issue: Issue, index: number): void {
  const badge = SEVERITY_BADGES[issue.severity];
  const color = severityColor(issue.severity);

  console.log(`  ${badge}  ${color(issue.title)}`);
  console.log(chalk.gray(`         ID: ${issue.id}`));
  if (issue.file) {
    const location = issue.line ? `${issue.file}:${issue.line}` : issue.file;
    console.log(chalk.gray('         File: ') + chalk.white(location));
  }
  console.log(chalk.gray('         Description: ') + chalk.white(issue.description.split('\n')[0]));
  if (issue.fix) {
    console.log(chalk.gray('         Fix: ') + chalk.green(issue.fix.split('\n')[0]));
  }
  if (issue.references && issue.references.length > 0) {
    console.log(chalk.gray('         Reference: ') + chalk.blue.underline(issue.references[0]));
  }
  console.log('');
}

function printScanResults(report: Report): void {
  const allIssues: Issue[] = [];
  for (const result of report.results) {
    allIssues.push(...result.issues);
  }

  if (allIssues.length === 0) return;

  // Group by severity
  for (const severity of SEVERITY_ORDER) {
    const sevIssues = allIssues.filter((i) => i.severity === severity);
    if (sevIssues.length === 0) continue;

    printSeparator();
    const color = severityColor(severity);
    console.log(color(`  ${severity.toUpperCase()} (${sevIssues.length} issue${sevIssues.length > 1 ? 's' : ''})`));
    printSeparator();
    console.log('');

    sevIssues.forEach((issue, idx) => printIssue(issue, idx));
  }
}

function printScannerErrors(report: Report): void {
  const errors = report.results.filter((r) => r.error);
  if (errors.length === 0) return;

  printSeparator('─');
  console.log(chalk.yellow.bold('  SCANNER WARNINGS'));
  printSeparator('─');
  console.log('');

  for (const result of errors) {
    console.log(
      chalk.yellow('  ⚠') +
        chalk.white(` Scanner "${result.scanner}" encountered an error: `) +
        chalk.gray(result.error || 'Unknown error')
    );
  }
  console.log('');
}

function printScannerSummary(report: Report): void {
  printSeparator();
  console.log(chalk.bold.white('  SCANNER DETAILS'));
  printSeparator();
  console.log('');

  for (const result of report.results) {
    const issueCount = result.issues.length;
    const status = result.error
      ? chalk.yellow('⚠ ERROR')
      : issueCount === 0
      ? chalk.green('✓ CLEAN')
      : chalk.red(`✗ ${issueCount} issue${issueCount > 1 ? 's' : ''}`);

    const duration = chalk.gray(`(${formatDuration(result.duration)})`);
    console.log(`  ${status.padEnd(30)} ${chalk.white(result.scanner)} ${duration}`);
  }
  console.log('');
}

export function renderConsoleReport(report: Report): void {
  printHeader(report);
  printSummary(report);
  printScanResults(report);
  printScannerErrors(report);
  printScannerSummary(report);

  // Final verdict
  printSeparator('═');
  const { summary } = report;
  if (summary.critical > 0 || summary.high > 0) {
    console.log(chalk.red.bold('  ✗ SCAN FAILED — Critical or high severity issues found'));
    console.log(chalk.red(`    ${summary.critical} critical, ${summary.high} high severity issues must be addressed`));
  } else if (summary.medium > 0 || summary.low > 0) {
    console.log(chalk.yellow.bold('  ⚠ SCAN PASSED WITH WARNINGS — Medium or low severity issues found'));
    console.log(chalk.yellow(`    ${summary.medium} medium, ${summary.low} low severity issues should be reviewed`));
  } else {
    console.log(chalk.green.bold('  ✓ SCAN PASSED — No critical issues found'));
  }
  printSeparator('═');
  console.log('');
}
