#!/usr/bin/env node

import * as fs from 'fs';
import * as path from 'path';
import * as readline from 'readline';
import * as child_process from 'child_process';
import { Command } from 'commander';
import { runScan, ALL_SCANNERS } from './scanner';
import { renderConsoleReport } from './reporters/console';
import { renderJsonReport } from './reporters/json';
import { renderHtmlReport } from './reporters/html';
import { renderMarkdownReport } from './reporters/markdown';
import { renderSarifReport } from './reporters/sarif';
import { ScanOptions, Severity, WsvConfig, Issue } from './types';

const VALID_FORMATS = ['console', 'json', 'html', 'markdown', 'sarif'] as const;
const VALID_SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
const SEVERITY_LEVELS: Record<Severity, number> = {
  critical: 5, high: 4, medium: 3, low: 2, info: 1,
};

function loadConfig(configPath: string): Partial<WsvConfig> {
  try {
    return JSON.parse(fs.readFileSync(configPath, 'utf8')) as WsvConfig;
  } catch (err) {
    console.error(`Warning: Failed to load config file "${configPath}":`, err instanceof Error ? err.message : err);
    return {};
  }
}

function findConfig(startPath: string): string | null {
  const candidates = ['.wsvrc.json', '.wsvrc', 'wsv.config.json'];
  let currentDir = startPath;
  for (let i = 0; i < 5; i++) {
    for (const candidate of candidates) {
      const fullPath = path.join(currentDir, candidate);
      if (fs.existsSync(fullPath)) return fullPath;
    }
    const parent = path.dirname(currentDir);
    if (parent === currentDir) break;
    currentDir = parent;
  }
  return null;
}

function shouldFailBuild(summary: Record<string, number>, failOn: Severity[]): boolean {
  return failOn.some((sev) => (summary[sev] ?? 0) > 0);
}

async function runInteractiveFix(issues: Issue[], projectPath: string): Promise<void> {
  const fixable = issues.filter((i) => i.fixable && i.fixCommand);
  if (fixable.length === 0) {
    console.log('\nNo auto-fixable issues found.');
    return;
  }

  console.log(`\n${'─'.repeat(76)}`);
  console.log(`  AUTO-FIX: ${fixable.length} fixable issue(s) found`);
  console.log(`${'─'.repeat(76)}\n`);

  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const question = (prompt: string): Promise<string> =>
    new Promise((resolve) => rl.question(prompt, resolve));

  // Group by unique fixCommand to avoid running duplicates
  const seen = new Set<string>();
  const uniqueFixes: Issue[] = [];
  for (const issue of fixable) {
    if (!seen.has(issue.fixCommand!)) {
      seen.add(issue.fixCommand!);
      uniqueFixes.push(issue);
    }
  }

  let fixedCount = 0;
  for (const issue of uniqueFixes) {
    console.log(`  [${issue.severity.toUpperCase()}] ${issue.title}`);
    if (issue.file) console.log(`         File: ${issue.file}${issue.line ? `:${issue.line}` : ''}`);
    console.log(`         Fix:  ${issue.fixCommand}`);

    const answer = await question('  Apply fix? [y/N/a(ll)/q(uit)] ').then((a) => a.trim().toLowerCase());

    if (answer === 'q') {
      console.log('  Aborted.');
      break;
    }

    if (answer === 'y' || answer === 'a') {
      try {
        console.log(`  Running: ${issue.fixCommand}`);
        child_process.execSync(issue.fixCommand!, { cwd: projectPath, stdio: 'inherit' });
        console.log('  ✓ Done\n');
        fixedCount++;
      } catch {
        console.log('  ✗ Failed\n');
      }

      if (answer === 'a') {
        // Apply all remaining without asking
        for (const remaining of uniqueFixes.slice(uniqueFixes.indexOf(issue) + 1)) {
          try {
            console.log(`  Running: ${remaining.fixCommand}`);
            child_process.execSync(remaining.fixCommand!, { cwd: projectPath, stdio: 'inherit' });
            console.log('  ✓ Done\n');
            fixedCount++;
          } catch {
            console.log('  ✗ Failed\n');
          }
        }
        break;
      }
    } else {
      console.log('  Skipped\n');
    }
  }

  rl.close();
  console.log(`\n  ${fixedCount} fix(es) applied.`);
}

const program = new Command();

program
  .name('web-secure-verify')
  .description('Security scanning CLI tool for React and Next.js projects')
  .version('1.0.0');

program
  .command('scan')
  .description('Scan a project for security vulnerabilities')
  .option('-p, --path <path>', 'Project path to scan', process.cwd())
  .option('-f, --format <fmt>', 'Output format: console|json|html|markdown|sarif', 'console')
  .option('-o, --output <file>', 'Output file path (for json/html/markdown/sarif formats)')
  .option('-s, --severity <lvl>', 'Minimum severity level: info|low|medium|high|critical', 'low')
  .option('--skip <scanners>', 'Comma-separated list of scanners to skip')
  .option('--fail-on <levels>', 'Comma-separated severity levels that fail the build (e.g. critical,high)')
  .option('--fix', 'Interactively apply auto-fixes after scan')
  .option('--ignore-file <file>', 'Path to ignore file (default: .scannerignore)')
  .option('-c, --config <file>', 'Config file path (.wsvrc.json)')
  .option('--list-scanners', 'List all available scanners and exit')
  .action(async (cmdOptions: {
    path: string;
    format: string;
    output?: string;
    severity: string;
    skip?: string;
    failOn?: string;
    fix?: boolean;
    ignoreFile?: string;
    config?: string;
    listScanners?: boolean;
  }) => {
    if (cmdOptions.listScanners) {
      console.log('\nAvailable scanners:\n');
      for (const name of Object.keys(ALL_SCANNERS)) {
        console.log(`  ${name}`);
      }
      console.log();
      process.exit(0);
    }

    const projectPath = path.resolve(cmdOptions.path);

    let fileConfig: Partial<WsvConfig> = {};
    const configPath = cmdOptions.config
      ? path.resolve(cmdOptions.config)
      : findConfig(projectPath);

    if (configPath) {
      fileConfig = loadConfig(configPath);
      if (!cmdOptions.config) console.log(`Using config: ${configPath}`);
    }

    const format = (cmdOptions.format !== 'console'
      ? cmdOptions.format
      : fileConfig.format ?? cmdOptions.format) as ScanOptions['format'];

    const severity = (cmdOptions.severity !== 'low'
      ? cmdOptions.severity
      : fileConfig.severity ?? cmdOptions.severity) as Severity;

    const skipList: string[] = [];
    if (cmdOptions.skip) {
      skipList.push(...cmdOptions.skip.split(',').map((s) => s.trim()));
    } else if (fileConfig.skip) {
      skipList.push(...fileConfig.skip);
    }

    // --fail-on parsing
    let failOn: Severity[] = [];
    if (cmdOptions.failOn) {
      failOn = cmdOptions.failOn.split(',').map((s) => s.trim()) as Severity[];
    } else if (fileConfig.failOn) {
      failOn = fileConfig.failOn;
    } else {
      // Default: fail on critical and high
      failOn = ['critical', 'high'];
    }

    // Validate
    if (!VALID_FORMATS.includes(format as typeof VALID_FORMATS[number])) {
      console.error(`Error: Invalid format "${format}". Valid: ${VALID_FORMATS.join(', ')}`);
      process.exit(1);
    }
    if (!VALID_SEVERITIES.includes(severity)) {
      console.error(`Error: Invalid severity "${severity}". Valid: ${VALID_SEVERITIES.join(', ')}`);
      process.exit(1);
    }
    for (const sev of failOn) {
      if (!VALID_SEVERITIES.includes(sev)) {
        console.error(`Error: Invalid --fail-on level "${sev}". Valid: ${VALID_SEVERITIES.join(', ')}`);
        process.exit(1);
      }
    }

    const options: ScanOptions = {
      path: projectPath,
      format,
      output: cmdOptions.output ?? fileConfig.output,
      severity,
      skip: skipList,
      config: configPath ?? undefined,
      fix: cmdOptions.fix,
      failOn,
      ignoreFile: cmdOptions.ignoreFile,
    };

    try {
      if (format === 'console') {
        console.log(`\nScanning project at: ${projectPath}\n`);
      }

      const report = await runScan(options);
      const output = options.output;

      switch (format) {
        case 'console':
          renderConsoleReport(report);
          break;
        case 'json': {
          const json = renderJsonReport(report, output);
          if (!output) console.log(json);
          else console.log(`JSON report written to: ${output}`);
          break;
        }
        case 'html':
          renderHtmlReport(report, output);
          if (output) console.log(`HTML report written to: ${output}`);
          break;
        case 'markdown': {
          const md = renderMarkdownReport(report, output);
          if (!output) console.log(md);
          else console.log(`Markdown report written to: ${output}`);
          break;
        }
        case 'sarif': {
          const sarif = renderSarifReport(report, output);
          if (!output) console.log(sarif);
          else console.log(`SARIF report written to: ${output}`);
          break;
        }
      }

      // Interactive fix mode
      if (options.fix) {
        const allIssues = report.results.flatMap((r) => r.issues);
        await runInteractiveFix(allIssues, projectPath);
      }

      // Exit code based on --fail-on
      const failed = shouldFailBuild(report.summary, failOn);

      // Show fail-on summary for non-console formats
      if (format !== 'console' && failed) {
        const counts = failOn
          .filter((s) => (report.summary[s] ?? 0) > 0)
          .map((s) => `${report.summary[s]} ${s}`)
          .join(', ');
        console.error(`\nBuild failed: ${counts} severity issue(s) found.`);
      }

      process.exit(failed ? 1 : 0);
    } catch (err: unknown) {
      console.error('\nError during scan:', err instanceof Error ? err.message : String(err));
      process.exit(2);
    }
  });

program
  .command('list-scanners')
  .description('List all available scanners')
  .action(() => {
    console.log('\nAvailable scanners:\n');
    const descriptions: Record<string, string> = {
      'npm-audit': 'CVE vulnerabilities in dependencies (direct + transitive)',
      outdated: 'Outdated packages needing version updates',
      deprecated: 'Packages officially deprecated on the npm registry',
      secrets: 'Hardcoded secrets, API keys, and high-entropy strings',
      'code-security': 'eval(), innerHTML, XSS, injection patterns',
      nextjs: 'Next.js config misconfigurations and security headers',
      license: 'Restrictive or unknown licenses in dependencies',
      'supply-chain': 'Typosquatting, malicious packages, postinstall scripts',
      'rsc-boundary': 'Next.js RSC/client boundary violations',
      hydration: 'React hydration mismatch patterns',
      bundle: 'Bundle size impact (unoptimized imports)',
      'source-maps': 'Exposed source maps in production builds',
    };
    for (const [name, desc] of Object.entries(descriptions)) {
      console.log(`  ${name.padEnd(16)} ${desc}`);
    }
    console.log();
  });

if (process.argv.length === 2) {
  program.help();
}

program.parse(process.argv);
