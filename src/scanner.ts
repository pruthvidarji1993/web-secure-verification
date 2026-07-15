import * as fs from 'fs';
import * as path from 'path';
import { Report, ScanOptions, ScanResult, Severity } from './types';
import { loadIgnoreConfig, shouldIgnoreIssue } from './ignore';
import { runNpmAuditScanner } from './scanners/npm-audit';
import { runOutdatedScanner } from './scanners/outdated';
import { runDeprecatedScanner } from './scanners/deprecated';
import { runSecretsScanner } from './scanners/secrets';
import { runCodeSecurityScanner } from './scanners/code-security';
import { runNextjsScanner } from './scanners/nextjs';
import { runLicenseScanner } from './scanners/license';
import { runSupplyChainScanner } from './scanners/supply-chain';
import { runRscBoundaryScanner } from './scanners/rsc-boundary';
import { runHydrationScanner } from './scanners/hydration';
import { runBundleScanner } from './scanners/bundle';
import { runSourceMapsScanner } from './scanners/source-maps';

const SEVERITY_LEVELS: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

function meetsMinSeverity(issueSeverity: Severity, minSeverity: Severity): boolean {
  return SEVERITY_LEVELS[issueSeverity] >= SEVERITY_LEVELS[minSeverity];
}

function getProjectName(projectPath: string): string {
  const packageJsonPath = path.join(projectPath, 'package.json');
  if (fs.existsSync(packageJsonPath)) {
    try {
      const pkg = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
      if (pkg.name) return pkg.name;
    } catch {
      // fall through
    }
  }
  return path.basename(projectPath);
}

type ScannerFn = (projectPath: string) => Promise<ScanResult>;

const ALL_SCANNERS: Record<string, ScannerFn> = {
  'npm-audit': runNpmAuditScanner,
  outdated: runOutdatedScanner,
  deprecated: runDeprecatedScanner,
  secrets: runSecretsScanner,
  'code-security': runCodeSecurityScanner,
  nextjs: runNextjsScanner,
  license: runLicenseScanner,
  'supply-chain': runSupplyChainScanner,
  'rsc-boundary': runRscBoundaryScanner,
  hydration: runHydrationScanner,
  bundle: runBundleScanner,
  'source-maps': runSourceMapsScanner,
};

export { ALL_SCANNERS };

export async function runScan(options: ScanOptions): Promise<Report> {
  const startTime = Date.now();
  const projectPath = path.resolve(options.path);

  if (!fs.existsSync(projectPath)) {
    throw new Error(`Project path does not exist: ${projectPath}`);
  }

  const projectName = getProjectName(projectPath);
  const ignoreConfig = loadIgnoreConfig(projectPath, options.ignoreFile);

  const skipSet = new Set([
    ...options.skip.map((s) => s.toLowerCase().trim()),
    ...Array.from(ignoreConfig.ignoredScanners),
  ]);

  const scannersToRun = Object.entries(ALL_SCANNERS).filter(
    ([name]) => !skipSet.has(name)
  );

  const scannerPromises = scannersToRun.map(([name, scannerFn]) =>
    scannerFn(projectPath).catch(
      (err): ScanResult => ({
        scanner: name,
        issues: [],
        duration: 0,
        error: err instanceof Error ? err.message : String(err),
      })
    )
  );

  const settledResults = await Promise.allSettled(scannerPromises);

  const results: ScanResult[] = settledResults.map((settled, index) => {
    const scannerName = scannersToRun[index][0];
    if (settled.status === 'fulfilled') {
      const filteredIssues = settled.value.issues.filter(
        (issue) =>
          meetsMinSeverity(issue.severity, options.severity) &&
          !shouldIgnoreIssue(issue, ignoreConfig)
      );
      return { ...settled.value, issues: filteredIssues };
    } else {
      return {
        scanner: scannerName,
        issues: [],
        duration: 0,
        error: settled.reason instanceof Error ? settled.reason.message : String(settled.reason),
      };
    }
  });

  const summary = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };
  for (const result of results) {
    for (const issue of result.issues) {
      summary[issue.severity]++;
      summary.total++;
    }
  }

  return {
    projectPath,
    projectName,
    scannedAt: new Date().toISOString(),
    duration: Date.now() - startTime,
    summary,
    results,
  };
}
