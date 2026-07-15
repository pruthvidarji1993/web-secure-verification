import { execSync } from 'child_process';
import { Issue, ScanResult, Severity } from '../types';

interface OutdatedPackage {
  current: string;
  wanted: string;
  latest: string;
  location?: string;
  dependent?: string;
}

function classifyUpdate(current: string, latest: string): Severity {
  if (!current || current === 'MISSING' || !latest) return 'medium';

  const currentParts = current.replace(/[^0-9.]/g, '').split('.').map(Number);
  const latestParts = latest.replace(/[^0-9.]/g, '').split('.').map(Number);

  if (currentParts.length < 3 || latestParts.length < 3) return 'medium';

  if (latestParts[0] > currentParts[0]) return 'high';
  if (latestParts[1] > currentParts[1]) return 'medium';
  if (latestParts[2] > currentParts[2]) return 'low';

  return 'info';
}

export async function runOutdatedScanner(projectPath: string): Promise<ScanResult> {
  const startTime = Date.now();
  const issues: Issue[] = [];

  try {
    let rawOutput: string;
    try {
      rawOutput = execSync('npm outdated --json', {
        cwd: projectPath,
        encoding: 'utf8',
        stdio: ['pipe', 'pipe', 'pipe'],
        timeout: 60000,
      });
    } catch (err: unknown) {
      // npm outdated exits with code 1 when outdated packages are found
      const execError = err as { stdout?: string; stderr?: string; message?: string };
      if (execError.stdout) {
        rawOutput = execError.stdout;
      } else {
        throw new Error(`npm outdated failed: ${execError.message || String(err)}`);
      }
    }

    if (!rawOutput || rawOutput.trim() === '') {
      return {
        scanner: 'outdated',
        issues: [],
        duration: Date.now() - startTime,
      };
    }

    let outdatedData: Record<string, OutdatedPackage>;
    try {
      outdatedData = JSON.parse(rawOutput);
    } catch {
      throw new Error('Failed to parse npm outdated output as JSON');
    }

    for (const [pkgName, info] of Object.entries(outdatedData)) {
      const severity = classifyUpdate(info.current, info.latest);

      let updateType = 'patch';
      if (severity === 'high') updateType = 'major';
      else if (severity === 'medium') updateType = 'minor';

      issues.push({
        id: `outdated-${pkgName}`,
        title: `Outdated package: ${pkgName}`,
        description: `${pkgName} is outdated. Current: ${info.current}, Wanted: ${info.wanted}, Latest: ${info.latest}. This is a ${updateType} version update.`,
        severity,
        scanner: 'outdated',
        fix: `Run: npm install ${pkgName}@${info.latest}`,
        references: [`https://www.npmjs.com/package/${pkgName}`],
      });
    }
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      scanner: 'outdated',
      issues: [],
      duration: Date.now() - startTime,
      error: message,
    };
  }

  return {
    scanner: 'outdated',
    issues,
    duration: Date.now() - startTime,
  };
}
