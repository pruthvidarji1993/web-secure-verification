import { execSync } from 'child_process';
import { Issue, ScanResult, Severity } from '../types';

interface NpmAuditV6Vulnerability {
  title: string;
  severity: string;
  overview: string;
  recommendation?: string;
  url?: string;
  module_name: string;
  findings: Array<{ version: string }>;
  cves?: string[];
}

interface NpmAuditV6Output {
  advisories: Record<string, NpmAuditV6Vulnerability>;
  metadata: {
    vulnerabilities: {
      info: number;
      low: number;
      moderate: number;
      high: number;
      critical: number;
    };
  };
}

interface NpmAuditV7Vulnerability {
  name: string;
  severity: string;
  isDirect: boolean;
  via: Array<
    | string
    | {
        title: string;
        url?: string;
        severity: string;
        range?: string;
      }
  >;
  effects: string[];
  range: string;
  nodes: string[];
  fixAvailable: boolean | { name: string; version: string; isSemVerMajor: boolean };
}

interface NpmAuditV7Output {
  vulnerabilities: Record<string, NpmAuditV7Vulnerability>;
  metadata: {
    vulnerabilities: {
      info: number;
      low: number;
      moderate: number;
      high: number;
      critical: number;
    };
  };
}

function mapSeverity(severity: string): Severity {
  switch (severity.toLowerCase()) {
    case 'critical':
      return 'critical';
    case 'high':
      return 'high';
    case 'moderate':
    case 'medium':
      return 'medium';
    case 'low':
      return 'low';
    default:
      return 'info';
  }
}

function isV7Output(output: unknown): output is NpmAuditV7Output {
  return (
    typeof output === 'object' &&
    output !== null &&
    'vulnerabilities' in output &&
    !('advisories' in output)
  );
}

export async function runNpmAuditScanner(projectPath: string): Promise<ScanResult> {
  const startTime = Date.now();
  const issues: Issue[] = [];

  try {
    let rawOutput: string;
    try {
      rawOutput = execSync('npm audit --json', {
        cwd: projectPath,
        encoding: 'utf8',
        stdio: ['pipe', 'pipe', 'pipe'],
        timeout: 60000,
      });
    } catch (err: unknown) {
      // npm audit exits with non-zero code when vulnerabilities are found
      // We still want to parse the output
      const execError = err as { stdout?: string; stderr?: string; message?: string };
      if (execError.stdout) {
        rawOutput = execError.stdout;
      } else {
        throw new Error(`npm audit failed: ${execError.message || String(err)}`);
      }
    }

    let auditData: unknown;
    try {
      auditData = JSON.parse(rawOutput);
    } catch {
      throw new Error('Failed to parse npm audit output as JSON');
    }

    if (isV7Output(auditData)) {
      // npm v7+ format
      for (const [pkgName, vuln] of Object.entries(auditData.vulnerabilities)) {
        const severity = mapSeverity(vuln.severity);
        const viaObjects = vuln.via.filter(
          (v): v is { title: string; url?: string; severity: string; range?: string } =>
            typeof v === 'object'
        );
        const viaStrings = vuln.via.filter((v): v is string => typeof v === 'string');

        const viaDetails = viaObjects.map((v) => v.title).join(', ');
        const title = viaDetails || `Vulnerability in ${pkgName}`;

        const hasFixAvailable = !!vuln.fixAvailable;
        const fixInfo =
          typeof vuln.fixAvailable === 'object'
            ? `Update to ${vuln.fixAvailable.name}@${vuln.fixAvailable.version}`
            : vuln.fixAvailable
            ? 'Run npm audit fix'
            : 'No fix available';

        const refs = viaObjects
          .map((v) => v.url)
          .filter((url): url is string => !!url);

        const cves = viaObjects
          .flatMap((v) => {
            // CVEs sometimes appear in URL fragments
            const cveMatch = v.url?.match(/(CVE-\d{4}-\d+)/i);
            return cveMatch ? [cveMatch[1]] : [];
          });

        let description = `Package "${pkgName}" has a ${vuln.severity} severity vulnerability. Affected range: ${vuln.range}`;
        if (!vuln.isDirect && viaStrings.length > 0) {
          description += `. This is a transitive (indirect) dependency via: ${viaStrings.join(' > ')}`;
        }

        issues.push({
          id: `npm-audit-${pkgName}-${severity}`,
          title,
          description,
          severity,
          scanner: 'npm-audit',
          fix: fixInfo,
          fixable: hasFixAvailable,
          fixCommand: hasFixAvailable ? 'npm audit fix' : undefined,
          references: refs,
          ruleId: `npm-audit-${severity}`,
          metadata: {
            packageName: pkgName,
            installedVersion: vuln.range,
            cvss: undefined,
            cve: cves.length > 0 ? cves : undefined,
            via: vuln.via,
          },
        });
      }
    } else {
      // npm v6 format
      const v6Data = auditData as NpmAuditV6Output;
      if (v6Data.advisories) {
        for (const [id, advisory] of Object.entries(v6Data.advisories)) {
          const severity = mapSeverity(advisory.severity);
          const version = advisory.findings?.[0]?.version || 'unknown';

          issues.push({
            id: `npm-audit-${id}`,
            title: advisory.title,
            description: `${advisory.overview} Package: ${advisory.module_name}@${version}`,
            severity,
            scanner: 'npm-audit',
            fix: advisory.recommendation || 'Update the package to a non-vulnerable version',
            references: advisory.url ? [advisory.url] : [],
            ruleId: `npm-audit-${severity}`,
            metadata: {
              packageName: advisory.module_name,
              installedVersion: version,
              cvss: undefined,
              cve: advisory.cves && advisory.cves.length > 0 ? advisory.cves : undefined,
              via: undefined,
            },
          });
        }
      }
    }
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      scanner: 'npm-audit',
      issues: [],
      duration: Date.now() - startTime,
      error: message,
    };
  }

  return {
    scanner: 'npm-audit',
    issues,
    duration: Date.now() - startTime,
  };
}
