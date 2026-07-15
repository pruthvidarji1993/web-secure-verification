import * as fs from 'fs';
import * as path from 'path';
import { Issue, ScanResult } from '../types';

interface PackageJson {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
}

interface NpmRegistryLatest {
  deprecated?: string;
  name?: string;
  version?: string;
}

async function fetchPackageInfo(packageName: string): Promise<NpmRegistryLatest | null> {
  try {
    const url = `https://registry.npmjs.org/${encodeURIComponent(packageName)}/latest`;
    const response = await fetch(url, {
      signal: AbortSignal.timeout(10000),
      headers: {
        Accept: 'application/json',
      },
    });

    if (!response.ok) {
      return null;
    }

    const data = (await response.json()) as NpmRegistryLatest;
    return data;
  } catch {
    return null;
  }
}

async function processBatch(
  packages: string[],
  batchSize: number,
  delayMs: number
): Promise<Map<string, string | undefined>> {
  const results = new Map<string, string | undefined>();

  for (let i = 0; i < packages.length; i += batchSize) {
    const batch = packages.slice(i, i + batchSize);

    const batchResults = await Promise.allSettled(
      batch.map(async (pkgName) => {
        const info = await fetchPackageInfo(pkgName);
        return { pkgName, deprecated: info?.deprecated };
      })
    );

    for (const result of batchResults) {
      if (result.status === 'fulfilled') {
        results.set(result.value.pkgName, result.value.deprecated);
      }
    }

    // Rate limiting: wait between batches (except after the last batch)
    if (i + batchSize < packages.length && delayMs > 0) {
      await new Promise((resolve) => setTimeout(resolve, delayMs));
    }
  }

  return results;
}

export async function runDeprecatedScanner(projectPath: string): Promise<ScanResult> {
  const startTime = Date.now();
  const issues: Issue[] = [];

  try {
    const packageJsonPath = path.join(projectPath, 'package.json');

    if (!fs.existsSync(packageJsonPath)) {
      return {
        scanner: 'deprecated',
        issues: [],
        duration: Date.now() - startTime,
        error: 'package.json not found in project path',
      };
    }

    const packageJsonContent = fs.readFileSync(packageJsonPath, 'utf8');
    const packageJson: PackageJson = JSON.parse(packageJsonContent);

    const allDeps: string[] = [
      ...Object.keys(packageJson.dependencies || {}),
      ...Object.keys(packageJson.devDependencies || {}),
      ...Object.keys(packageJson.peerDependencies || {}),
    ];

    // Remove duplicates
    const uniqueDeps = [...new Set(allDeps)];

    if (uniqueDeps.length === 0) {
      return {
        scanner: 'deprecated',
        issues: [],
        duration: Date.now() - startTime,
      };
    }

    // Process in batches of 10 with 500ms delay between batches to respect rate limits
    const results = await processBatch(uniqueDeps, 10, 500);

    for (const [pkgName, deprecated] of results) {
      if (deprecated) {
        issues.push({
          id: `deprecated-${pkgName}`,
          title: `Deprecated package: ${pkgName}`,
          description: `The package "${pkgName}" is deprecated. Message: ${deprecated}`,
          severity: 'medium',
          scanner: 'deprecated',
          fix: 'Find an alternative package or update to a non-deprecated version',
          references: [`https://www.npmjs.com/package/${pkgName}`],
        });
      }
    }
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      scanner: 'deprecated',
      issues: [],
      duration: Date.now() - startTime,
      error: message,
    };
  }

  return {
    scanner: 'deprecated',
    issues,
    duration: Date.now() - startTime,
  };
}
