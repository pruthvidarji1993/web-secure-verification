import * as fs from 'fs';
import * as path from 'path';
import { Issue, ScanResult } from '../types';

const FORBIDDEN_LICENSES = new Set([
  'GPL-3.0',
  'GPL-3.0-only',
  'GPL-3.0-or-later',
  'GPL-2.0',
  'GPL-2.0-only',
  'GPL-2.0-or-later',
  'AGPL-3.0',
  'AGPL-3.0-only',
  'AGPL-3.0-or-later',
  'LGPL-3.0',
  'LGPL-3.0-only',
  'LGPL-3.0-or-later',
  'CC-BY-NC',
  'CC-BY-NC-4.0',
  'CC-BY-NC-SA-4.0',
  'SSPL',
  'SSPL-1.0',
]);

const COPYLEFT_LICENSES = new Set([
  'LGPL-2.1',
  'LGPL-2.1-only',
  'LGPL-2.1-or-later',
  'MPL-2.0',
  'EUPL-1.2',
]);

const PERMISSIVE_LICENSES = new Set([
  'MIT',
  'Apache-2.0',
  'BSD-2-Clause',
  'BSD-3-Clause',
  'ISC',
  '0BSD',
  'CC0-1.0',
  'Unlicense',
  'BlueOak-1.0.0',
  'Python-2.0',
  'PSF-2.0',
  'WTFPL',
  'Artistic-2.0',
  'Zlib',
]);

function normalizeLicense(license: unknown): string {
  if (!license) return 'UNKNOWN';
  if (typeof license === 'string') return license.trim();
  // Handle SPDX expression objects like { type: 'MIT' }
  if (typeof license === 'object' && license !== null) {
    const l = license as Record<string, unknown>;
    if (typeof l['type'] === 'string') return l['type'].trim();
    if (typeof l['name'] === 'string') return l['name'].trim();
  }
  return 'UNKNOWN';
}

function detectLicenseFromText(text: string): string | null {
  if (/GNU GENERAL PUBLIC LICENSE\s+Version 3/i.test(text)) return 'GPL-3.0';
  if (/GNU GENERAL PUBLIC LICENSE\s+Version 2/i.test(text)) return 'GPL-2.0';
  if (/GNU AFFERO GENERAL PUBLIC LICENSE/i.test(text)) return 'AGPL-3.0';
  if (/GNU LESSER GENERAL PUBLIC LICENSE\s+Version 3/i.test(text)) return 'LGPL-3.0';
  if (/GNU LESSER GENERAL PUBLIC LICENSE\s+Version 2\.1/i.test(text)) return 'LGPL-2.1';
  if (/Mozilla Public License\s+Version 2\.0/i.test(text)) return 'MPL-2.0';
  if (/MIT License/i.test(text) || /Permission is hereby granted.*MIT/i.test(text)) return 'MIT';
  if (/Apache License\s+Version 2\.0/i.test(text)) return 'Apache-2.0';
  if (/ISC License/i.test(text)) return 'ISC';
  if (/BSD 2-Clause/i.test(text)) return 'BSD-2-Clause';
  if (/BSD 3-Clause/i.test(text)) return 'BSD-3-Clause';
  return null;
}

function getLicenseForPackage(pkgDir: string): string {
  // Try reading the package.json license field
  const pkgJsonPath = path.join(pkgDir, 'package.json');
  if (fs.existsSync(pkgJsonPath)) {
    try {
      const pkgJson = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));
      if (pkgJson.license) {
        return normalizeLicense(pkgJson.license);
      }
      if (pkgJson.licenses && Array.isArray(pkgJson.licenses) && pkgJson.licenses.length > 0) {
        return normalizeLicense(pkgJson.licenses[0]);
      }
    } catch {
      // fall through to file check
    }
  }

  // Try reading LICENSE files
  const licenseFiles = ['LICENSE', 'LICENSE.md', 'LICENSE.txt', 'LICENCE', 'LICENCE.md'];
  for (const licFile of licenseFiles) {
    const licPath = path.join(pkgDir, licFile);
    if (fs.existsSync(licPath)) {
      try {
        const text = fs.readFileSync(licPath, 'utf8');
        const detected = detectLicenseFromText(text);
        if (detected) return detected;
        return 'UNKNOWN';
      } catch {
        // fall through
      }
    }
  }

  return 'UNKNOWN';
}

export async function runLicenseScanner(projectPath: string): Promise<ScanResult> {
  const startTime = Date.now();
  const issues: Issue[] = [];

  try {
    const packageJsonPath = path.join(projectPath, 'package.json');
    if (!fs.existsSync(packageJsonPath)) {
      return {
        scanner: 'license',
        issues: [],
        duration: Date.now() - startTime,
        error: 'package.json not found',
      };
    }

    let packageJson: {
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
    };
    try {
      packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
    } catch {
      return {
        scanner: 'license',
        issues: [],
        duration: Date.now() - startTime,
        error: 'Failed to parse package.json',
      };
    }

    const allDeps = {
      ...(packageJson.dependencies || {}),
      ...(packageJson.devDependencies || {}),
    };

    const nodeModulesPath = path.join(projectPath, 'node_modules');
    if (!fs.existsSync(nodeModulesPath)) {
      return {
        scanner: 'license',
        issues: [],
        duration: Date.now() - startTime,
        error: 'node_modules directory not found — run npm install first',
      };
    }

    for (const pkgName of Object.keys(allDeps)) {
      const pkgDir = path.join(nodeModulesPath, pkgName);
      if (!fs.existsSync(pkgDir)) continue;

      // Read the installed version from the package's own package.json
      let version = allDeps[pkgName];
      try {
        const installedPkg = JSON.parse(
          fs.readFileSync(path.join(pkgDir, 'package.json'), 'utf8'),
        );
        version = installedPkg.version || version;
      } catch {
        // use semver range from package.json
      }

      const license = getLicenseForPackage(pkgDir);

      if (PERMISSIVE_LICENSES.has(license)) continue;

      if (FORBIDDEN_LICENSES.has(license)) {
        issues.push({
          id: `license-${pkgName}-${license}`,
          title: `Restrictive license: ${pkgName} (${license})`,
          description:
            `The package "${pkgName}" is licensed under ${license}, which is a copyleft license that ` +
            `requires any software that uses it to also be released under the same license. ` +
            `This can create legal obligations for proprietary or commercial projects.`,
          severity: 'critical',
          scanner: 'license',
          fix:
            `Replace "${pkgName}" with a package that has a permissive license (MIT, Apache-2.0, ISC, BSD), ` +
            `or consult legal counsel to understand if your usage is compliant.`,
          fixable: false,
          references: [`https://www.npmjs.com/package/${pkgName}`],
          metadata: { packageName: pkgName, license, version },
        });
      } else if (COPYLEFT_LICENSES.has(license)) {
        issues.push({
          id: `license-${pkgName}-${license}`,
          title: `Restrictive license: ${pkgName} (${license})`,
          description:
            `The package "${pkgName}" uses the ${license} license, a weak copyleft license. ` +
            `Modifications to this library must be released under the same license, and in some ` +
            `configurations may require disclosing your source code. Review your usage carefully.`,
          severity: 'high',
          scanner: 'license',
          fix:
            `Review whether your use of "${pkgName}" triggers copyleft obligations. ` +
            `Consider replacing it with a permissively-licensed alternative or consulting legal counsel.`,
          fixable: false,
          references: [`https://www.npmjs.com/package/${pkgName}`],
          metadata: { packageName: pkgName, license, version },
        });
      } else if (license === 'UNKNOWN') {
        issues.push({
          id: `license-${pkgName}-UNKNOWN`,
          title: `Unknown license: ${pkgName}`,
          description:
            `The license for "${pkgName}" could not be determined. Using software with an unknown license ` +
            `may create legal risks, as the terms of use are unclear.`,
          severity: 'medium',
          scanner: 'license',
          fix:
            `Check the npm page or repository for "${pkgName}" to determine its license. ` +
            `If no license is specified, contact the maintainer or avoid using this package in production.`,
          fixable: false,
          references: [`https://www.npmjs.com/package/${pkgName}`],
          metadata: { packageName: pkgName, license, version },
        });
      } else {
        // Non-standard license expression — flag as medium
        issues.push({
          id: `license-${pkgName}-${license}`,
          title: `Non-standard license: ${pkgName} (${license})`,
          description:
            `The package "${pkgName}" uses the "${license}" license, which is not in the known permissive ` +
            `or forbidden lists. Review the license terms carefully before using this package in production.`,
          severity: 'medium',
          scanner: 'license',
          fix: `Review the license terms for "${pkgName}" and consult legal counsel if necessary.`,
          fixable: false,
          references: [`https://www.npmjs.com/package/${pkgName}`],
          metadata: { packageName: pkgName, license, version },
        });
      }
    }
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      scanner: 'license',
      issues: [],
      duration: Date.now() - startTime,
      error: message,
    };
  }

  return {
    scanner: 'license',
    issues,
    duration: Date.now() - startTime,
  };
}
