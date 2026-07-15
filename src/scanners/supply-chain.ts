import * as fs from 'fs';
import * as path from 'path';
import { Issue, ScanResult } from '../types';

// Patterns in postinstall scripts that indicate high-risk behaviour
const DANGEROUS_SCRIPT_PATTERN =
  /\b(?:curl|wget|bash|sh|powershell|pwsh|python|python3|node\s+-e|exec|eval)\b|https?:\/\//i;

// Well-known packages that commonly have benign postinstall scripts
const WELL_KNOWN_PACKAGES = new Set([
  'react',
  'react-dom',
  'lodash',
  'axios',
  'express',
  'typescript',
  'webpack',
  'babel-loader',
  'eslint',
  'prettier',
  'jest',
  'next',
  'vue',
  'angular',
  'svelte',
  'chalk',
  'commander',
  'glob',
  'rimraf',
  'cross-env',
  'dotenv',
  'husky',
  'lint-staged',
  'esbuild',
  'vite',
  'rollup',
  'turbo',
]);

// Known malicious packages (name or name@version)
const KNOWN_MALICIOUS = new Set([
  'event-stream@3.3.6',
  'flatmap-stream',
  'electron-native-notify',
  'getcookies',
  'uglifyjs',
  'crossenv',
  'nodecookies',
  'node-cookies',
  'discordi.js',
  'discord.js-updated',
  'free-2fa',
]);

// Typosquatting map: real package -> list of typo variants to flag
const TYPOSQUAT_MAP: Record<string, string[]> = {
  lodash: ['l0dash', 'Iodash', 'lodahs', 'ladash', 'nodash'],
  react: ['reakt', 'reaact', 'rect', 'recat'],
  axios: ['axois', 'axiso'],
  express: ['expres', 'expresss', 'exprss'],
  webpack: ['webpak', 'wbpack', 'webpackk'],
  typescript: ['typscript', 'typescrpt'],
  next: ['nxt', 'nextt'],
  chalk: ['chalkk', 'cahalk'],
  commander: ['comander', 'commandr'],
};

// Build a reverse map: typo -> real package
const TYPO_TO_REAL: Record<string, string> = {};
for (const [real, typos] of Object.entries(TYPOSQUAT_MAP)) {
  for (const typo of typos) {
    TYPO_TO_REAL[typo] = real;
  }
}

interface PackageJson {
  version?: string;
  scripts?: Record<string, string>;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
}

function readPackageJson(pkgDir: string): PackageJson | null {
  try {
    return JSON.parse(fs.readFileSync(path.join(pkgDir, 'package.json'), 'utf8')) as PackageJson;
  } catch {
    return null;
  }
}

function checkPostinstallScripts(
  projectPath: string,
  allDeps: Record<string, string>,
): Issue[] {
  const issues: Issue[] = [];
  const nodeModulesPath = path.join(projectPath, 'node_modules');

  if (!fs.existsSync(nodeModulesPath)) return issues;

  for (const pkgName of Object.keys(allDeps)) {
    const pkgDir = path.join(nodeModulesPath, pkgName);
    if (!fs.existsSync(pkgDir)) continue;

    const pkgJson = readPackageJson(pkgDir);
    if (!pkgJson?.scripts) continue;

    const INSTALL_HOOKS = ['preinstall', 'install', 'postinstall'];

    for (const hook of INSTALL_HOOKS) {
      const script = pkgJson.scripts[hook];
      if (!script || script.trim() === '') continue;

      const isDangerous = DANGEROUS_SCRIPT_PATTERN.test(script);
      const isWellKnown = WELL_KNOWN_PACKAGES.has(pkgName);

      // Well-known packages with simple, non-dangerous scripts get medium; everything else gets high
      const severity = isDangerous || !isWellKnown ? 'high' : 'medium';

      issues.push({
        id: `supply-chain-postinstall-${pkgName}`,
        title: `${hook} script in dependency: ${pkgName}`,
        description:
          `The package "${pkgName}" has a "${hook}" script that runs automatically during npm install.\n` +
          `Script: ${script.substring(0, 200)}${script.length > 200 ? '...' : ''}\n\n` +
          (isDangerous
            ? 'WARNING: The script contains potentially dangerous commands (curl/wget/bash/URLs) that could download and execute arbitrary code.'
            : 'Review this script to ensure it performs only expected operations.'),
        severity,
        scanner: 'supply-chain',
        fixable: false,
        fix:
          `Audit the ${hook} script in "${pkgName}". If the script is unexpected or suspicious, ` +
          `remove the package and find a safer alternative. You can also use --ignore-scripts flag ` +
          `when running npm install to prevent scripts from running (but this may break some packages).`,
        references: [`https://www.npmjs.com/package/${pkgName}`],
        metadata: { packageName: pkgName, hook, script },
      });

      // Only report once per package (first hook found)
      break;
    }
  }

  return issues;
}

function checkTyposquatting(
  projectPath: string,
  allDeps: Record<string, string>,
): Issue[] {
  const issues: Issue[] = [];
  const nodeModulesPath = path.join(projectPath, 'node_modules');

  for (const pkgName of Object.keys(allDeps)) {
    // Check against known-malicious list (both bare name and name@version)
    let version = allDeps[pkgName];
    const pkgDir = path.join(nodeModulesPath, pkgName);
    if (fs.existsSync(pkgDir)) {
      const pkgJson = readPackageJson(pkgDir);
      if (pkgJson?.version) version = pkgJson.version;
    }

    const nameAtVersion = `${pkgName}@${version}`;
    const isMaliciousByName = KNOWN_MALICIOUS.has(pkgName);
    const isMaliciousByVersion = KNOWN_MALICIOUS.has(nameAtVersion);

    if (isMaliciousByName || isMaliciousByVersion) {
      issues.push({
        id: `supply-chain-malicious-${pkgName}`,
        title: `Known malicious package detected: ${pkgName}`,
        description:
          `The package "${pkgName}"${isMaliciousByVersion ? ` at version ${version}` : ''} is on the ` +
          `known-malicious packages list. This package has been identified as containing malicious code ` +
          `that could compromise your application or steal sensitive data.`,
        severity: 'critical',
        scanner: 'supply-chain',
        fixable: false,
        fix:
          `Immediately remove "${pkgName}" from your project. Run: npm uninstall ${pkgName}. ` +
          `Rotate any secrets that may have been exposed, and audit your system for signs of compromise.`,
        references: [
          `https://www.npmjs.com/package/${pkgName}`,
          'https://github.com/nicedoc/awesome-malicious-packages',
        ],
        metadata: { packageName: pkgName, version },
      });
      continue;
    }

    // Check for typosquatting
    const realPkg = TYPO_TO_REAL[pkgName];
    if (realPkg) {
      issues.push({
        id: `supply-chain-typosquat-${pkgName}`,
        title: `Possible typosquat of "${realPkg}": ${pkgName}`,
        description:
          `The package "${pkgName}" closely resembles the popular package "${realPkg}". ` +
          `Typosquatting attacks occur when attackers publish packages with names similar to popular ` +
          `packages to trick developers into installing malicious code. ` +
          `Verify you intended to install "${pkgName}" and not "${realPkg}".`,
        severity: 'high',
        scanner: 'supply-chain',
        fixable: false,
        fix:
          `Verify whether you intended to install "${pkgName}" or "${realPkg}". ` +
          `If this was a mistake, run: npm uninstall ${pkgName} && npm install ${realPkg}. ` +
          `Inspect the package source at https://www.npmjs.com/package/${pkgName} before using it.`,
        references: [
          `https://www.npmjs.com/package/${pkgName}`,
          `https://www.npmjs.com/package/${realPkg}`,
        ],
        metadata: { packageName: pkgName, resembles: realPkg, version },
      });
    }
  }

  return issues;
}

export async function runSupplyChainScanner(projectPath: string): Promise<ScanResult> {
  const startTime = Date.now();
  const issues: Issue[] = [];

  try {
    const packageJsonPath = path.join(projectPath, 'package.json');
    if (!fs.existsSync(packageJsonPath)) {
      return {
        scanner: 'supply-chain',
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
        scanner: 'supply-chain',
        issues: [],
        duration: Date.now() - startTime,
        error: 'Failed to parse package.json',
      };
    }

    const allDeps: Record<string, string> = {
      ...(packageJson.dependencies || {}),
      ...(packageJson.devDependencies || {}),
    };

    const postinstallIssues = checkPostinstallScripts(projectPath, allDeps);
    issues.push(...postinstallIssues);

    const typosquatIssues = checkTyposquatting(projectPath, allDeps);
    issues.push(...typosquatIssues);
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      scanner: 'supply-chain',
      issues: [],
      duration: Date.now() - startTime,
      error: message,
    };
  }

  return {
    scanner: 'supply-chain',
    issues,
    duration: Date.now() - startTime,
  };
}
