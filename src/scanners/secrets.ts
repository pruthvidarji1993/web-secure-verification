import * as fs from 'fs';
import * as path from 'path';
import { glob } from 'glob';
import { Issue, ScanResult } from '../types';

interface SecretPattern {
  id: string;
  name: string;
  pattern: RegExp;
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  fix: string;
  ruleId: string;
}

const SECRET_PATTERNS: SecretPattern[] = [
  {
    id: 'aws-access-key',
    name: 'AWS Access Key ID',
    pattern: /AKIA[0-9A-Z]{16}/g,
    severity: 'critical',
    description: 'AWS Access Key ID found in source code',
    fix: 'Remove the key from source code and rotate it immediately. Use environment variables instead.',
    ruleId: 'secrets-aws-key',
  },
  {
    id: 'aws-secret-key',
    name: 'AWS Secret Access Key',
    pattern: /aws_secret_access_key\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/gi,
    severity: 'critical',
    description: 'AWS Secret Access Key found in source code',
    fix: 'Remove the secret from source code and rotate it immediately. Use environment variables instead.',
    ruleId: 'secrets-aws-key',
  },
  {
    id: 'google-api-key',
    name: 'Google API Key',
    pattern: /AIza[0-9A-Za-z\-_]{35}/g,
    severity: 'high',
    description: 'Google API key found in source code',
    fix: 'Remove the key from source code and restrict/regenerate it. Use environment variables.',
    ruleId: 'secrets-google-key',
  },
  {
    id: 'stripe-secret-key',
    name: 'Stripe Secret Key',
    pattern: /sk_live_[0-9a-zA-Z]{24,}/g,
    severity: 'critical',
    description: 'Stripe live secret key found in source code',
    fix: 'Remove the key from source code and revoke/rotate it immediately. Use environment variables.',
    ruleId: 'secrets-stripe-key',
  },
  {
    id: 'stripe-publishable-key',
    name: 'Stripe Publishable Key (Live)',
    pattern: /pk_live_[0-9a-zA-Z]{24,}/g,
    severity: 'high',
    description: 'Stripe live publishable key found in source code',
    fix: 'Move to environment variables even though this is a publishable key.',
    ruleId: 'secrets-stripe-key',
  },
  {
    id: 'github-token',
    name: 'GitHub Personal Access Token',
    pattern: /ghp_[0-9a-zA-Z]{36}/g,
    severity: 'critical',
    description: 'GitHub personal access token found in source code',
    fix: 'Remove the token and revoke it immediately. Use environment variables or GitHub Actions secrets.',
    ruleId: 'secrets-github-token',
  },
  {
    id: 'github-pat',
    name: 'GitHub PAT (new format)',
    pattern: /github_pat_[0-9a-zA-Z_]{80,}/g,
    severity: 'critical',
    description: 'GitHub fine-grained personal access token found in source code',
    fix: 'Remove the token and revoke it immediately. Use environment variables or GitHub Actions secrets.',
    ruleId: 'secrets-github-token',
  },
  {
    id: 'private-key',
    name: 'Private Key',
    pattern: /-----BEGIN\s+(?:RSA\s+|EC\s+|OPENSSH\s+|DSA\s+|PGP\s+)?PRIVATE\s+KEY(?:\s+BLOCK)?-----/g,
    severity: 'critical',
    description: 'Private key found in source code',
    fix: 'Remove the private key from source code immediately. Store securely and never commit to version control.',
    ruleId: 'secrets-private-key',
  },
  {
    id: 'jwt-secret-hardcoded',
    name: 'Hardcoded JWT Secret',
    pattern:
      /(?:jwt[_\-]?secret|jwtSecret|JWT_SECRET)\s*[=:]\s*['"]([^'"${}]{8,})['"](?!\s*\|\|\s*process\.env)/gi,
    severity: 'high',
    description: 'JWT secret appears to be hardcoded rather than loaded from environment',
    fix: 'Move JWT secret to an environment variable (e.g., process.env.JWT_SECRET).',
    ruleId: 'secrets-jwt-secret',
  },
];

interface GenericSecretPattern {
  variablePattern: RegExp;
  description: string;
  fix: string;
}

const GENERIC_SECRET_PATTERNS: GenericSecretPattern[] = [
  {
    variablePattern:
      /(?:password|passwd|pwd|secret|api_key|apikey|access_token|auth_token|private_key)\s*[=:]\s*['"]([^'"${}]{8,})['"]/gi,
    description: 'Potential hardcoded credential found',
    fix: 'Use environment variables instead of hardcoding sensitive values.',
  },
];

function calculateShannonEntropy(str: string): number {
  const freq: Record<string, number> = {};
  for (const char of str) {
    freq[char] = (freq[char] || 0) + 1;
  }
  let entropy = 0;
  for (const count of Object.values(freq)) {
    const p = count / str.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function isEnvReference(value: string): boolean {
  return (
    value.includes('process.env.') ||
    value.includes('${') ||
    value.includes('import.meta.env.') ||
    value === '' ||
    value === 'undefined' ||
    value === 'null'
  );
}

function checkGitignoreForEnvFiles(projectPath: string): boolean {
  const gitignorePath = path.join(projectPath, '.gitignore');
  if (!fs.existsSync(gitignorePath)) {
    return false;
  }
  const content = fs.readFileSync(gitignorePath, 'utf8');
  const lines = content.split('\n').map((l) => l.trim());
  return lines.some(
    (line) => line === '.env' || line === '.env.*' || line === '.env*' || line === '*.env'
  );
}

function scanFileForSecrets(filePath: string, projectPath: string): Issue[] {
  const issues: Issue[] = [];

  let content: string;
  try {
    content = fs.readFileSync(filePath, 'utf8');
  } catch {
    return issues;
  }

  const relativePath = path.relative(projectPath, filePath);
  const lines = content.split('\n');

  // Check known secret patterns
  for (const pattern of SECRET_PATTERNS) {
    const regex = new RegExp(pattern.pattern.source, pattern.pattern.flags);
    let match: RegExpExecArray | null;

    while ((match = regex.exec(content)) !== null) {
      const lineNumber =
        content.substring(0, match.index).split('\n').length;
      const lineContent = lines[lineNumber - 1] || '';

      // Skip if it looks like an env reference
      if (isEnvReference(lineContent)) continue;

      // Skip test files with placeholder values
      if (
        relativePath.includes('__tests__') ||
        relativePath.includes('.test.') ||
        relativePath.includes('.spec.')
      ) {
        continue;
      }

      issues.push({
        id: `secrets-${pattern.id}-${relativePath}-${lineNumber}`,
        title: `${pattern.name} detected`,
        description: `${pattern.description} in ${relativePath}`,
        severity: pattern.severity,
        scanner: 'secrets',
        file: relativePath,
        line: lineNumber,
        fix: pattern.fix,
        ruleId: pattern.ruleId,
      });
    }
  }

  // Check generic secret patterns
  for (const gPattern of GENERIC_SECRET_PATTERNS) {
    const regex = new RegExp(gPattern.variablePattern.source, gPattern.variablePattern.flags);
    let match: RegExpExecArray | null;

    while ((match = regex.exec(content)) !== null) {
      const value = match[1] || '';
      if (isEnvReference(value)) continue;

      // Skip very common non-sensitive patterns
      if (/^(test|example|placeholder|your[-_]?|<|>|\[|\]|\{|\})/i.test(value)) continue;

      const lineNumber = content.substring(0, match.index).split('\n').length;

      issues.push({
        id: `secrets-generic-${relativePath}-${lineNumber}`,
        title: 'Potential hardcoded credential',
        description: `${gPattern.description} in ${relativePath}: ${match[0].substring(0, 50)}...`,
        severity: 'medium',
        scanner: 'secrets',
        file: relativePath,
        line: lineNumber,
        fix: gPattern.fix,
      });
    }
  }

  // High-entropy string detection
  const isTestFile =
    relativePath.includes('__tests__') ||
    relativePath.includes('.spec.') ||
    relativePath.includes('.test.');

  if (!isTestFile) {
    // Collect all positions caught by existing patterns to avoid duplicates
    const caughtPositions = new Set<number>();
    for (const pattern of SECRET_PATTERNS) {
      const regex = new RegExp(pattern.pattern.source, pattern.pattern.flags);
      let m: RegExpExecArray | null;
      while ((m = regex.exec(content)) !== null) {
        for (let i = m.index; i < m.index + m[0].length; i++) {
          caughtPositions.add(i);
        }
      }
    }

    // Match quoted strings (single or double quoted)
    const quotedStringRegex = /(['"])((?:[^'"\\]|\\.){20,200})\1/g;
    let qMatch: RegExpExecArray | null;

    while ((qMatch = quotedStringRegex.exec(content)) !== null) {
      const str = qMatch[2];

      // Skip if already caught by a named pattern
      if (caughtPositions.has(qMatch.index)) continue;

      // Only consider alphanumeric + special chars (base64-like or hex-like)
      if (!/^[A-Za-z0-9+/=_\-!@#$%^&*]+$/.test(str)) continue;

      const lineNumber = content.substring(0, qMatch.index).split('\n').length;
      const lineContent = lines[lineNumber - 1] || '';

      // Skip import statements and require() calls
      if (/^\s*(import\s|.*\brequire\s*\()/.test(lineContent)) continue;

      // Skip URLs
      if (/https?:\/\//.test(str)) continue;

      // Skip regex patterns (lines containing = / or new RegExp)
      if (/new\s+RegExp|\/[^/]+\/[gimsuy]*/.test(lineContent)) continue;

      const entropy = calculateShannonEntropy(str);
      if (entropy <= 4.5) continue;

      issues.push({
        id: `secrets-entropy-${relativePath}-${lineNumber}`,
        title: 'High-entropy string detected (possible hardcoded secret)',
        description: `High-entropy string found in ${relativePath}:${lineNumber} (entropy: ${entropy.toFixed(2)} bits/char). Value starts with: "${str.substring(0, 20)}..."`,
        severity: 'high',
        scanner: 'secrets',
        file: relativePath,
        line: lineNumber,
        fix: 'Move to environment variables or secrets manager',
        fixable: false,
        ruleId: 'secrets-entropy',
      });
    }
  }

  return issues;
}

export async function runSecretsScanner(projectPath: string): Promise<ScanResult> {
  const startTime = Date.now();
  const issues: Issue[] = [];

  try {
    // Check if .env files are in .gitignore
    const envInGitignore = checkGitignoreForEnvFiles(projectPath);
    if (!envInGitignore) {
      const envExists = fs.existsSync(path.join(projectPath, '.env'));
      if (envExists) {
        issues.push({
          id: 'secrets-env-not-gitignored',
          title: '.env file not in .gitignore',
          description:
            'A .env file exists but is not listed in .gitignore. This risks committing sensitive credentials to version control.',
          severity: 'high',
          scanner: 'secrets',
          file: '.env',
          fix: 'Add ".env" and ".env.*" to your .gitignore file.',
        });
      } else if (!fs.existsSync(path.join(projectPath, '.gitignore'))) {
        issues.push({
          id: 'secrets-no-gitignore',
          title: 'No .gitignore file found',
          description:
            'No .gitignore file found. This risks committing sensitive files to version control.',
          severity: 'medium',
          scanner: 'secrets',
          fix: 'Create a .gitignore file and add .env, node_modules/, and other sensitive paths.',
        });
      }
    }

    // Find all source files to scan
    const patterns = [
      '**/*.js',
      '**/*.ts',
      '**/*.jsx',
      '**/*.tsx',
      '**/.env',
      '**/.env.*',
      '**/*.env',
    ];

    const ignorePatterns = [
      '**/node_modules/**',
      '**/.next/**',
      '**/dist/**',
      '**/build/**',
      '**/.git/**',
      '**/coverage/**',
    ];

    const allFiles: string[] = [];

    for (const pattern of patterns) {
      const files = await glob(pattern, {
        cwd: projectPath,
        absolute: true,
        ignore: ignorePatterns,
        dot: true,
      });
      allFiles.push(...files);
    }

    // Also scan JSON files (but not package-lock, yarn.lock etc.)
    const jsonFiles = await glob('**/*.json', {
      cwd: projectPath,
      absolute: true,
      ignore: [
        ...ignorePatterns,
        '**/package-lock.json',
        '**/yarn.lock',
        '**/pnpm-lock.yaml',
        '**/.next/**',
      ],
      dot: false,
    });
    allFiles.push(...jsonFiles);

    // Deduplicate
    const uniqueFiles = [...new Set(allFiles)];

    for (const filePath of uniqueFiles) {
      const fileIssues = scanFileForSecrets(filePath, projectPath);
      issues.push(...fileIssues);
    }
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      scanner: 'secrets',
      issues: [],
      duration: Date.now() - startTime,
      error: message,
    };
  }

  return {
    scanner: 'secrets',
    issues,
    duration: Date.now() - startTime,
  };
}
