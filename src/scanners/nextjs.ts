import * as fs from 'fs';
import * as path from 'path';
import { glob } from 'glob';
import { Issue, ScanResult } from '../types';

const REQUIRED_SECURITY_HEADERS = [
  {
    id: 'x-frame-options',
    header: 'X-Frame-Options',
    pattern: /X-Frame-Options/i,
    description: 'X-Frame-Options header prevents clickjacking attacks by controlling if the site can be embedded in iframes.',
    fix: 'Add X-Frame-Options: DENY or SAMEORIGIN header in next.config.js headers configuration.',
    reference: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options',
  },
  {
    id: 'x-content-type-options',
    header: 'X-Content-Type-Options',
    pattern: /X-Content-Type-Options/i,
    description: 'X-Content-Type-Options prevents MIME-type sniffing attacks.',
    fix: 'Add X-Content-Type-Options: nosniff header in next.config.js headers configuration.',
    reference: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options',
  },
  {
    id: 'content-security-policy',
    header: 'Content-Security-Policy',
    pattern: /Content-Security-Policy/i,
    description: 'Content Security Policy (CSP) helps prevent XSS and other injection attacks by specifying allowed content sources.',
    fix: 'Add a Content-Security-Policy header in next.config.js headers configuration.',
    reference: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP',
  },
  {
    id: 'hsts',
    header: 'Strict-Transport-Security',
    pattern: /Strict-Transport-Security/i,
    description: 'HTTP Strict Transport Security (HSTS) forces browsers to use HTTPS, preventing protocol downgrade attacks.',
    fix: 'Add Strict-Transport-Security header in next.config.js headers configuration.',
    reference: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security',
  },
];

const SENSITIVE_PATTERNS = [
  /AKIA[0-9A-Z]{16}/,
  /AIza[0-9A-Za-z\-_]{35}/,
  /sk_live_[0-9a-zA-Z]{24,}/,
  /ghp_[0-9a-zA-Z]{36}/,
  /-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY/,
];

function isSensitiveValue(value: string): boolean {
  return SENSITIVE_PATTERNS.some((p) => p.test(value));
}

function checkNextConfig(projectPath: string): Issue[] {
  const issues: Issue[] = [];

  // Find next.config file (js or ts)
  const configFiles = ['next.config.js', 'next.config.ts', 'next.config.mjs'];
  let configPath: string | null = null;
  let configContent: string | null = null;

  for (const configFile of configFiles) {
    const fullPath = path.join(projectPath, configFile);
    if (fs.existsSync(fullPath)) {
      configPath = fullPath;
      configContent = fs.readFileSync(fullPath, 'utf8');
      break;
    }
  }

  if (!configPath || !configContent) {
    issues.push({
      id: 'nextjs-no-config',
      title: 'Next.js config file not found',
      description: 'No next.config.js or next.config.ts file found. Security headers cannot be verified.',
      severity: 'medium',
      scanner: 'nextjs',
      fix: 'Create a next.config.js file and configure security headers.',
      references: ['https://nextjs.org/docs/api-reference/next.config.js/headers'],
    });
    return issues;
  }

  const relativeConfigPath = path.relative(projectPath, configPath);

  // Check for security headers
  const hasHeadersConfig = /headers\s*\(/.test(configContent) || /headers\s*:/.test(configContent);

  if (!hasHeadersConfig) {
    issues.push({
      id: 'nextjs-no-headers',
      title: 'No security headers configured in Next.js',
      description: 'No HTTP security headers are configured in next.config.js. Security headers protect against common web attacks.',
      severity: 'high',
      scanner: 'nextjs',
      file: relativeConfigPath,
      fix: 'Add a headers() async function to next.config.js that returns security headers for all routes.',
      references: ['https://nextjs.org/docs/advanced-features/security-headers'],
    });
  } else {
    // Check for specific headers
    for (const headerCheck of REQUIRED_SECURITY_HEADERS) {
      if (!headerCheck.pattern.test(configContent)) {
        issues.push({
          id: `nextjs-missing-header-${headerCheck.id}`,
          title: `Missing ${headerCheck.header} header`,
          description: headerCheck.description,
          severity: 'medium',
          scanner: 'nextjs',
          file: relativeConfigPath,
          fix: headerCheck.fix,
          references: [headerCheck.reference],
        });
      }
    }
  }

  // Check for dangerouslyAllowSVG without contentSecurityPolicy
  if (/dangerouslyAllowSVG\s*:\s*true/.test(configContent)) {
    if (!/contentSecurityPolicy/.test(configContent)) {
      issues.push({
        id: 'nextjs-dangerous-svg-no-csp',
        title: 'dangerouslyAllowSVG enabled without contentSecurityPolicy',
        description:
          'dangerouslyAllowSVG allows SVG files to be served as images, which can contain scripts. Without contentSecurityPolicy, this can lead to XSS vulnerabilities.',
        severity: 'high',
        scanner: 'nextjs',
        file: relativeConfigPath,
        fix: 'Add contentSecurityPolicy to the Image configuration when using dangerouslyAllowSVG: true.',
        references: ['https://nextjs.org/docs/api-reference/components/image#dangerouslyallowsvg'],
      });
    }
  }

  return issues;
}

async function checkNextPublicEnvVars(projectPath: string): Promise<Issue[]> {
  const issues: Issue[] = [];

  // Find all .env files
  const envFiles = await glob('**/.env*', {
    cwd: projectPath,
    absolute: true,
    ignore: ['**/node_modules/**'],
    dot: true,
  });

  for (const envFile of envFiles) {
    const relativePath = path.relative(projectPath, envFile);
    let content: string;
    try {
      content = fs.readFileSync(envFile, 'utf8');
    } catch {
      continue;
    }

    const lines = content.split('\n');
    lines.forEach((line, index) => {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) return;

      const match = trimmed.match(/^(NEXT_PUBLIC_[A-Z0-9_]+)\s*=\s*(.+)$/);
      if (match) {
        const varName = match[1];
        const value = match[2].trim().replace(/^['"]|['"]$/g, '');

        if (isSensitiveValue(value)) {
          issues.push({
            id: `nextjs-next-public-sensitive-${varName}`,
            title: `Sensitive value in NEXT_PUBLIC_ env var: ${varName}`,
            description: `The environment variable "${varName}" is prefixed with NEXT_PUBLIC_ which exposes it to the browser. It appears to contain a sensitive value (API key or secret).`,
            severity: 'critical',
            scanner: 'nextjs',
            file: relativePath,
            line: index + 1,
            fix: `Remove the NEXT_PUBLIC_ prefix from ${varName} and access it only server-side, or use a different (non-sensitive) value for the public variable.`,
          });
        }
      }
    });
  }

  return issues;
}

async function checkApiRoutesForAuth(projectPath: string): Promise<Issue[]> {
  const issues: Issue[] = [];

  // Find pages/api/ routes (Next.js pages router)
  const apiFiles = await glob('pages/api/**/*.{js,ts}', {
    cwd: projectPath,
    absolute: true,
    ignore: ['**/node_modules/**'],
  });

  // Also check app/api/ routes (Next.js app router)
  const appApiFiles = await glob('app/**/route.{js,ts}', {
    cwd: projectPath,
    absolute: true,
    ignore: ['**/node_modules/**'],
  });

  const allApiFiles = [...apiFiles, ...appApiFiles];

  const AUTH_INDICATORS = [
    /\bauth\b/i,
    /\bsession\b/i,
    /\btoken\b/i,
    /\bcookie\b/i,
    /\bgetServerSideSession\b/,
    /\bgetSession\b/,
    /\bgetToken\b/,
    /\bverifyToken\b/,
    /\bauthenticate\b/i,
    /\bauthorize\b/i,
    /\bgetServerSession\b/,
    /\bnext-auth\b/,
    /\bjwt\b/i,
    /\bbearer\b/i,
    /\bAuthorization\b/,
    /\bmiddleware\b/i,
    /withAuth/,
    /requireAuth/,
    /isAuthenticated/,
  ];

  for (const filePath of allApiFiles) {
    const relativePath = path.relative(projectPath, filePath);
    let content: string;
    try {
      content = fs.readFileSync(filePath, 'utf8');
    } catch {
      continue;
    }

    const hasAuthCheck = AUTH_INDICATORS.some((pattern) => pattern.test(content));

    if (!hasAuthCheck) {
      issues.push({
        id: `nextjs-api-no-auth-${relativePath}`,
        title: `API route may be missing authentication: ${relativePath}`,
        description: `The API route "${relativePath}" has no apparent authentication check. This could expose sensitive operations to unauthenticated users.`,
        severity: 'medium',
        scanner: 'nextjs',
        file: relativePath,
        fix: 'Add authentication checks using next-auth, JWT validation, or session verification at the beginning of the handler.',
        references: ['https://next-auth.js.org/getting-started/example'],
      });
    }
  }

  return issues;
}

function checkNextAuthConfig(projectPath: string): Issue[] {
  const issues: Issue[] = [];

  // Check if next-auth is used
  const packageJsonPath = path.join(projectPath, 'package.json');
  if (!fs.existsSync(packageJsonPath)) return issues;

  let packageJson: { dependencies?: Record<string, string>; devDependencies?: Record<string, string> };
  try {
    packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
  } catch {
    return issues;
  }

  const allDeps = {
    ...(packageJson.dependencies || {}),
    ...(packageJson.devDependencies || {}),
  };

  const usesNextAuth = 'next-auth' in allDeps || '@auth/nextjs' in allDeps;
  if (!usesNextAuth) return issues;

  // Check for NEXTAUTH_SECRET in env files
  const envFiles = ['.env', '.env.local', '.env.production', '.env.production.local'];
  let hasNextAuthSecret = false;

  for (const envFile of envFiles) {
    const envPath = path.join(projectPath, envFile);
    if (fs.existsSync(envPath)) {
      const content = fs.readFileSync(envPath, 'utf8');
      if (/^NEXTAUTH_SECRET\s*=\s*.+/m.test(content)) {
        hasNextAuthSecret = true;
        break;
      }
    }
  }

  // Also check for AUTH_SECRET (newer next-auth v5)
  if (!hasNextAuthSecret) {
    for (const envFile of envFiles) {
      const envPath = path.join(projectPath, envFile);
      if (fs.existsSync(envPath)) {
        const content = fs.readFileSync(envPath, 'utf8');
        if (/^AUTH_SECRET\s*=\s*.+/m.test(content)) {
          hasNextAuthSecret = true;
          break;
        }
      }
    }
  }

  // Check next-auth config files
  const nextAuthConfigFiles = ['pages/api/auth/[...nextauth].js', 'pages/api/auth/[...nextauth].ts', 'auth.ts', 'auth.js'];
  for (const configFile of nextAuthConfigFiles) {
    const configPath = path.join(projectPath, configFile);
    if (fs.existsSync(configPath)) {
      const content = fs.readFileSync(configPath, 'utf8');
      if (/(?:secret|NEXTAUTH_SECRET|AUTH_SECRET)\s*:/.test(content)) {
        hasNextAuthSecret = true;
        break;
      }
    }
  }

  if (!hasNextAuthSecret) {
    issues.push({
      id: 'nextjs-nextauth-no-secret',
      title: 'next-auth NEXTAUTH_SECRET not configured',
      description:
        'next-auth is installed but NEXTAUTH_SECRET environment variable is not configured. Without a secret, JWT tokens may use a weak default, compromising session security.',
      severity: 'high',
      scanner: 'nextjs',
      fix: 'Set NEXTAUTH_SECRET in your .env.local file with a strong random secret. Generate one with: openssl rand -base64 32',
      references: ['https://next-auth.js.org/configuration/options#secret'],
    });
  }

  return issues;
}

export async function runNextjsScanner(projectPath: string): Promise<ScanResult> {
  const startTime = Date.now();
  const issues: Issue[] = [];

  try {
    // Check if this is a Next.js project
    const packageJsonPath = path.join(projectPath, 'package.json');
    if (!fs.existsSync(packageJsonPath)) {
      return {
        scanner: 'nextjs',
        issues: [],
        duration: Date.now() - startTime,
        error: 'package.json not found',
      };
    }

    let packageJson: { dependencies?: Record<string, string>; devDependencies?: Record<string, string> };
    try {
      packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
    } catch {
      return {
        scanner: 'nextjs',
        issues: [],
        duration: Date.now() - startTime,
        error: 'Failed to parse package.json',
      };
    }

    const allDeps = {
      ...(packageJson.dependencies || {}),
      ...(packageJson.devDependencies || {}),
    };

    if (!('next' in allDeps)) {
      // Not a Next.js project, skip
      return {
        scanner: 'nextjs',
        issues: [],
        duration: Date.now() - startTime,
      };
    }

    // Run all Next.js checks
    const configIssues = checkNextConfig(projectPath);
    issues.push(...configIssues);

    const envVarIssues = await checkNextPublicEnvVars(projectPath);
    issues.push(...envVarIssues);

    const apiAuthIssues = await checkApiRoutesForAuth(projectPath);
    issues.push(...apiAuthIssues);

    const nextAuthIssues = checkNextAuthConfig(projectPath);
    issues.push(...nextAuthIssues);
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      scanner: 'nextjs',
      issues: [],
      duration: Date.now() - startTime,
      error: message,
    };
  }

  return {
    scanner: 'nextjs',
    issues,
    duration: Date.now() - startTime,
  };
}
