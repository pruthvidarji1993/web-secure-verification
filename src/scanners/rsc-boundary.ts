import * as fs from 'fs';
import * as path from 'path';
import { glob } from 'glob';
import { Issue, ScanResult } from '../types';

const IGNORE_PATTERNS = [
  '**/node_modules/**',
  '**/.next/**',
  '**/dist/**',
  '**/build/**',
  '**/.git/**',
];

const SOURCE_PATTERNS = ['**/*.ts', '**/*.tsx', '**/*.js', '**/*.jsx'];

interface FileClassification {
  filePath: string;
  relativePath: string;
  isClientComponent: boolean;
  isServerComponent: boolean;
  hasUseServer: boolean;
  content: string;
  lines: string[];
}

function classifyFile(filePath: string, projectPath: string): FileClassification | null {
  let content: string;
  try {
    content = fs.readFileSync(filePath, 'utf8');
  } catch {
    return null;
  }

  const relativePath = path.relative(projectPath, filePath);
  const lines = content.split('\n');

  // Detect 'use client' directive — must appear before any non-comment code
  let isClientComponent = false;
  for (const line of lines.slice(0, 10)) {
    const trimmed = line.trim();
    if (trimmed === '' || trimmed.startsWith('//') || trimmed.startsWith('/*') || trimmed.startsWith('*')) continue;
    if (trimmed === "'use client'" || trimmed === '"use client"' || trimmed.startsWith("'use client'") || trimmed.startsWith('"use client"')) {
      isClientComponent = true;
    }
    break;
  }

  // Detect 'use server' directive
  let hasUseServer = false;
  for (const line of lines.slice(0, 10)) {
    const trimmed = line.trim();
    if (trimmed === '' || trimmed.startsWith('//') || trimmed.startsWith('/*') || trimmed.startsWith('*')) continue;
    if (trimmed === "'use server'" || trimmed === '"use server"' || trimmed.startsWith("'use server'") || trimmed.startsWith('"use server"')) {
      hasUseServer = true;
    }
    break;
  }

  // Detect server component heuristics (async function, next/headers usage)
  const hasAsyncFunction =
    /export\s+default\s+async\s+function/.test(content) ||
    /^async\s+function\s+\w+/m.test(content);
  const usesNextHeaders = /from\s+['"]next\/headers['"]/.test(content);

  const isServerComponent = !isClientComponent && (hasAsyncFunction || usesNextHeaders);

  return {
    filePath,
    relativePath,
    isClientComponent,
    isServerComponent,
    hasUseServer,
    content,
    lines,
  };
}

function checkNonSerializableProps(file: FileClassification): Issue[] {
  const issues: Issue[] = [];
  if (!file.isServerComponent) return issues;

  const { lines, relativePath } = file;

  // Pattern: passing new Date() as a prop
  const datePropsPattern = /<\w+[^>]*\w+=\{(?:new\s+Date|[^}]*Date\.)/g;
  // Pattern: passing a function as a prop
  const funcPropsPattern = /<\w+[^>]*\w+=\{(?:async\s*)?\(/g;
  // Pattern: passing a class instance (new Foo() used in JSX attribute)
  const classInstancePattern = /<\w+[^>]*\w+=\{new\s+\w+\(/g;

  const checks = [
    {
      pattern: datePropsPattern,
      type: 'non-serializable-date',
      message:
        'Passing a Date object as a prop to a component across the RSC boundary is not supported. ' +
        'Date objects are not serializable by React. Convert to an ISO string or timestamp before passing.',
      severity: 'high' as const,
    },
    {
      pattern: funcPropsPattern,
      type: 'non-serializable-function',
      message:
        'Passing a function as a prop to a component from a Server Component is not allowed across ' +
        'the RSC boundary. Functions are not serializable. Use Server Actions or move the handler to the client.',
      severity: 'high' as const,
    },
    {
      pattern: classInstancePattern,
      type: 'non-serializable-class-instance',
      message:
        'Passing a class instance as a prop across the RSC boundary is not supported. ' +
        'Class instances are not serializable. Pass plain data (objects, primitives) instead.',
      severity: 'high' as const,
    },
  ];

  for (const check of checks) {
    const regex = new RegExp(check.pattern.source, check.pattern.flags);
    let match: RegExpExecArray | null;
    while ((match = regex.exec(file.content)) !== null) {
      const lineNumber = file.content.substring(0, match.index).split('\n').length;
      const lineContent = lines[lineNumber - 1] || '';
      const trimmed = lineContent.trim();

      if (trimmed.startsWith('//') || trimmed.startsWith('*')) continue;

      issues.push({
        id: `rsc-boundary-${check.type}-${relativePath}-${lineNumber}`,
        title: `Non-serializable prop passed across RSC boundary in ${relativePath}`,
        description: `${check.message}\n\nFound at line ${lineNumber}: ${trimmed.substring(0, 120)}`,
        severity: check.severity,
        scanner: 'rsc-boundary',
        file: relativePath,
        line: lineNumber,
        fix: 'Ensure all data passed from Server Components to Client Components is JSON-serializable (strings, numbers, plain objects, arrays).',
        fixable: false,
        references: ['https://nextjs.org/docs/app/building-your-application/rendering/composition-patterns'],
      });
    }
  }

  return issues;
}

function checkClientImportingServerOnly(
  file: FileClassification,
  allFiles: Map<string, FileClassification>,
): Issue[] {
  const issues: Issue[] = [];
  if (!file.isClientComponent) return issues;

  const { lines, relativePath } = file;

  // Find all imports in this client component file
  const importPattern = /^import\s+.+\s+from\s+['"]([^'"]+)['"]/gm;
  let match: RegExpExecArray | null;

  while ((match = importPattern.exec(file.content)) !== null) {
    const importPath = match[1];
    const lineNumber = file.content.substring(0, match.index).split('\n').length;
    const lineContent = lines[lineNumber - 1] || '';

    // Only check relative imports
    if (!importPath.startsWith('.')) continue;

    // Resolve the import to an absolute path
    const dir = path.dirname(file.filePath);
    const extensions = ['.ts', '.tsx', '.js', '.jsx'];
    let resolvedPath: string | null = null;

    for (const ext of extensions) {
      const candidate = path.resolve(dir, importPath + ext);
      if (allFiles.has(candidate)) {
        resolvedPath = candidate;
        break;
      }
      // also try index file
      const indexCandidate = path.resolve(dir, importPath, 'index' + ext);
      if (allFiles.has(indexCandidate)) {
        resolvedPath = indexCandidate;
        break;
      }
    }

    if (!resolvedPath) continue;

    const importedFile = allFiles.get(resolvedPath);
    if (!importedFile?.hasUseServer) continue;

    issues.push({
      id: `rsc-boundary-client-imports-server-${relativePath}-${lineNumber}`,
      title: `Client Component imports 'use server' module directly: ${relativePath}`,
      description:
        `The Client Component "${relativePath}" directly imports from "${importPath}" which contains ` +
        `'use server'. Server Actions should only be called via form actions or passed as props, ` +
        `not directly imported into Client Components.\n\nLine ${lineNumber}: ${lineContent.trim().substring(0, 120)}`,
      severity: 'high',
      scanner: 'rsc-boundary',
      file: relativePath,
      line: lineNumber,
      fix:
        'Pass Server Actions as props from a Server Component, or use them in form action attributes. ' +
        'Do not import server action files directly into client components.',
      fixable: false,
      references: [
        'https://nextjs.org/docs/app/building-your-application/data-fetching/server-actions-and-mutations',
      ],
    });
  }

  return issues;
}

function checkServerActionImportsInClient(file: FileClassification): Issue[] {
  const issues: Issue[] = [];
  if (!file.isClientComponent) return issues;

  const { lines, relativePath } = file;

  // Look for patterns where 'use server' actions are called outside of form action attributes
  // i.e. imported and invoked directly (not as action={...})
  const directCallPattern = /\bawait\s+\w+\s*\(|(?<!=\{)\b\w+Action\s*\(/g;

  // First check if this file imports from a 'use server' file (we need to have seen imports)
  const hasServerImportMarker = /from\s+['"][^'"]*actions?['"]|from\s+['"][^'"]*server['"]/.test(
    file.content,
  );
  if (!hasServerImportMarker) return issues;

  let match: RegExpExecArray | null;
  while ((match = directCallPattern.exec(file.content)) !== null) {
    const lineNumber = file.content.substring(0, match.index).split('\n').length;
    const lineContent = lines[lineNumber - 1] || '';
    const trimmed = lineContent.trim();

    if (trimmed.startsWith('//') || trimmed.startsWith('*')) continue;
    // Skip if it's in a form action attribute
    if (/action=\{/.test(lineContent)) continue;

    issues.push({
      id: `rsc-boundary-server-action-direct-call-${relativePath}-${lineNumber}`,
      title: `Possible direct Server Action call in Client Component: ${relativePath}`,
      description:
        `The Client Component "${relativePath}" may be calling a Server Action directly outside ` +
        `of a form action attribute. This is allowed but should be intentional — calling server ` +
        `actions directly from event handlers is fine, but ensure the action is properly imported ` +
        `with 'use server' and handles errors correctly.\n\nLine ${lineNumber}: ${trimmed.substring(0, 120)}`,
      severity: 'medium',
      scanner: 'rsc-boundary',
      file: relativePath,
      line: lineNumber,
      fix:
        'Ensure this Server Action call is intentional. Use try/catch and handle loading/error states. ' +
        'Consider using useTransition for non-form Server Action calls.',
      fixable: false,
      references: [
        'https://nextjs.org/docs/app/building-your-application/data-fetching/server-actions-and-mutations#behavior',
      ],
    });

    // Only report once per file to avoid noise
    break;
  }

  return issues;
}

export async function runRscBoundaryScanner(projectPath: string): Promise<ScanResult> {
  const startTime = Date.now();
  const issues: Issue[] = [];

  try {
    // Check if this is a Next.js project
    const packageJsonPath = path.join(projectPath, 'package.json');
    if (!fs.existsSync(packageJsonPath)) {
      return {
        scanner: 'rsc-boundary',
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
        scanner: 'rsc-boundary',
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
      // Not a Next.js project — RSC boundary checks don't apply
      return {
        scanner: 'rsc-boundary',
        issues: [],
        duration: Date.now() - startTime,
      };
    }

    // Collect all source files
    const allFilePaths: string[] = [];
    for (const pattern of SOURCE_PATTERNS) {
      const files = await glob(pattern, {
        cwd: projectPath,
        absolute: true,
        ignore: IGNORE_PATTERNS,
      });
      allFilePaths.push(...files);
    }

    const uniqueFiles = [...new Set(allFilePaths)];

    // Classify all files
    const fileMap = new Map<string, FileClassification>();
    for (const filePath of uniqueFiles) {
      const classified = classifyFile(filePath, projectPath);
      if (classified) fileMap.set(filePath, classified);
    }

    // Run checks on each file
    for (const file of fileMap.values()) {
      const propIssues = checkNonSerializableProps(file);
      issues.push(...propIssues);

      const clientServerIssues = checkClientImportingServerOnly(file, fileMap);
      issues.push(...clientServerIssues);

      const serverActionIssues = checkServerActionImportsInClient(file);
      issues.push(...serverActionIssues);
    }
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      scanner: 'rsc-boundary',
      issues: [],
      duration: Date.now() - startTime,
      error: message,
    };
  }

  return {
    scanner: 'rsc-boundary',
    issues,
    duration: Date.now() - startTime,
  };
}
