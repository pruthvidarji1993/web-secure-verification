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

// Only scan component files — hydration issues only occur in React components
const SOURCE_PATTERNS = ['**/*.tsx', '**/*.jsx'];

function isInNonCodeContext(line: string, matchIndex: number): boolean {
  let inSingle = false;
  let inDouble = false;
  let inBacktick = false;
  let inRegex = false;
  let prevNonSpace = '';

  for (let i = 0; i < matchIndex && i < line.length; i++) {
    const char = line[i];
    if (char === '\\' && (inSingle || inDouble || inBacktick || inRegex)) { i++; continue; }
    if (!inDouble && !inBacktick && !inRegex && char === "'") inSingle = !inSingle;
    else if (!inSingle && !inBacktick && !inRegex && char === '"') inDouble = !inDouble;
    else if (!inSingle && !inDouble && !inRegex && char === '`') inBacktick = !inBacktick;
    else if (!inSingle && !inDouble && !inBacktick && char === '/') {
      if (inRegex) inRegex = false;
      else if (/[=(,!&|?:[\s]/.test(prevNonSpace) || prevNonSpace === '') inRegex = true;
    }
    if (char !== ' ' && char !== '\t') prevNonSpace = char;
  }
  return inSingle || inDouble || inBacktick || inRegex;
}

// Check if a line is a comment (simple heuristic)
function isCommentLine(line: string): boolean {
  const trimmed = line.trim();
  return (
    trimmed.startsWith('//') ||
    trimmed.startsWith('*') ||
    trimmed.startsWith('/*')
  );
}

// Check if content contains JSX (heuristic: has JSX-like angle brackets)
function hasJsx(content: string): boolean {
  return /<[A-Z][a-zA-Z]*[\s/>]|<[a-z]+[\s/>]|return\s*\([\s\S]*</.test(content);
}

// Check if a match is inside a useEffect, useCallback, useMemo, or useRef block
// Simple heuristic: look for one of these hook names within 10 lines above the match
function isInsideSafeHook(lines: string[], lineNumber: number): boolean {
  const SAFE_HOOKS = ['useEffect', 'useCallback', 'useMemo', 'useRef', 'useLayoutEffect'];
  const start = Math.max(0, lineNumber - 11);
  const contextLines = lines.slice(start, lineNumber - 1);

  return contextLines.some((l) => SAFE_HOOKS.some((hook) => l.includes(hook)));
}

interface HydrationCheck {
  id: string;
  pattern: RegExp;
  title: string;
  description: string;
  severity: 'high' | 'medium' | 'low';
  fix: string;
  references: string[];
  requiresJsx: boolean;
  requiresOutsideHook: boolean;
}

const HYDRATION_CHECKS: HydrationCheck[] = [
  {
    id: 'browser-api-in-render',
    pattern: /(?:window|document|navigator)\s*[.[]/g,
    title: 'Browser API (window/document/navigator) accessed outside useEffect',
    description:
      'Accessing window, document, or navigator during render causes hydration mismatches because ' +
      'these APIs do not exist on the server. The server renders without these globals, ' +
      'while the client has them, leading to a mismatch.',
    severity: 'high',
    fix:
      'Wrap browser API access in a useEffect hook to ensure it only runs on the client. ' +
      'Alternatively, use the "typeof window !== \'undefined\'" guard for conditional logic.',
    references: [
      'https://nextjs.org/docs/messages/react-hydration-error',
      'https://react.dev/reference/react-dom/client/hydrateRoot',
    ],
    requiresJsx: true,
    requiresOutsideHook: true,
  },
  {
    id: 'new-date-in-render',
    pattern: /new\s+Date\s*\(\s*\)/g,
    title: 'new Date() used in render — potential hydration mismatch',
    description:
      'Calling new Date() during render returns different timestamps on the server and client, ' +
      'because they execute at different times. This causes React hydration errors in production.',
    severity: 'medium',
    fix:
      'Move new Date() inside a useEffect hook to generate the value only on the client. ' +
      'For static dates, compute them at module level or pass them as props from a Server Component.',
    references: ['https://nextjs.org/docs/messages/react-hydration-error'],
    requiresJsx: true,
    requiresOutsideHook: true,
  },
  {
    id: 'math-random-in-render',
    pattern: /Math\.random\s*\(\s*\)/g,
    title: 'Math.random() used in render — potential hydration mismatch',
    description:
      'Calling Math.random() during render produces different values on the server and client, ' +
      'causing hydration mismatches. Each render pass yields a different random number.',
    severity: 'medium',
    fix:
      'Move Math.random() inside useEffect, or generate the random value on the server and pass it as a prop. ' +
      'For stable IDs, use useId() from React.',
    references: [
      'https://react.dev/reference/react/useId',
      'https://nextjs.org/docs/messages/react-hydration-error',
    ],
    requiresJsx: true,
    requiresOutsideHook: true,
  },
  {
    id: 'storage-in-render',
    pattern: /(?:localStorage|sessionStorage)\s*\./g,
    title: 'localStorage/sessionStorage accessed outside useEffect',
    description:
      'localStorage and sessionStorage are not available on the server (Node.js environment). ' +
      'Accessing them during render causes a ReferenceError on the server and hydration mismatches on the client.',
    severity: 'high',
    fix:
      'Wrap all localStorage/sessionStorage access in useEffect to ensure it only runs client-side. ' +
      'Never read storage during the initial render or in Server Components.',
    references: ['https://nextjs.org/docs/messages/react-hydration-error'],
    requiresJsx: true,
    requiresOutsideHook: true,
  },
  {
    id: 'typeof-window-conditional',
    pattern: /typeof\s+window\s*!==?\s*['"]undefined['"]|typeof\s+window\s*===?\s*['"]undefined['"]/g,
    title: 'Conditional rendering based on typeof window',
    description:
      'Using typeof window to conditionally render content causes hydration mismatches. ' +
      'The server always sees window as undefined, while the client sees it defined, ' +
      'so the rendered HTML differs between server and client.',
    severity: 'low',
    fix:
      'Use a state variable initialized in useEffect to track client-side mounting. ' +
      'Example: const [mounted, setMounted] = useState(false); useEffect(() => setMounted(true), []); ' +
      'Then conditionally render based on mounted.',
    references: [
      'https://nextjs.org/docs/messages/react-hydration-error',
      'https://joshwcomeau.com/react/the-perils-of-rehydration/',
    ],
    requiresJsx: false,
    requiresOutsideHook: false,
  },
];

function scanFileForHydrationIssues(filePath: string, projectPath: string): Issue[] {
  const issues: Issue[] = [];

  let content: string;
  try {
    content = fs.readFileSync(filePath, 'utf8');
  } catch {
    return issues;
  }

  const relativePath = path.relative(projectPath, filePath);
  const lines = content.split('\n');
  const fileHasJsx = hasJsx(content);

  for (const check of HYDRATION_CHECKS) {
    // Skip JSX-dependent checks if file has no JSX
    if (check.requiresJsx && !fileHasJsx) continue;

    const regex = new RegExp(check.pattern.source, check.pattern.flags);
    let match: RegExpExecArray | null;

    while ((match = regex.exec(content)) !== null) {
      const lineNumber = content.substring(0, match.index).split('\n').length;
      const lineContent = lines[lineNumber - 1] || '';

      // Skip comment lines
      if (isCommentLine(lineContent)) continue;

      const trimmed = lineContent.trim();

      // Skip if match position is inside a string or regex literal
      const lineStart = content.lastIndexOf('\n', match.index - 1) + 1;
      const charIndexInLine = match.index - lineStart;
      if (isInNonCodeContext(lineContent, charIndexInLine)) continue;

      // Skip if inside a safe hook
      if (check.requiresOutsideHook && isInsideSafeHook(lines, lineNumber)) continue;

      issues.push({
        id: `hydration-${check.id}-${relativePath}-${lineNumber}`,
        title: check.title,
        description:
          `${check.description}\n\nFound in: ${relativePath}:${lineNumber}\n` +
          `Code: ${trimmed.substring(0, 120)}`,
        severity: check.severity,
        scanner: 'hydration',
        file: relativePath,
        line: lineNumber,
        fix: check.fix,
        fixable: false,
        references: check.references,
        metadata: { matchedText: match[0] },
      });
    }
  }

  return issues;
}

export async function runHydrationScanner(projectPath: string): Promise<ScanResult> {
  const startTime = Date.now();
  const issues: Issue[] = [];

  try {
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

    for (const filePath of uniqueFiles) {
      const fileIssues = scanFileForHydrationIssues(filePath, projectPath);
      issues.push(...fileIssues);
    }
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      scanner: 'hydration',
      issues: [],
      duration: Date.now() - startTime,
      error: message,
    };
  }

  return {
    scanner: 'hydration',
    issues,
    duration: Date.now() - startTime,
  };
}
