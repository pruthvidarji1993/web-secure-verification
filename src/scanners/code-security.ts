import * as fs from 'fs';
import * as path from 'path';
import { glob } from 'glob';
import { Issue, ScanResult, Severity } from '../types';

interface CodePattern {
  id: string;
  name: string;
  pattern: RegExp;
  severity: Severity;
  description: string;
  fix: string;
}

const CODE_PATTERNS: CodePattern[] = [
  {
    id: 'eval-usage',
    name: 'Use of eval()',
    pattern: /\beval\s*\(/g,
    severity: 'critical',
    description:
      'eval() executes arbitrary code and is a major security risk. It can execute malicious code if user input is passed to it.',
    fix: 'Replace eval() with safer alternatives like JSON.parse() for data, or refactor the logic.',
  },
  {
    id: 'new-function',
    name: 'Use of new Function()',
    pattern: /new\s+Function\s*\(/g,
    severity: 'high',
    description:
      'new Function() is similar to eval() and can execute arbitrary code. This is dangerous if user input influences the function body.',
    fix: 'Replace with a safer alternative. Consider using a proper expression parser or restructuring the code.',
  },
  {
    id: 'dangerous-inner-html',
    name: 'dangerouslySetInnerHTML usage',
    pattern: /dangerouslySetInnerHTML\s*=\s*\{\s*\{?\s*__html\s*:/g,
    severity: 'high',
    description:
      'dangerouslySetInnerHTML can introduce XSS vulnerabilities if the content is not properly sanitized.',
    fix: 'Sanitize HTML content using a library like DOMPurify before passing it to dangerouslySetInnerHTML.',
  },
  {
    id: 'inner-html-assignment',
    name: 'innerHTML assignment',
    pattern: /\.innerHTML\s*=/g,
    severity: 'high',
    description:
      'Direct innerHTML assignment can introduce XSS vulnerabilities if the content includes unsanitized user input.',
    fix: 'Use textContent for plain text, or sanitize HTML with DOMPurify before assigning to innerHTML.',
  },
  {
    id: 'document-write',
    name: 'document.write() usage',
    pattern: /\bdocument\.write\s*\(/g,
    severity: 'medium',
    description:
      'document.write() can introduce XSS vulnerabilities and overwrites the entire document when called after page load.',
    fix: 'Use DOM manipulation methods (createElement, appendChild, textContent) instead of document.write().',
  },
  {
    id: 'exec-string-concat',
    name: 'exec() with string concatenation',
    pattern: /(?:exec|execSync|spawn|spawnSync)\s*\(\s*(?:[^)]*\+[^)]*|`[^`]*\$\{)/g,
    severity: 'high',
    description:
      'Using exec() with string concatenation or template literals containing variables can lead to command injection.',
    fix: 'Use execFile() or spawn() with array arguments instead of string concatenation. Validate and sanitize all inputs.',
  },
  {
    id: 'dangerous-disable-sanitizers',
    name: '__dangerouslyDisableSanitizers usage',
    pattern: /__dangerouslyDisableSanitizers/g,
    severity: 'high',
    description:
      '__dangerouslyDisableSanitizers disables built-in security sanitization and can introduce XSS vulnerabilities.',
    fix: 'Remove __dangerouslyDisableSanitizers and use proper sanitization methods.',
  },
  {
    id: 'eslint-disable-security',
    name: 'ESLint security rule disabled',
    pattern:
      /\/\/\s*eslint-disable(?:-next-line)?\s+(?:security\/|no-eval|no-implied-eval|no-new-func)/g,
    severity: 'low',
    description:
      'An ESLint security rule has been disabled. This may indicate a security issue that has been suppressed instead of fixed.',
    fix: 'Fix the underlying security issue instead of disabling the ESLint rule.',
  },
  {
    id: 'math-random-security',
    name: 'Math.random() for security purposes',
    pattern:
      /Math\.random\(\)[^;]*(?:token|secret|id|key|nonce|csrf|session|auth|password|salt)/gi,
    severity: 'medium',
    description:
      'Math.random() is not cryptographically secure and should not be used for security-sensitive values like tokens, IDs, or secrets.',
    fix: 'Use crypto.randomBytes() or crypto.randomUUID() for cryptographically secure random values.',
  },
  {
    id: 'http-hardcoded-url',
    name: 'Hardcoded HTTP URL',
    pattern: /['"`]http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])[a-zA-Z0-9][\w.-]*[^\s'"`]*/g,
    severity: 'low',
    description:
      'Hardcoded HTTP URL found. HTTP traffic is not encrypted and can be intercepted (man-in-the-middle attacks).',
    fix: 'Use HTTPS instead of HTTP for all external URLs.',
  },
];

function isInNonCodeContext(line: string, matchIndex: number): boolean {
  let inSingle = false;
  let inDouble = false;
  let inBacktick = false;
  let inRegex = false;
  let prevNonSpace = '';

  for (let i = 0; i < matchIndex && i < line.length; i++) {
    const char = line[i];

    if (char === '\\' && (inSingle || inDouble || inBacktick || inRegex)) {
      i++;
      continue;
    }

    if (!inDouble && !inBacktick && !inRegex && char === "'") {
      inSingle = !inSingle;
    } else if (!inSingle && !inBacktick && !inRegex && char === '"') {
      inDouble = !inDouble;
    } else if (!inSingle && !inDouble && !inRegex && char === '`') {
      inBacktick = !inBacktick;
    } else if (!inSingle && !inDouble && !inBacktick && char === '/') {
      if (inRegex) {
        inRegex = false;
      } else if (/[=(,!&|?:[\s]/.test(prevNonSpace) || prevNonSpace === '') {
        inRegex = true;
      }
    }

    if (char !== ' ' && char !== '\t') prevNonSpace = char;
  }

  return inSingle || inDouble || inBacktick || inRegex;
}

function scanFileForCodeIssues(filePath: string, projectPath: string): Issue[] {
  const issues: Issue[] = [];

  let content: string;
  try {
    content = fs.readFileSync(filePath, 'utf8');
  } catch {
    return issues;
  }

  const relativePath = path.relative(projectPath, filePath);
  const lines = content.split('\n');

  for (const codePattern of CODE_PATTERNS) {
    const regex = new RegExp(codePattern.pattern.source, codePattern.pattern.flags);
    let match: RegExpExecArray | null;

    while ((match = regex.exec(content)) !== null) {
      const lineNumber = content.substring(0, match.index).split('\n').length;
      const lineContent = lines[lineNumber - 1] || '';

      // Skip commented-out code
      const trimmedLine = lineContent.trim();
      if (trimmedLine.startsWith('//') || trimmedLine.startsWith('*')) {
        continue;
      }

      // Skip matches inside string literals or regex literals
      const lineStart = content.lastIndexOf('\n', match.index - 1) + 1;
      const charIndexInLine = match.index - lineStart;
      if (isInNonCodeContext(lineContent, charIndexInLine)) {
        continue;
      }

      // For Math.random check, ensure it's actually near security-sensitive context
      if (codePattern.id === 'math-random-security') {
        // Check surrounding context (5 lines before and after)
        const contextStart = Math.max(0, lineNumber - 6);
        const contextEnd = Math.min(lines.length, lineNumber + 5);
        const context = lines.slice(contextStart, contextEnd).join('\n').toLowerCase();
        if (
          !context.includes('token') &&
          !context.includes('secret') &&
          !context.includes('nonce') &&
          !context.includes('csrf') &&
          !context.includes('session') &&
          !context.includes('auth') &&
          !context.includes('password') &&
          !context.includes('salt') &&
          !context.includes('key')
        ) {
          continue;
        }
      }

      issues.push({
        id: `code-security-${codePattern.id}-${relativePath}-${lineNumber}`,
        title: codePattern.name,
        description: `${codePattern.description}\n\nFound in: ${relativePath}:${lineNumber}\nCode: ${lineContent.trim().substring(0, 100)}`,
        severity: codePattern.severity,
        scanner: 'code-security',
        file: relativePath,
        line: lineNumber,
        fix: codePattern.fix,
      });
    }
  }

  return issues;
}

export async function runCodeSecurityScanner(projectPath: string): Promise<ScanResult> {
  const startTime = Date.now();
  const issues: Issue[] = [];

  try {
    const patterns = ['**/*.js', '**/*.ts', '**/*.jsx', '**/*.tsx'];
    const ignorePatterns = [
      '**/node_modules/**',
      '**/.next/**',
      '**/dist/**',
      '**/build/**',
      '**/.git/**',
      '**/coverage/**',
      '**/*.min.js',
      '**/*.bundle.js',
    ];

    const allFiles: string[] = [];

    for (const pattern of patterns) {
      const files = await glob(pattern, {
        cwd: projectPath,
        absolute: true,
        ignore: ignorePatterns,
      });
      allFiles.push(...files);
    }

    const uniqueFiles = [...new Set(allFiles)];

    for (const filePath of uniqueFiles) {
      const fileIssues = scanFileForCodeIssues(filePath, projectPath);
      issues.push(...fileIssues);
    }
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      scanner: 'code-security',
      issues: [],
      duration: Date.now() - startTime,
      error: message,
    };
  }

  return {
    scanner: 'code-security',
    issues,
    duration: Date.now() - startTime,
  };
}
