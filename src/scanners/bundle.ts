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

// Heavy packages that should be lazy-loaded when used in page components
const HEAVY_PACKAGES = [
  'recharts',
  'chart.js',
  'react-chartjs-2',
  'monaco-editor',
  '@uiw/react-md-editor',
  'react-quill',
  'draft-js',
  'slate',
];

interface BundleCheck {
  id: string;
  pattern: RegExp;
  title: string;
  description: string;
  severity: 'high' | 'medium' | 'low';
  fix: string;
  references: string[];
  fixable: boolean;
}

const BUNDLE_CHECKS: BundleCheck[] = [
  {
    id: 'full-lodash-import',
    pattern: /^import\s+\w+\s+from\s+['"]lodash['"]|^import\s+\*\s+as\s+\w+\s+from\s+['"]lodash['"]/gm,
    title: 'Full lodash import detected',
    description:
      'Importing the entire lodash library adds approximately 70KB (minified) to your bundle. ' +
      'Most applications only use a small subset of lodash functions.',
    severity: 'high',
    fix:
      "Import only the specific lodash functions you need. For example, instead of:\n" +
      "  import _ from 'lodash'\n" +
      "Use:\n" +
      "  import debounce from 'lodash/debounce'\n" +
      "  import throttle from 'lodash/throttle'\n" +
      "Or consider using es-toolkit, which provides tree-shakeable alternatives.",
    references: [
      'https://bundlephobia.com/package/lodash',
      'https://github.com/nicolo-ribaudo/tc39-proposal-esm-phase-imports',
    ],
    fixable: false,
  },
  {
    id: 'moment-import',
    pattern: /^import\s+\w+\s+from\s+['"]moment['"]/gm,
    title: 'moment.js import detected',
    description:
      'moment.js adds approximately 232KB (minified) to your bundle and is no longer actively maintained. ' +
      'It is not tree-shakeable, so the entire library is included even if you only use one function.',
    severity: 'high',
    fix:
      "Replace moment.js with a lighter alternative:\n" +
      "  - date-fns (~13KB, tree-shakeable): import { format } from 'date-fns'\n" +
      "  - dayjs (~7KB, similar API): import dayjs from 'dayjs'\n" +
      "  - Luxon (~23KB): import { DateTime } from 'luxon'",
    references: [
      'https://bundlephobia.com/package/moment',
      'https://you-dont-need.github.io/You-Dont-Need-Momentjs/',
    ],
    fixable: false,
  },
  {
    id: 'star-import-large-lib',
    pattern:
      /^import\s+\*\s+as\s+\w+\s+from\s+['"](?:rxjs|d3|three|antd|@mui\/material|@material-ui\/core)['"]/gm,
    title: 'Wildcard import from large library',
    description:
      'Importing everything from a large library (rxjs, d3, three.js, antd, MUI) prevents tree-shaking ' +
      'and forces the bundler to include the entire library in your bundle.',
    severity: 'medium',
    fix:
      "Import only the specific submodules or exports you need. For example:\n" +
      "  rxjs: import { Observable, map } from 'rxjs'\n" +
      "  d3: import { select } from 'd3-selection'; import { scaleLinear } from 'd3-scale'\n" +
      "  three: import { Scene, PerspectiveCamera } from 'three'\n" +
      "  MUI: import Button from '@mui/material/Button'",
    references: ['https://webpack.js.org/guides/tree-shaking/'],
    fixable: false,
  },
  {
    id: 'sync-require-in-component',
    pattern: /=\s*require\s*\(/g,
    title: 'Synchronous require() in source file',
    description:
      'Using synchronous require() in React component files prevents code splitting and lazy loading. ' +
      "It forces the module to be included in the initial bundle, increasing the page's load time.",
    severity: 'medium',
    fix:
      "Replace require() with dynamic import() for code splitting:\n" +
      "  const module = await import('./module');\n" +
      "For React components, use React.lazy():\n" +
      "  const Component = React.lazy(() => import('./Component'));\n" +
      "Or in Next.js: import dynamic from 'next/dynamic'; const Component = dynamic(() => import('./Component'));",
    references: [
      'https://react.dev/reference/react/lazy',
      'https://nextjs.org/docs/pages/building-your-application/optimizing/lazy-loading',
    ],
    fixable: false,
  },
];

function isCommentLine(line: string): boolean {
  const trimmed = line.trim();
  return trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('/*');
}

function checkHeavyPackageLazyLoading(
  content: string,
  relativePath: string,
): Issue[] {
  const issues: Issue[] = [];

  // Only flag in files that are page/component files (have export default function)
  const isPageOrComponent = /export\s+default\s+(?:function|class|\w)/.test(content);
  if (!isPageOrComponent) return issues;

  // Check if any heavy package is imported without lazy loading
  const hasLazyLoad =
    /dynamic\s*\(/.test(content) ||
    /React\.lazy\s*\(/.test(content) ||
    /import\s*\(/.test(content);

  for (const pkg of HEAVY_PACKAGES) {
    // Escape dots in package names for regex
    const escapedPkg = pkg.replace(/[.]/g, '\\.').replace(/\//g, '\\/');
    const importPattern = new RegExp(
      `^import\\s+.+\\s+from\\s+['"]${escapedPkg}['"]`,
      'gm',
    );

    let match: RegExpExecArray | null;
    while ((match = importPattern.exec(content)) !== null) {
      const lines = content.split('\n');
      const lineNumber = content.substring(0, match.index).split('\n').length;
      const lineContent = lines[lineNumber - 1] || '';

      if (isCommentLine(lineContent)) continue;

      // If the file uses any lazy loading, give benefit of the doubt — but still warn
      issues.push({
        id: `bundle-heavy-package-not-lazy-${relativePath}-${lineNumber}`,
        title: `Heavy package "${pkg}" imported without lazy loading`,
        description:
          `The package "${pkg}" is a large library that significantly increases bundle size. ` +
          `It is imported at the top level of a page/component file without using React.lazy() or ` +
          `next/dynamic, which means it will be included in the initial bundle and slow down page load.` +
          (hasLazyLoad
            ? '\n\nNote: the file uses lazy loading elsewhere — verify this import is intentional.'
            : ''),
        severity: 'low',
        scanner: 'bundle',
        file: relativePath,
        line: lineNumber,
        fix:
          `Lazy-load "${pkg}" to reduce initial bundle size:\n` +
          `  Next.js: const Component = dynamic(() => import('${pkg}'), { ssr: false });\n` +
          `  React: const Component = React.lazy(() => import('${pkg}'));`,
        fixable: false,
        references: [
          'https://nextjs.org/docs/pages/building-your-application/optimizing/lazy-loading',
          'https://react.dev/reference/react/lazy',
        ],
        metadata: { packageName: pkg },
      });
    }
  }

  return issues;
}

function scanFileForBundleIssues(filePath: string, projectPath: string): Issue[] {
  const issues: Issue[] = [];

  let content: string;
  try {
    content = fs.readFileSync(filePath, 'utf8');
  } catch {
    return issues;
  }

  const relativePath = path.relative(projectPath, filePath);
  const lines = content.split('\n');

  // Run pattern-based checks
  for (const check of BUNDLE_CHECKS) {
    const regex = new RegExp(check.pattern.source, check.pattern.flags);
    let match: RegExpExecArray | null;

    while ((match = regex.exec(content)) !== null) {
      const lineNumber = content.substring(0, match.index).split('\n').length;
      const lineContent = lines[lineNumber - 1] || '';

      if (isCommentLine(lineContent)) continue;

      // For sync require, only flag if it looks like it's inside a function body
      // (not a top-level CJS require pattern in config files)
      if (check.id === 'sync-require-in-component') {
        // Skip config files
        if (
          relativePath.includes('config') ||
          relativePath.endsWith('.config.js') ||
          relativePath.endsWith('.config.ts')
        ) {
          continue;
        }
        // Skip if it doesn't look like a React component (no JSX)
        if (!/<[A-Z][a-zA-Z]*[\s/>]|<[a-z]+[\s/>]/.test(content)) continue;
      }

      issues.push({
        id: `bundle-${check.id}-${relativePath}-${lineNumber}`,
        title: check.title,
        description:
          `${check.description}\n\nFound in: ${relativePath}:${lineNumber}\n` +
          `Code: ${lineContent.trim().substring(0, 120)}`,
        severity: check.severity,
        scanner: 'bundle',
        file: relativePath,
        line: lineNumber,
        fix: check.fix,
        fixable: check.fixable,
        references: check.references,
      });
    }
  }

  // Run heavy package lazy-loading check
  const heavyIssues = checkHeavyPackageLazyLoading(content, relativePath);
  issues.push(...heavyIssues);

  return issues;
}

export async function runBundleScanner(projectPath: string): Promise<ScanResult> {
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
      const fileIssues = scanFileForBundleIssues(filePath, projectPath);
      issues.push(...fileIssues);
    }
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      scanner: 'bundle',
      issues: [],
      duration: Date.now() - startTime,
      error: message,
    };
  }

  return {
    scanner: 'bundle',
    issues,
    duration: Date.now() - startTime,
  };
}
