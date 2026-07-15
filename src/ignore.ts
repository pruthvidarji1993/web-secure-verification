import * as fs from 'fs';
import * as path from 'path';
import { Issue } from './types';

export interface IgnoreConfig {
  ignoredFiles: Set<string>;          // file paths to completely ignore
  ignoredScanners: Set<string>;       // scanner names to skip
  ignoredRuleIds: Set<string>;        // specific rule IDs to ignore globally
  ignoredFilePatterns: RegExp[];      // glob-style patterns converted to regex
}

export function loadIgnoreConfig(projectPath: string, ignoreFilePath?: string): IgnoreConfig {
  const config: IgnoreConfig = {
    ignoredFiles: new Set(),
    ignoredScanners: new Set(),
    ignoredRuleIds: new Set(),
    ignoredFilePatterns: [],
  };

  const candidates = ignoreFilePath
    ? [ignoreFilePath]
    : [
        path.join(projectPath, '.scannerignore'),
        path.join(projectPath, '.wsvignore'),
      ];

  let ignoreFilePath2: string | null = null;
  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) {
      ignoreFilePath2 = candidate;
      break;
    }
  }

  if (!ignoreFilePath2) return config;

  const lines = fs.readFileSync(ignoreFilePath2, 'utf8').split('\n');

  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;

    // Directives: "scanner:<name>", "rule:<ruleId>", "file:<path>"
    if (line.startsWith('scanner:')) {
      config.ignoredScanners.add(line.slice('scanner:'.length).trim());
    } else if (line.startsWith('rule:')) {
      config.ignoredRuleIds.add(line.slice('rule:'.length).trim());
    } else if (line.startsWith('file:')) {
      config.ignoredFiles.add(line.slice('file:'.length).trim());
    } else {
      // Treat as a glob pattern for file paths
      // Convert simple glob to regex: * → [^/]*, ** → .*
      const regexStr = line
        .replace(/[.+^${}()|[\]\\]/g, '\\$&')
        .replace(/\\\*/g, '*')
        .replace(/\*\*/g, '.*')
        .replace(/\*/g, '[^/]*');
      try {
        config.ignoredFilePatterns.push(new RegExp(regexStr));
      } catch {
        // invalid pattern, skip
      }
    }
  }

  return config;
}

export function shouldIgnoreIssue(issue: Issue, ignoreConfig: IgnoreConfig): boolean {
  // Check scanner-level ignore
  if (ignoreConfig.ignoredScanners.has(issue.scanner)) return true;

  // Check rule ID ignore
  if (issue.ruleId && ignoreConfig.ignoredRuleIds.has(issue.ruleId)) return true;
  if (ignoreConfig.ignoredRuleIds.has(issue.id)) return true;

  // Check file-level ignore
  if (issue.file) {
    if (ignoreConfig.ignoredFiles.has(issue.file)) return true;
    for (const pattern of ignoreConfig.ignoredFilePatterns) {
      if (pattern.test(issue.file)) return true;
    }
  }

  return false;
}

export function applyInlineIgnores(
  content: string,
  issues: Issue[],
  filePath: string,
  projectPath: string
): Issue[] {
  const lines = content.split('\n');
  const relPath = path.relative(projectPath, filePath);

  // Find all lines with disable directives
  const disabledLines = new Map<number, Set<string>>(); // lineNumber → set of ruleIds (empty = all)
  const disabledRangeStart = new Map<number, Set<string>>(); // for wsv-disable (multi-line)
  const disabledRangeEnd = new Set<number>(); // lines where enable is found

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1;

    // wsv-disable-next-line [rule1, rule2] OR wsv-disable-next-line (all)
    const nextLineMatch = line.match(/\/\/\s*wsv-disable-next-line\s*(.*)/);
    if (nextLineMatch) {
      const rules = nextLineMatch[1].trim();
      const ruleSet: Set<string> = rules ? new Set(rules.split(/[\s,]+/).filter(Boolean)) : new Set();
      disabledLines.set(lineNum + 1, ruleSet);
    }

    // wsv-disable [rules] (start of block)
    const disableMatch = line.match(/\/\/\s*wsv-disable\s*(.*)/);
    if (disableMatch && !line.includes('wsv-disable-next-line')) {
      const rules = disableMatch[1].trim();
      const ruleSet: Set<string> = rules ? new Set(rules.split(/[\s,]+/).filter(Boolean)) : new Set();
      disabledRangeStart.set(lineNum, ruleSet);
    }

    // wsv-enable
    if (/\/\/\s*wsv-enable/.test(line)) {
      disabledRangeEnd.add(lineNum);
    }
  }

  // Build range-disabled lines
  let activeRangeRules: Set<string> | null = null;
  const rangeDisabledLines = new Map<number, Set<string>>();
  for (let i = 1; i <= lines.length + 1; i++) {
    if (disabledRangeStart.has(i)) {
      activeRangeRules = disabledRangeStart.get(i)!;
    }
    if (disabledRangeEnd.has(i)) {
      activeRangeRules = null;
    }
    if (activeRangeRules !== null) {
      rangeDisabledLines.set(i, activeRangeRules);
    }
  }

  return issues.filter((issue) => {
    if (!issue.file || issue.file !== relPath) return true;
    if (issue.line === undefined) return true;

    const lineDisabled = disabledLines.get(issue.line);
    const rangeDisabled = rangeDisabledLines.get(issue.line);

    function isDisabledByRuleSet(ruleSet: Set<string>): boolean {
      if (ruleSet.size === 0) return true; // all rules disabled
      if (issue.ruleId && ruleSet.has(issue.ruleId)) return true;
      if (ruleSet.has(issue.id)) return true;
      if (ruleSet.has(issue.scanner)) return true;
      return false;
    }

    if (lineDisabled !== undefined && isDisabledByRuleSet(lineDisabled)) return false;
    if (rangeDisabled !== undefined && isDisabledByRuleSet(rangeDisabled)) return false;

    return true;
  });
}
