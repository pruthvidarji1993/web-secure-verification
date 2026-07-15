import * as fs from 'fs';
import { Report, Severity } from '../types';

function severityToSarifLevel(severity: Severity): string {
  switch (severity) {
    case 'critical': return 'error';
    case 'high': return 'error';
    case 'medium': return 'warning';
    case 'low': return 'note';
    case 'info': return 'none';
  }
}

function buildRules(report: Report) {
  const seenRuleIds = new Set<string>();
  const rules: object[] = [];

  for (const result of report.results) {
    for (const issue of result.issues) {
      const ruleId = issue.ruleId || issue.id;
      if (!seenRuleIds.has(ruleId)) {
        seenRuleIds.add(ruleId);
        rules.push({
          id: ruleId,
          name: issue.title.replace(/[^a-zA-Z0-9]/g, ''),
          shortDescription: { text: issue.title },
          fullDescription: { text: issue.description.split('\n')[0] },
          defaultConfiguration: {
            level: severityToSarifLevel(issue.severity),
          },
          properties: {
            tags: [issue.scanner, 'security'],
            severity: issue.severity,
          },
        });
      }
    }
  }

  return rules;
}

function buildResults(report: Report) {
  const results: object[] = [];

  for (const scanResult of report.results) {
    for (const issue of scanResult.issues) {
      const ruleId = issue.ruleId || issue.id;
      const result: Record<string, unknown> = {
        ruleId,
        level: severityToSarifLevel(issue.severity),
        message: {
          text: issue.description.split('\n')[0],
        },
      };

      if (issue.file) {
        result.locations = [
          {
            physicalLocation: {
              artifactLocation: {
                uri: issue.file.replace(/\\/g, '/'),
                uriBaseId: '%SRCROOT%',
              },
              region: issue.line
                ? {
                    startLine: issue.line,
                    startColumn: 1,
                  }
                : undefined,
            },
          },
        ];
      } else {
        result.locations = [
          {
            physicalLocation: {
              artifactLocation: {
                uri: '.',
                uriBaseId: '%SRCROOT%',
              },
            },
          },
        ];
      }

      if (issue.fix) {
        result.fixes = [
          {
            description: { text: issue.fix },
          },
        ];
      }

      results.push(result);
    }
  }

  return results;
}

export function renderSarifReport(report: Report, outputPath?: string): string {
  const sarif = {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'web-secure-verification',
            version: '1.0.0',
            informationUri: 'https://www.npmjs.com/package/web-secure-verification',
            rules: buildRules(report),
          },
        },
        results: buildResults(report),
        artifacts: [],
        columnKind: 'unicodeCodePoints',
      },
    ],
  };

  const output = JSON.stringify(sarif, null, 2);

  if (outputPath) {
    fs.writeFileSync(outputPath, output, 'utf8');
  }

  return output;
}
