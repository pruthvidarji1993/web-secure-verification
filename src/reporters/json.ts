import * as fs from 'fs';
import { Report } from '../types';

export function renderJsonReport(report: Report, outputPath?: string): string {
  const json = JSON.stringify(report, null, 2);

  if (outputPath) {
    fs.writeFileSync(outputPath, json, 'utf8');
  }

  return json;
}
