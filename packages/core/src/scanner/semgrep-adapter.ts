import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { which } from '../utils.js';
import type { FileEntry } from '../ingestion.js';
import type { Finding, Severity, Category, ScannerAdapter } from './types.js';
import { RegexAdapter } from './regex-adapter.js';

const execFileAsync = promisify(execFile);

interface SemgrepMatch {
  check_id: string;
  path: string;
  start: { line: number };
  extra: {
    message: string;
    severity: string;
    metadata?: { category?: string };
  };
}

interface SemgrepOutput {
  results: SemgrepMatch[];
}

function mapSeverity(s: string): Severity {
  const upper = s.toUpperCase();
  if (upper === 'ERROR' || upper === 'CRITICAL') return 'CRITICAL';
  if (upper === 'WARNING' || upper === 'HIGH') return 'HIGH';
  if (upper === 'INFO' || upper === 'MEDIUM') return 'MEDIUM';
  if (upper === 'LOW') return 'LOW';
  return 'INFO';
}

function mapCategory(cat?: string): Category {
  const valid: Category[] = [
    'filesystem', 'shell', 'network', 'secrets', 'obfuscation',
    'prompt_injection', 'context_poisoning', 'consent_gap', 'cross_file_chain',
  ];
  if (cat && valid.includes(cat as Category)) return cat as Category;
  return 'shell';
}

export class SemgrepAdapter implements ScannerAdapter {
  name = 'semgrep';

  async scan(files: FileEntry[], skillRoot: string): Promise<Finding[]> {
    const semgrepBin = await which('semgrep');
    if (!semgrepBin) {
      console.warn('[stss] semgrep not found on PATH; falling back to RegexAdapter');
      return new RegexAdapter().scan(files, skillRoot);
    }

    try {
      const { stdout } = await execFileAsync(semgrepBin, [
        '--json',
        '--config', 'auto',
        skillRoot,
      ]);

      const output: SemgrepOutput = JSON.parse(stdout);
      return output.results.map((r, i) => ({
        id: `SEMGREP-${String(i + 1).padStart(3, '0')}`,
        severity: mapSeverity(r.extra.severity),
        category: mapCategory(r.extra.metadata?.category),
        location: { file: r.path.replace(skillRoot + '/', ''), line: r.start.line },
        message: r.extra.message,
        source: 'static' as const,
      }));
    } catch (err) {
      console.warn('[stss] semgrep execution failed; falling back to RegexAdapter:', err);
      return new RegexAdapter().scan(files, skillRoot);
    }
  }
}
