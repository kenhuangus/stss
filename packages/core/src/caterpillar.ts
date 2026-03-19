/**
 * Caterpillar integration — optional parallel scanning stage.
 *
 * If `caterpillar` is installed (npm i -g @alice-io/caterpillar), this module
 * shells out to it and merges its findings into the STSS pipeline.  When not
 * installed the stage is silently skipped.
 *
 * Two modes:
 *   • offline  — local pattern matching only (no auth required)
 *   • alice    — full behavioral analysis (free, requires `caterpillar login`)
 */

import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { which } from './utils.js';
import type { Finding, Severity, Category } from './scanner/types.js';

const execFileAsync = promisify(execFile);

// ── Caterpillar JSON response types ────────────────────────────────────────

interface CaterpillarFinding {
  severity: string;
  category: string;
  title: string;
  description: string;
  evidence?: string;
  recommendation?: string;
}

interface CaterpillarResponse {
  success: boolean;
  data?: {
    skill: string;
    grade: string;
    score: number;
    findings: CaterpillarFinding[];
    summary: string;
  };
  error?: { code: string; message: string };
}

// ── Mapping helpers ────────────────────────────────────────────────────────

const SEVERITY_MAP: Record<string, Severity> = {
  critical: 'CRITICAL',
  high: 'HIGH',
  medium: 'MEDIUM',
  low: 'LOW',
  info: 'INFO',
};

const CATEGORY_MAP: Record<string, Category> = {
  'Credential Theft': 'filesystem',
  'Data Exfiltration': 'network',
  'Crypto Theft': 'secrets',
  'Persistence': 'consent_gap',
  'Network Attacks': 'shell',
  'Obfuscation': 'obfuscation',
  'Dangerous Permissions': 'shell',
  'Supply Chain': 'consent_gap',
  'Social Engineering': 'prompt_injection',
  'Privacy Violation': 'secrets',
};

function mapSeverity(s: string): Severity {
  return SEVERITY_MAP[s.toLowerCase()] ?? 'MEDIUM';
}

function mapCategory(c: string): Category {
  return CATEGORY_MAP[c] ?? 'shell';
}

// ── Public API ─────────────────────────────────────────────────────────────

export interface CaterpillarResult {
  findings: Finding[];
  mode: 'alice' | 'offline' | 'skipped';
}

/**
 * Run Caterpillar against a skill directory.
 *
 * Returns findings mapped to the STSS Finding interface, or an empty array
 * if Caterpillar is not installed.
 */
export async function runCaterpillar(skillRoot: string): Promise<CaterpillarResult> {
  const bin = await which('caterpillar');

  if (!bin) {
    return { findings: [], mode: 'skipped' };
  }

  // Detect authentication: try to read the stored config
  const mode = await detectMode(bin);

  try {
    const { stdout } = await execFileAsync(bin, [
      'ask', skillRoot, '--output', 'json',
    ], { timeout: 60_000 });

    const response: CaterpillarResponse = JSON.parse(stdout);

    if (!response.success || !response.data?.findings) {
      return { findings: [], mode };
    }

    const findings: Finding[] = response.data.findings.map((f, i) => ({
      id: `CATERPILLAR-${String(i + 1).padStart(3, '0')}`,
      severity: mapSeverity(f.severity),
      category: mapCategory(f.category),
      location: { file: 'SKILL.md' },
      message: `${f.title}: ${f.description}`,
      remediation: f.recommendation,
      source: 'static' as const,
    }));

    return { findings, mode };
  } catch (err) {
    console.warn('[stss] Caterpillar scan failed:', err instanceof Error ? err.message : err);
    return { findings: [], mode };
  }
}

/** Check whether the user has authenticated with Caterpillar. */
async function detectMode(bin: string): Promise<'alice' | 'offline'> {
  try {
    const { stdout } = await execFileAsync(bin, ['config', 'get', 'api_key'], { timeout: 5_000 });
    return stdout.trim() ? 'alice' : 'offline';
  } catch {
    return 'offline';
  }
}

// ── Terminal output helpers ────────────────────────────────────────────────

export function logCaterpillarStatus(result: CaterpillarResult): void {
  if (result.mode === 'skipped') return; // silent when not installed

  const count = result.findings.length;
  const label = count === 1 ? 'finding' : 'findings';

  if (result.mode === 'alice') {
    console.log(`\u2713 Caterpillar: ${count} ${label} (full behavioral analysis)`);
  } else {
    console.log(`\u2713 Caterpillar: ${count} ${label} (offline mode)`);
    console.log('');
    console.log('\u250c\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2510');
    console.log('\u2502  Unlock full behavioral analysis (free):           \u2502');
    console.log('\u2502                                                    \u2502');
    console.log('\u2502    pnpm exec caterpillar login                     \u2502');
    console.log('\u2502                                                    \u2502');
    console.log('\u2502  Adds LLM-powered semantic analysis,               \u2502');
    console.log('\u2502  credential flow tracing, and prompt               \u2502');
    console.log('\u2502  injection detection beyond pattern matching.      \u2502');
    console.log('\u2514\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2518');
  }
}

export function logCaterpillarNotInstalled(): void {
  console.log('');
  console.log('\u250c\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2510');
  console.log('\u2502  Additional scanner available (free):               \u2502');
  console.log('\u2502                                                    \u2502');
  console.log('\u2502    npm install -g @alice-io/caterpillar            \u2502');
  console.log('\u2502                                                    \u2502');
  console.log('\u2502  Caterpillar adds credential theft detection,      \u2502');
  console.log('\u2502  data exfiltration patterns, and supply chain      \u2502');
  console.log('\u2502  analysis to your STSS scan pipeline.              \u2502');
  console.log('\u2514\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2518');
}
