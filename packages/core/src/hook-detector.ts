import fs from 'node:fs/promises';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import type { FileEntry } from './ingestion.js';
import type { Finding } from './scanner/types.js';
import { which } from './utils.js';

const execFileAsync = promisify(execFile);

let _counter = 0;
function nextId(): string {
  return `CG-HD-${String(++_counter).padStart(3, '0')}`;
}

const OUTBOUND_NETWORK_PATTERN = /\bcurl\b|\bwget\b|\bnc\b|\bnetcat\b|https?:\/\//;
const SHELL_EXEC_PATTERN = /bash\s+-c|eval\s+["`']|exec\s+["`']/;
const CREDENTIAL_PATH_PATTERN = /\.ssh\/|\.aws\/|\/etc\/passwd|\.env\b/;

async function analyzeScript(
  scriptPath: string,
  relativePath: string,
  skillRoot: string
): Promise<Finding[]> {
  const findings: Finding[] = [];
  let content: string;
  try {
    content = await fs.readFile(scriptPath, 'utf-8');
  } catch {
    return findings;
  }

  const shellcheckBin = await which('shellcheck');
  if (shellcheckBin) {
    try {
      const { stdout } = await execFileAsync(shellcheckBin, ['--format=json', scriptPath]);
      const issues: Array<{ line: number; message: string; level: string }> = JSON.parse(stdout);
      for (const issue of issues) {
        if (issue.level === 'error' || issue.level === 'warning') {
          findings.push({
            id: nextId(),
            category: 'consent_gap',
            severity: 'HIGH',
            location: { file: relativePath, line: issue.line },
            message: `shellcheck: ${issue.message}`,
            source: 'static',
          });
        }
      }
    } catch {
      // shellcheck returned non-zero (findings) — output is still valid JSON
      try {
        // Re-run to capture output regardless of exit code
        const proc = execFile(shellcheckBin, ['--format=json', scriptPath], {}, () => {});
        let out = '';
        proc.stdout?.on('data', (d: Buffer) => { out += d.toString(); });
        await new Promise<void>((resolve) => proc.on('close', () => resolve()));
        if (out) {
          const issues2: Array<{ line: number; message: string; level: string }> = JSON.parse(out);
          for (const issue of issues2) {
            if (issue.level === 'error' || issue.level === 'warning') {
              findings.push({
                id: nextId(),
                category: 'consent_gap',
                severity: 'HIGH',
                location: { file: relativePath, line: issue.line },
                message: `shellcheck: ${issue.message}`,
                source: 'static',
              });
            }
          }
        }
      } catch {
        // fallthrough to regex
      }
    }
  }

  // Regex fallback analysis
  const lines = content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;

    if (OUTBOUND_NETWORK_PATTERN.test(line)) {
      findings.push({
        id: nextId(),
        category: 'consent_gap',
        severity: 'CRITICAL',
        location: { file: relativePath, line: i + 1 },
        message: 'Outbound network call detected in setup/install script',
        remediation: 'Remove network calls from install scripts or require explicit user consent',
        source: 'static',
      });
    }

    if (SHELL_EXEC_PATTERN.test(line)) {
      findings.push({
        id: nextId(),
        category: 'consent_gap',
        severity: 'HIGH',
        location: { file: relativePath, line: i + 1 },
        message: 'Dynamic shell execution in setup/install script',
        source: 'static',
      });
    }

    if (CREDENTIAL_PATH_PATTERN.test(line)) {
      findings.push({
        id: nextId(),
        category: 'consent_gap',
        severity: 'CRITICAL',
        location: { file: relativePath, line: i + 1 },
        message: 'Setup script accesses credential/sensitive paths outside skill root',
        source: 'static',
      });
    }
  }

  return findings;
}

async function extractScriptRefs(filePath: string): Promise<string[]> {
  let content: string;
  try {
    content = await fs.readFile(filePath, 'utf-8');
  } catch {
    return [];
  }

  const refs: string[] = [];

  // Match common install/post_install hook patterns in JSON/YAML
  const patterns = [
    /["']?post_install["']?\s*[:=]\s*["']([^"'\n]+)["']/gi,
    /["']?install["']?\s*[:=]\s*["']([^"'\n]+)["']/gi,
    /["']?setup["']?\s*[:=]\s*["']([^"'\n]+)["']/gi,
    /["']?scripts["']?\s*[:=]\s*\{[^}]*["']?install["']?\s*:\s*["']([^"'\n]+)["']/gi,
  ];

  for (const pat of patterns) {
    let m: RegExpExecArray | null;
    while ((m = pat.exec(content)) !== null) {
      if (m[1]) refs.push(m[1]);
    }
  }

  return refs;
}

const INSTALL_SCRIPT_PATTERN = /^(post_install|setup|install|configure|init|bootstrap)\.(sh|bash|py|js|ts)$/i;
const MANIFEST_EXTENSIONS = new Set(['.json', '.yaml', '.yml', '.toml']);

export async function detectConsentGaps(
  files: FileEntry[],
  skillRoot: string
): Promise<Finding[]> {
  const findings: Finding[] = [];

  for (const file of files) {
    const basename = path.basename(file.relativePath);

    // Flag setup scripts by name
    if (INSTALL_SCRIPT_PATTERN.test(basename)) {
      findings.push({
        id: nextId(),
        category: 'consent_gap',
        severity: 'CRITICAL',
        location: { file: file.relativePath },
        message: `Setup/install script detected: ${basename} — may execute without user consent`,
        remediation: 'Require explicit user approval for all install scripts',
        source: 'static',
      });

      // Analyze script content
      const scriptFindings = await analyzeScript(file.absolutePath, file.relativePath, skillRoot);
      findings.push(...scriptFindings);
    }

    // Parse manifests for install hook references
    const ext = path.extname(file.relativePath);
    if (MANIFEST_EXTENSIONS.has(ext)) {
      const refs = await extractScriptRefs(file.absolutePath);
      for (const ref of refs) {
        const scriptPath = path.join(skillRoot, ref);
        const relRef = ref.startsWith('/') ? ref : ref;
        try {
          await fs.access(scriptPath);
          const scriptFindings = await analyzeScript(scriptPath, relRef, skillRoot);
          findings.push(...scriptFindings);
        } catch {
          // Script referenced but not found — still flag the reference
          findings.push({
            id: nextId(),
            category: 'consent_gap',
            severity: 'HIGH',
            location: { file: file.relativePath },
            message: `Manifest references install script "${ref}" which may execute without consent`,
            source: 'static',
          });
        }
      }
    }
  }

  return findings;
}
