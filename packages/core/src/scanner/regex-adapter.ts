import fs from 'node:fs/promises';
import path from 'node:path';
import type { FileEntry } from '../ingestion.js';
import type { Finding, Severity, Category, ScannerAdapter } from './types.js';

let _findingCounter = 0;
function nextId(prefix: string): string {
  return `${prefix}-${String(++_findingCounter).padStart(3, '0')}`;
}

interface Rule {
  id: string;
  category: Category;
  severity: Severity;
  pattern: RegExp;
  message: string;
  remediation?: string;
  /** Only apply to these file extensions (undefined = all files) */
  extensions?: string[];
  /** Only apply to markdown files */
  mdOnly?: boolean;
  /** Post-match escalation logic */
  escalate?: (line: string, allLines: string[], lineIdx: number) => Severity | null;
}

// Hardcoded IP / non-localhost URL pattern for network escalation
const HARDCODED_IP_OR_URL = /(\b(?:\d{1,3}\.){3}\d{1,3}\b|https?:\/\/(?!localhost|127\.0\.0\.1)[^\s'"]+)/i;

const RULES: Rule[] = [
  // ── 1. filesystem ──────────────────────────────────────────────────────────
  {
    id: 'FS-001', category: 'filesystem', severity: 'HIGH',
    pattern: /\.ssh|\.env\b|\/etc\/passwd|\/etc\/shadow|~\/\.aws|credentials|id_rsa|\.npmrc|\.netrc/i,
    message: 'Sensitive filesystem path reference detected',
    remediation: 'Remove references to sensitive filesystem paths',
  },

  // ── 2. shell ───────────────────────────────────────────────────────────────
  {
    id: 'SH-001', category: 'shell', severity: 'HIGH',
    pattern: /subprocess|child_process|exec\(|eval\(|os\.system\(|shell\s*=\s*True|spawn\(|execSync\b|execFile\b|shelljs/,
    message: 'Shell execution pattern detected',
    remediation: 'Avoid subprocess or shell execution; use safe APIs instead',
  },

  // ── 3. network ─────────────────────────────────────────────────────────────
  {
    id: 'NET-001', category: 'network', severity: 'HIGH',
    pattern: /fetch\(|axios\b|http\.get\(|https\.get\(|XMLHttpRequest|socket\(|urllib\b|requests\.get\(|requests\.post\(/,
    message: 'Outbound network call detected',
    remediation: 'Ensure network calls are intentional and documented',
    escalate: (line, _allLines, _idx) => {
      if (HARDCODED_IP_OR_URL.test(line)) return 'CRITICAL';
      return null;
    },
  },

  // ── 4. secrets ─────────────────────────────────────────────────────────────
  {
    id: 'SEC-001', category: 'secrets', severity: 'HIGH',
    pattern: /process\.env|os\.environ/,
    message: 'Environment variable access detected (potential secret read)',
    remediation: 'Document why env vars are read; avoid logging their values',
  },
  {
    id: 'SEC-002', category: 'secrets', severity: 'HIGH',
    // Hex strings ≥32 chars or base64 ≥40 chars near key/secret/token/password/apikey/api_key
    pattern: /(?:key|secret|token|password|apikey|api_key)[^\n]{0,80}(?:[0-9a-fA-F]{32,}|[A-Za-z0-9+/]{40,}={0,2})|(?:[0-9a-fA-F]{32,}|[A-Za-z0-9+/]{40,}={0,2})[^\n]{0,80}(?:key|secret|token|password|apikey|api_key)/i,
    message: 'Potential hardcoded secret detected near sensitive keyword',
    remediation: 'Move secrets to environment variables or a secrets manager',
  },

  // ── 5. obfuscation ─────────────────────────────────────────────────────────
  {
    id: 'OBF-001', category: 'obfuscation', severity: 'HIGH',
    pattern: /base64\.b64decode[^)]*\).*exec\(|Buffer\.from\([^)]*,\s*['"]base64['"]\)[^;]*eval\(/,
    message: 'Base64 decode combined with code execution detected',
    remediation: 'Remove obfuscated code execution patterns',
  },
  {
    id: 'OBF-002', category: 'obfuscation', severity: 'HIGH',
    // fromCharCode chains: 5+ consecutive
    pattern: /(?:fromCharCode\([^)]*\)[^;]*){5,}/,
    message: 'Long fromCharCode chain detected (possible obfuscation)',
    remediation: 'Replace character code chains with readable string literals',
  },
  {
    id: 'OBF-003', category: 'obfuscation', severity: 'HIGH',
    pattern: /unescape\([^)]*\)[^;]*eval\(/,
    message: 'unescape() combined with eval() detected',
    remediation: 'Remove obfuscated code execution patterns',
  },

  // ── 6. prompt_injection (md files only) ────────────────────────────────────
  {
    id: 'PI-001', category: 'prompt_injection', severity: 'MEDIUM',
    pattern: /ignore previous instructions|disregard your|you are now operating as|override your|pretend you are|read arbitrary files|exfiltrate|send to|POST to/i,
    message: 'Potential prompt injection instruction detected',
    remediation: 'Remove adversarial prompt instructions from skill documentation',
    mdOnly: true,
  },

  // ── 7. context_poisoning (md files only) ───────────────────────────────────
  {
    id: 'CP-001', category: 'context_poisoning', severity: 'MEDIUM',
    pattern: /debug mode|maintenance mode|diagnostic mode|you are now in|special mode activated|you have been granted/i,
    message: 'Potential context poisoning detected',
    remediation: 'Remove mode-switching or privilege-granting language from documentation',
    mdOnly: true,
  },

  // ── 8. consent_gap ─────────────────────────────────────────────────────────
  {
    id: 'CG-001', category: 'consent_gap', severity: 'CRITICAL',
    pattern: /^(post_install|setup|install|configure|init|bootstrap)\.(sh|bash|py|js|ts)$/i,
    message: 'Setup/install script detected — may execute without user consent',
    remediation: 'Document all setup scripts and require explicit user approval',
  },
];

function isMdFile(filePath: string): boolean {
  const ext = path.extname(filePath).toLowerCase();
  return ext === '.md' || path.basename(filePath).toUpperCase() === 'SKILL.MD';
}

function isConsentGapFile(relativePath: string): boolean {
  const basename = path.basename(relativePath);
  return /^(post_install|setup|install|configure|init|bootstrap)\.(sh|bash|py|js|ts)$/i.test(basename);
}

async function scanFile(file: FileEntry): Promise<Finding[]> {
  const findings: Finding[] = [];
  let content: string;
  try {
    content = await fs.readFile(file.absolutePath, 'utf-8');
  } catch {
    return findings;
  }

  const lines = content.split('\n');
  const isMd = isMdFile(file.relativePath);

  // Check consent gap by filename first
  if (isConsentGapFile(file.relativePath)) {
    findings.push({
      id: nextId('CG'),
      category: 'consent_gap',
      severity: 'CRITICAL',
      location: { file: file.relativePath },
      message: `Setup/install script detected: ${path.basename(file.relativePath)}`,
      remediation: 'Document all setup scripts and require explicit user approval',
      source: 'static',
    });
  }

  for (const rule of RULES) {
    // Skip consent_gap filename rule (handled above)
    if (rule.id === 'CG-001') continue;
    // Skip md-only rules for non-md files
    if (rule.mdOnly && !isMd) continue;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i]!;
      if (rule.pattern.test(line)) {
        let severity = rule.severity;
        if (rule.escalate) {
          const escalated = rule.escalate(line, lines, i);
          if (escalated) severity = escalated;
        }

        findings.push({
          id: nextId(rule.category.toUpperCase().slice(0, 3)),
          category: rule.category,
          severity,
          location: { file: file.relativePath, line: i + 1 },
          message: rule.message,
          remediation: rule.remediation,
          source: 'static',
        });
        // One finding per rule per file (avoid duplicate flooding)
        break;
      }
    }
  }

  // context_poisoning: heading followed within 3 lines by shell commands or file access patterns
  if (isMd) {
    const shellOrFilePattern = /subprocess|exec\(|os\.system|curl|wget|\/etc\/|\.ssh/;
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i]!;
      if (/^#{1,6}\s/.test(line)) {
        // Check next 3 lines for shell/file patterns
        for (let j = i + 1; j <= i + 3 && j < lines.length; j++) {
          if (shellOrFilePattern.test(lines[j]!)) {
            findings.push({
              id: nextId('CP'),
              category: 'context_poisoning',
              severity: 'MEDIUM',
              location: { file: file.relativePath, line: j + 1 },
              message: 'Heading followed by shell/file access pattern (possible context poisoning)',
              remediation: 'Review headings that introduce shell or filesystem commands',
              source: 'static',
            });
            break;
          }
        }
      }
    }
  }

  return findings;
}

export class RegexAdapter implements ScannerAdapter {
  name = 'regex';

  async scan(files: FileEntry[], _skillRoot: string): Promise<Finding[]> {
    const allFindings: Finding[] = [];
    for (const file of files) {
      const findings = await scanFile(file);
      allFindings.push(...findings);
    }
    return allFindings;
  }
}
