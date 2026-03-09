import { z } from 'zod';
import type { Finding, Severity, Category } from './scanner/types.js';
import type { LLMAuditConfig } from './policy.js';
import { resolveKeyRef } from './utils.js';

export type { LLMAuditConfig };

export interface LLMAuditContext {
  skillName: string;
  skillDescription: string;
  skillMdContent: string;
  flaggedFiles: Array<{ path: string; content: string }>;
  staticFindings: Finding[];
}

export interface LLMAuditResult {
  llmFindings: Finding[];
  overallRisk: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  rationale: string;
}

export interface LLMAdapter {
  analyze(context: LLMAuditContext): Promise<LLMAuditResult>;
}

// ── Zod schema for LLM response ───────────────────────────────────────────────

const LLMFindingSchema = z.object({
  id: z.string(),
  type: z.string(),
  severity: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']),
  description: z.string(),
  evidence: z.string().optional(),
  files_involved: z.array(z.string()).optional(),
});

const LLMResponseSchema = z.object({
  llm_findings: z.array(LLMFindingSchema),
  overall_risk: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']),
  rationale: z.string(),
});

function typeToCategory(t: string): Category {
  if (t.includes('context_poisoning')) return 'context_poisoning';
  if (t.includes('consent_gap')) return 'consent_gap';
  if (t.includes('cross_file_chain')) return 'cross_file_chain';
  return 'prompt_injection'; // behavioral_mismatch → prompt_injection
}

// ── Claude adapter ────────────────────────────────────────────────────────────

export class ClaudeLLMAdapter implements LLMAdapter {
  constructor(private readonly config: LLMAuditConfig) {}

  async analyze(context: LLMAuditContext): Promise<LLMAuditResult> {
    const apiKeyBuf = await resolveKeyRef(this.config.apiKeyRef);
    const apiKey = apiKeyBuf.toString('utf-8').trim();

    const systemPrompt =
      'You are a security auditor for AI agent skills. Respond only in valid JSON.';

    const userPrompt = JSON.stringify({
      task: 'Audit the following AI agent skill for security issues',
      evaluate: [
        'behavioral_coherence: Does actual file behavior match declared skill purpose?',
        'context_poisoning: Does SKILL.md attempt to reframe agent operating context?',
        'consent_gap: Are there scripts that execute without user approval in normal flows?',
        'cross_file_attack_chains: Do import chains lead from an innocent entry to malicious code?',
      ],
      context,
      response_format: {
        llm_findings: [{
          id: 'string',
          type: 'behavioral_mismatch|context_poisoning|consent_gap|cross_file_chain',
          severity: 'CRITICAL|HIGH|MEDIUM|LOW|INFO',
          description: 'string',
          evidence: 'quoted excerpt or file path',
          files_involved: ['path1'],
        }],
        overall_risk: 'LOW|MEDIUM|HIGH|CRITICAL',
        rationale: 'string',
      },
    });

    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: this.config.model,
        max_tokens: 2048,
        system: systemPrompt,
        messages: [{ role: 'user', content: userPrompt }],
      }),
    });

    if (!response.ok) {
      throw new Error(`Anthropic API error: ${response.status} ${await response.text()}`);
    }

    const data = await response.json() as { content: Array<{ type: string; text: string }> };
    const text = data.content.find((c) => c.type === 'text')?.text ?? '{}';

    const parsed = LLMResponseSchema.parse(JSON.parse(text));

    const llmFindings: Finding[] = parsed.llm_findings.map((f, i) => {
      let severity = f.severity as Severity;

      // Apply escalation rules
      if (this.config.escalateOnContextPoisoning && f.type.includes('context_poisoning')) {
        if (['LOW', 'INFO', 'MEDIUM'].includes(severity)) severity = 'HIGH';
      }
      if (this.config.escalateOnConsentGap && f.type.includes('consent_gap')) {
        if (['LOW', 'INFO', 'MEDIUM'].includes(severity)) severity = 'HIGH';
      }
      if (this.config.escalateOnBehavioralMismatch && f.type.includes('behavioral_mismatch')) {
        if (['LOW', 'INFO'].includes(severity)) severity = 'MEDIUM';
      }

      return {
        id: f.id || `LLM-${String(i + 1).padStart(3, '0')}`,
        severity,
        category: typeToCategory(f.type),
        location: { file: f.files_involved?.[0] ?? 'unknown' },
        message: f.description,
        source: 'llm' as const,
      };
    });

    return {
      llmFindings,
      overallRisk: parsed.overall_risk,
      rationale: parsed.rationale,
    };
  }
}

// ── LLM Auditor orchestrator ──────────────────────────────────────────────────

export async function runLLMAudit(
  context: LLMAuditContext,
  config: LLMAuditConfig,
  adapterOverride?: LLMAdapter
): Promise<LLMAuditResult> {
  if (!config.enabled) {
    return { llmFindings: [], overallRisk: 'LOW', rationale: 'LLM audit disabled' };
  }

  const adapter = adapterOverride ?? new ClaudeLLMAdapter(config);

  try {
    return await adapter.analyze(context);
  } catch (err) {
    console.warn('[stss] LLM audit failed, continuing without LLM findings:', err);
    return { llmFindings: [], overallRisk: 'LOW', rationale: 'LLM audit failed' };
  }
}
