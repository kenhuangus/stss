import fs from 'node:fs/promises';
import crypto from 'node:crypto';
import yaml from 'js-yaml';
import { z } from 'zod';
import type { Finding, Severity } from './scanner/types.js';
import { canonicalJson } from './utils.js';

// ── Zod schemas ──────────────────────────────────────────────────────────────

const SeveritySchema = z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']);

const LLMAuditConfigSchema = z.object({
  enabled: z.boolean().default(false),
  adapter: z.string().default('claude'),
  model: z.string().default('claude-sonnet-4-20250514'),
  apiKeyRef: z.string().optional(),
  api_key_ref: z.string().optional(),
  escalateOnBehavioralMismatch: z.boolean().optional(),
  escalate_on_behavioral_mismatch: z.boolean().optional(),
  escalateOnContextPoisoning: z.boolean().optional(),
  escalate_on_context_poisoning: z.boolean().optional(),
  escalateOnConsentGap: z.boolean().optional(),
  escalate_on_consent_gap: z.boolean().optional(),
}).transform((v) => ({
  enabled: v.enabled,
  adapter: v.adapter,
  model: v.model,
  apiKeyRef: v.apiKeyRef ?? v.api_key_ref ?? 'env://ANTHROPIC_API_KEY',
  escalateOnBehavioralMismatch: v.escalateOnBehavioralMismatch ?? v.escalate_on_behavioral_mismatch ?? false,
  escalateOnContextPoisoning: v.escalateOnContextPoisoning ?? v.escalate_on_context_poisoning ?? false,
  escalateOnConsentGap: v.escalateOnConsentGap ?? v.escalate_on_consent_gap ?? false,
}));

const RegistryAuditConfigSchema = z.object({
  enabled: z.boolean().default(false),
  adapters: z.array(z.string()).default([]),
  failOnRegistryMalicious: z.boolean().optional(),
  fail_on_registry_malicious: z.boolean().optional(),
}).transform((v) => ({
  enabled: v.enabled,
  adapters: v.adapters,
  failOnRegistryMalicious: v.failOnRegistryMalicious ?? v.fail_on_registry_malicious ?? true,
}));

const NeverSignRuleSchema = z.object({
  severity: z.array(SeveritySchema).optional(),
  pattern: z.string().optional(),
  action: z.literal('BLOCK'),
});

const RequireApprovalRuleSchema = z.object({
  severity: z.array(SeveritySchema).optional(),
  action: z.literal('HUMAN_REVIEW'),
});

const AutoApproveRuleSchema = z.object({
  severity: z.array(SeveritySchema).optional(),
  action: z.literal('SIGN'),
});

const PolicyBodySchema = z.object({
  version: z.string(),
  never_sign: z.array(NeverSignRuleSchema).optional().default([]),
  neverSign: z.array(NeverSignRuleSchema).optional(),
  require_approval: z.array(RequireApprovalRuleSchema).optional().default([]),
  requireApproval: z.array(RequireApprovalRuleSchema).optional(),
  auto_approve: z.array(AutoApproveRuleSchema).optional().default([]),
  autoApprove: z.array(AutoApproveRuleSchema).optional(),
  scanner_adapter: z.string().optional(),
  scannerAdapter: z.string().optional(),
  signing_key_ref: z.string().optional(),
  signingKeyRef: z.string().optional(),
  policy_root_hash: z.string().optional(),
  policyRootHash: z.string().optional(),
  llm_audit: LLMAuditConfigSchema.optional(),
  llmAudit: LLMAuditConfigSchema.optional(),
  registry_audit: RegistryAuditConfigSchema.optional(),
  registryAudit: RegistryAuditConfigSchema.optional(),
}).transform((v) => ({
  version: v.version,
  neverSign: v.neverSign ?? v.never_sign ?? [],
  requireApproval: v.requireApproval ?? v.require_approval ?? [],
  autoApprove: v.autoApprove ?? v.auto_approve ?? [],
  scannerAdapter: v.scannerAdapter ?? v.scanner_adapter ?? 'regex',
  signingKeyRef: v.signingKeyRef ?? v.signing_key_ref ?? 'env://STSS_SIGNING_KEY',
  policyRootHash: v.policyRootHash ?? v.policy_root_hash,
  llmAudit: v.llmAudit ?? v.llm_audit,
  registryAudit: v.registryAudit ?? v.registry_audit,
}));

const PolicyYamlSchema = z.object({
  stss_policy: PolicyBodySchema.optional(),
}).transform((v) => v.stss_policy);

// ── Types ─────────────────────────────────────────────────────────────────────

export interface LLMAuditConfig {
  enabled: boolean;
  adapter: string;
  model: string;
  apiKeyRef: string;
  escalateOnBehavioralMismatch: boolean;
  escalateOnContextPoisoning: boolean;
  escalateOnConsentGap: boolean;
}

export interface RegistryAuditConfig {
  enabled: boolean;
  adapters: string[];
  failOnRegistryMalicious: boolean;
}

export interface Policy {
  version: string;
  neverSign: Array<{ severity?: Severity[]; pattern?: string; action: 'BLOCK' }>;
  requireApproval: Array<{ severity?: Severity[]; action: 'HUMAN_REVIEW' }>;
  autoApprove: Array<{ severity?: Severity[]; action: 'SIGN' }>;
  scannerAdapter: string;
  signingKeyRef: string;
  policyRootHash?: string;
  llmAudit?: LLMAuditConfig;
  registryAudit?: RegistryAuditConfig;
}

export type Decision = 'PASS' | 'PASS_WITH_WARNINGS' | 'FAIL';

export interface PolicyResult {
  decision: Decision;
  reason: string;
  summary: { critical: number; high: number; medium: number; low: number; info: number };
}

// ── Default policy ────────────────────────────────────────────────────────────

export const DEFAULT_POLICY: Policy = {
  version: '2.1.0',
  neverSign: [
    { severity: ['CRITICAL', 'HIGH'], action: 'BLOCK' },
  ],
  requireApproval: [
    { severity: ['MEDIUM'], action: 'HUMAN_REVIEW' },
  ],
  autoApprove: [
    { severity: ['LOW', 'INFO'], action: 'SIGN' },
  ],
  scannerAdapter: 'regex',
  signingKeyRef: 'env://STSS_SIGNING_KEY',
};

// ── Policy loading ────────────────────────────────────────────────────────────

function computePolicyHash(policy: Policy): string {
  const canonical = canonicalJson({
    version: policy.version,
    neverSign: policy.neverSign,
    requireApproval: policy.requireApproval,
    autoApprove: policy.autoApprove,
    scannerAdapter: policy.scannerAdapter,
    signingKeyRef: policy.signingKeyRef,
  });
  return crypto.createHash('sha256').update(canonical).digest('hex');
}

export function loadPolicyFromString(content: string): Policy {
  const raw = yaml.load(content);
  const result = PolicyYamlSchema.safeParse(raw);
  if (!result.success) {
    throw new Error(`Invalid policy YAML: ${result.error.message}`);
  }

  const parsed = result.data;
  if (!parsed) throw new Error('Policy YAML missing stss_policy root key');

  const policy: Policy = parsed as Policy;

  // Validate policyRootHash if present
  if (policy.policyRootHash) {
    const computed = computePolicyHash(policy);
    if (computed !== policy.policyRootHash) {
      throw new Error(
        `Policy integrity check failed: stored hash ${policy.policyRootHash} does not match computed ${computed}`
      );
    }
  }

  return policy;
}

export function loadPolicy(yamlPath: string): Policy {
  // Synchronous version for CLI convenience — but we expose async too
  const { readFileSync } = require('node:fs');
  const content: string = readFileSync(yamlPath, 'utf-8');
  return loadPolicyFromString(content);
}

export async function loadPolicyAsync(yamlPath: string): Promise<Policy> {
  const content = await fs.readFile(yamlPath, 'utf-8');
  return loadPolicyFromString(content);
}

// ── Policy evaluation ─────────────────────────────────────────────────────────

export function evaluatePolicy(findings: Finding[], policy: Policy): PolicyResult {
  const summary = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };

  for (const f of findings) {
    switch (f.severity) {
      case 'CRITICAL': summary.critical++; break;
      case 'HIGH': summary.high++; break;
      case 'MEDIUM': summary.medium++; break;
      case 'LOW': summary.low++; break;
      case 'INFO': summary.info++; break;
    }
  }

  // Check neverSign rules
  for (const rule of policy.neverSign) {
    if (rule.pattern) {
      const pat = new RegExp(rule.pattern);
      for (const f of findings) {
        if (pat.test(f.message) || (f.location.file && pat.test(f.location.file))) {
          return { decision: 'FAIL', reason: `Finding matches neverSign pattern "${rule.pattern}"`, summary };
        }
      }
    }
    if (rule.severity) {
      for (const sev of rule.severity) {
        const count = summary[sev.toLowerCase() as keyof typeof summary];
        if (count > 0) {
          return {
            decision: 'FAIL',
            reason: `${count} ${sev} finding(s) match neverSign rule`,
            summary,
          };
        }
      }
    }
  }

  // Check requireApproval rules — in v1, these also FAIL (approval flow not implemented)
  for (const rule of policy.requireApproval) {
    if (rule.severity) {
      for (const sev of rule.severity) {
        const count = summary[sev.toLowerCase() as keyof typeof summary];
        if (count > 0) {
          return {
            decision: 'FAIL',
            reason: `${count} ${sev} finding(s) require human approval (not yet implemented)`,
            summary,
          };
        }
      }
    }
  }

  // Only autoApprove findings remain
  if (summary.low > 0 || summary.info > 0) {
    return { decision: 'PASS_WITH_WARNINGS', reason: 'Only LOW/INFO findings remain', summary };
  }

  return { decision: 'PASS', reason: 'No findings', summary };
}
