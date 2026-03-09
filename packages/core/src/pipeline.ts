import fs from 'node:fs/promises';
import path from 'node:path';
import { ingestSkillDirectory, type FileEntry } from './ingestion.js';
import { buildMerkleTree } from './merkle.js';
import { createAdapter } from './scanner/index.js';
import { detectConsentGaps } from './hook-detector.js';
import { traceImportChains } from './chain-tracer.js';
import { evaluatePolicy, DEFAULT_POLICY, type Policy, type PolicyResult } from './policy.js';
import { runLLMAudit, type LLMAuditContext, type LLMAdapter } from './llm-auditor.js';
import { SkillsShAdapter, type SkillId } from './registry-adapters/skillssh.js';
import { signAttestation, type SignedAttestation, type AttestationPayload } from './signer.js';
import type { Finding } from './scanner/types.js';
import type { ChainFinding } from './chain-tracer.js';
import type { MerkleResult } from './merkle.js';

export const TOOL_VERSION = '1.0.0';
export const RULESET_VERSION = '1.0.0';

export interface ScanOptions {
  policy?: Policy;
  llmAudit?: boolean;
  registryAudit?: boolean;
  skillId?: SkillId;
  llmAdapterOverride?: LLMAdapter;
}

export interface ScanResult {
  files: FileEntry[];
  findings: Finding[];
  chainFindings: ChainFinding[];
  allFindings: Finding[];
  merkle: MerkleResult;
  policyResult: PolicyResult;
}

export interface ScanAndSignResult extends ScanResult {
  signedAttestation: SignedAttestation;
}

async function extractSkillMeta(skillRoot: string): Promise<{ name: string; description: string; content: string }> {
  const skillMdPath = path.join(skillRoot, 'SKILL.md');
  try {
    const content = await fs.readFile(skillMdPath, 'utf-8');
    // Extract frontmatter description if present
    const fmMatch = content.match(/^---\n([\s\S]*?)\n---/);
    let description = '';
    if (fmMatch) {
      const descMatch = fmMatch[1]!.match(/description:\s*(.+)/);
      if (descMatch) description = descMatch[1]!.trim();
    }
    const name = path.basename(skillRoot);
    return { name, description, content };
  } catch {
    return { name: path.basename(skillRoot), description: '', content: '' };
  }
}

export async function scan(skillRoot: string, options: ScanOptions = {}): Promise<ScanResult> {
  const policy = options.policy ?? DEFAULT_POLICY;

  // 1. Ingest files
  const files = await ingestSkillDirectory(skillRoot);

  // 2. Static scan
  const adapter = createAdapter(policy.scannerAdapter);
  const staticFindings = await adapter.scan(files, skillRoot);

  // 3. Hook detection
  const hookFindings = await detectConsentGaps(files, skillRoot);

  // 4. Chain tracing
  const allStaticFindings = [...staticFindings, ...hookFindings];
  const chainFindings = await traceImportChains(files, allStaticFindings, skillRoot);

  // 5. LLM audit (opt-in)
  let llmFindings: Finding[] = [];
  const skillMeta = await extractSkillMeta(skillRoot);
  const hasSignificantFindings = allStaticFindings.some(
    (f) => f.severity === 'CRITICAL' || f.severity === 'HIGH' || f.severity === 'MEDIUM'
  );

  if (
    options.llmAudit &&
    policy.llmAudit?.enabled &&
    (hasSignificantFindings || skillMeta.content.length > 0)
  ) {
    const flaggedFiles = await buildFlaggedFiles(files, allStaticFindings, skillRoot);
    const ctx: LLMAuditContext = {
      skillName: skillMeta.name,
      skillDescription: skillMeta.description,
      skillMdContent: skillMeta.content,
      flaggedFiles,
      staticFindings: allStaticFindings,
    };
    const result = await runLLMAudit(ctx, policy.llmAudit, options.llmAdapterOverride);
    llmFindings = result.llmFindings;
  }

  // 6. Registry audit (opt-in)
  let registryFindings: Finding[] = [];
  if (options.registryAudit && policy.registryAudit?.enabled && options.skillId) {
    for (const adapterName of policy.registryAudit.adapters) {
      if (adapterName === 'skills.sh') {
        const adapter = new SkillsShAdapter();
        const rf = await adapter.fetch(options.skillId);
        registryFindings.push(...rf);
      }
    }
  }

  // 7. Merge all findings
  const allFindings: Finding[] = [
    ...allStaticFindings,
    ...chainFindings,
    ...llmFindings,
    ...registryFindings,
  ];

  // 8. Build Merkle tree
  const merkle = await buildMerkleTree(files);

  // 9. Evaluate policy
  const policyResult = evaluatePolicy(allFindings, policy);

  return { files, findings: allStaticFindings, chainFindings, allFindings, merkle, policyResult };
}

async function buildFlaggedFiles(
  files: FileEntry[],
  findings: Finding[],
  _skillRoot: string
): Promise<Array<{ path: string; content: string }>> {
  const flaggedPaths = new Set(findings.map((f) => f.location.file));
  const result: Array<{ path: string; content: string }> = [];
  for (const file of files) {
    if (flaggedPaths.has(file.relativePath)) {
      try {
        const content = await fs.readFile(file.absolutePath, 'utf-8');
        result.push({ path: file.relativePath, content: content.slice(0, 4096) });
      } catch {
        // skip
      }
    }
  }
  return result;
}

export async function scanAndSign(
  skillRoot: string,
  skillId: SkillId,
  options: ScanOptions & { keyRef?: string; policyName?: string } = {}
): Promise<ScanAndSignResult> {
  const policy = options.policy ?? DEFAULT_POLICY;
  const scanResult = await scan(skillRoot, { ...options, skillId });

  if (scanResult.policyResult.decision === 'FAIL') {
    throw new Object({ ...scanResult, type: 'POLICY_FAIL' });
  }

  const now = new Date().toISOString();
  const summary = scanResult.policyResult.summary;

  const payload: AttestationPayload = {
    schemaVersion: 'stss/1.0',
    skill: {
      namespace: skillId.namespace,
      name: skillId.name,
      version: skillId.version ?? '0.0.0',
    },
    scan: {
      timestamp: now,
      toolVersion: TOOL_VERSION,
      rulesetVersion: RULESET_VERSION,
      summary,
      llmAuditPerformed: !!(options.llmAudit && policy.llmAudit?.enabled),
      registryAuditPerformed: !!(options.registryAudit && policy.registryAudit?.enabled),
      registrySources: policy.registryAudit?.adapters ?? [],
      consentGapAnalysis: true,
      crossFileChainAnalysis: true,
    },
    policy: {
      name: options.policyName ?? 'default',
      decision: scanResult.policyResult.decision,
      maxAllowedSeverity: 'INFO',
      policyRootHash: policy.policyRootHash ?? '',
    },
    merkle: { root: scanResult.merkle.root, hashAlgorithm: 'SHA-256' },
    fileHashes: scanResult.merkle.entries.map((e) => ({ path: e.path, hash: e.fileHash })),
  };

  const keyRef = options.keyRef ?? policy.signingKeyRef;
  const signedAttestation = await signAttestation(payload, keyRef);

  return { ...scanResult, signedAttestation };
}
