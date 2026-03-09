export { ingestSkillDirectory } from './ingestion.js';
export type { FileEntry } from './ingestion.js';

export { buildMerkleTree } from './merkle.js';
export type { MerkleEntry, MerkleResult } from './merkle.js';

export type { Finding, Severity, Category, ScannerAdapter } from './scanner/types.js';
export { RegexAdapter } from './scanner/regex-adapter.js';
export { SemgrepAdapter } from './scanner/semgrep-adapter.js';
export { createAdapter } from './scanner/index.js';

export { detectConsentGaps } from './hook-detector.js';

export { traceImportChains } from './chain-tracer.js';
export type { ChainFinding } from './chain-tracer.js';

export {
  loadPolicy,
  loadPolicyAsync,
  loadPolicyFromString,
  evaluatePolicy,
  DEFAULT_POLICY,
} from './policy.js';
export type { Policy, PolicyResult, Decision, LLMAuditConfig, RegistryAuditConfig } from './policy.js';

export { runLLMAudit, ClaudeLLMAdapter } from './llm-auditor.js';
export type { LLMAuditContext, LLMAuditResult, LLMAdapter } from './llm-auditor.js';

export { SkillsShAdapter } from './registry-adapters/skillssh.js';
export type { RegistryAdapter, SkillId } from './registry-adapters/skillssh.js';

export { signAttestation, generateKeypair } from './signer.js';
export type { AttestationPayload, SignedAttestation } from './signer.js';

export { verify } from './verifier.js';
export type { VerificationResult, VerificationStatus, VerifyOptions } from './verifier.js';

export { scan, scanAndSign, TOOL_VERSION, RULESET_VERSION } from './pipeline.js';
export type { ScanOptions, ScanResult, ScanAndSignResult } from './pipeline.js';
