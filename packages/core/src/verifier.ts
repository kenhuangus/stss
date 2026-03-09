import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512';
import { ingestSkillDirectory } from './ingestion.js';
import { buildMerkleTree } from './merkle.js';
import { evaluatePolicy } from './policy.js';
import { canonicalJson } from './utils.js';
import type { SignedAttestation, AttestationPayload } from './signer.js';
import type { Policy } from './policy.js';

// noble/ed25519 v2 requires a SHA-512 implementation
ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

export type VerificationStatus =
  | 'OK'
  | 'SIGNATURE_INVALID'
  | 'INTEGRITY_MISMATCH'
  | 'POLICY_FAILED';

export interface VerificationResult {
  status: VerificationStatus;
  reason: string;
  attestation: AttestationPayload;
}

export interface VerifyOptions {
  publicKey?: string; // base64 or falls back to env://STSS_PUBLIC_KEY
  localPolicy?: Policy;
  requireLlmAudit?: boolean;
}

async function resolvePublicKey(options: VerifyOptions, signingKeyId: string): Promise<Uint8Array> {
  // Use explicit public key if provided
  if (options.publicKey) {
    if (options.publicKey.startsWith('file://')) {
      const { readFile } = await import('node:fs/promises');
      const content = await readFile(options.publicKey.slice(7), 'utf-8');
      return new Uint8Array(Buffer.from(content.trim(), 'base64'));
    }
    return new Uint8Array(Buffer.from(options.publicKey, 'base64'));
  }

  // Fall back to env var
  const envVal = process.env['STSS_PUBLIC_KEY'];
  if (envVal) {
    return new Uint8Array(Buffer.from(envVal, 'base64'));
  }

  // Fall back to signingKeyId (which is the base64-encoded public key)
  return new Uint8Array(Buffer.from(signingKeyId, 'base64'));
}

export async function verify(
  skillRoot: string,
  signedAttestation: SignedAttestation,
  options: VerifyOptions = {}
): Promise<VerificationResult> {
  const { attestation, signature, signingKeyId } = signedAttestation;

  // ── Step 1: Signature verification ──────────────────────────────────────────
  let publicKey: Uint8Array;
  try {
    publicKey = await resolvePublicKey(options, signingKeyId);
  } catch (err) {
    return {
      status: 'SIGNATURE_INVALID',
      reason: `Failed to resolve public key: ${String(err)}`,
      attestation,
    };
  }

  const canonical = canonicalJson(attestation);
  const messageBytes = new Uint8Array(Buffer.from(canonical, 'utf-8'));
  const sigBytes = new Uint8Array(Buffer.from(signature, 'base64'));

  let sigValid: boolean;
  try {
    sigValid = await ed.verifyAsync(sigBytes, messageBytes, publicKey);
  } catch {
    sigValid = false;
  }

  if (!sigValid) {
    return { status: 'SIGNATURE_INVALID', reason: 'Ed25519 signature verification failed', attestation };
  }

  // ── Step 2: Merkle recompute ─────────────────────────────────────────────────
  const files = await ingestSkillDirectory(skillRoot);
  const merkle = await buildMerkleTree(files);

  if (merkle.root !== attestation.merkle.root) {
    return {
      status: 'INTEGRITY_MISMATCH',
      reason: `Merkle root mismatch: expected ${attestation.merkle.root}, got ${merkle.root}`,
      attestation,
    };
  }

  // ── Step 3: Policy check (optional) ─────────────────────────────────────────
  if (options.requireLlmAudit && !attestation.scan.llmAuditPerformed) {
    return {
      status: 'POLICY_FAILED',
      reason: 'LLM audit was required but not performed during signing',
      attestation,
    };
  }

  if (options.localPolicy) {
    // Reconstruct synthetic findings from summary for policy re-evaluation
    const syntheticFindings = [];
    const s = attestation.scan.summary;
    for (let i = 0; i < s.critical; i++) syntheticFindings.push({ severity: 'CRITICAL' as const, category: 'shell' as const, id: `SYN-C-${i}`, location: { file: 'summary' }, message: 'Synthetic critical', source: 'static' as const });
    for (let i = 0; i < s.high; i++) syntheticFindings.push({ severity: 'HIGH' as const, category: 'shell' as const, id: `SYN-H-${i}`, location: { file: 'summary' }, message: 'Synthetic high', source: 'static' as const });
    for (let i = 0; i < s.medium; i++) syntheticFindings.push({ severity: 'MEDIUM' as const, category: 'shell' as const, id: `SYN-M-${i}`, location: { file: 'summary' }, message: 'Synthetic medium', source: 'static' as const });
    for (let i = 0; i < s.low; i++) syntheticFindings.push({ severity: 'LOW' as const, category: 'shell' as const, id: `SYN-L-${i}`, location: { file: 'summary' }, message: 'Synthetic low', source: 'static' as const });

    const policyResult = evaluatePolicy(syntheticFindings, options.localPolicy);
    if (policyResult.decision === 'FAIL') {
      return {
        status: 'POLICY_FAILED',
        reason: `Local policy evaluation failed: ${policyResult.reason}`,
        attestation,
      };
    }
  }

  return { status: 'OK', reason: 'All checks passed', attestation };
}
