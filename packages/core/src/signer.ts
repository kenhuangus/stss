import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512';
import { resolveKeyRef, canonicalJson } from './utils.js';
import type { Decision } from './policy.js';

// noble/ed25519 v2 requires a SHA-512 implementation
ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

export interface AttestationPayload {
  schemaVersion: 'stss/1.0';
  skill: { namespace: string; name: string; version: string };
  scan: {
    timestamp: string; // RFC3339
    toolVersion: string;
    rulesetVersion: string;
    summary: { critical: number; high: number; medium: number; low: number; info: number };
    llmAuditPerformed: boolean;
    registryAuditPerformed: boolean;
    registrySources: string[];
    consentGapAnalysis: boolean;
    crossFileChainAnalysis: boolean;
  };
  policy: {
    name: string;
    decision: Decision;
    maxAllowedSeverity: string;
    policyRootHash: string;
  };
  merkle: { root: string; hashAlgorithm: 'SHA-256' };
  fileHashes: Array<{ path: string; hash: string }>;
}

export interface SignedAttestation {
  attestation: AttestationPayload;
  signature: string; // base64
  signingKeyId: string;
  algorithm: 'ed25519';
}

export async function signAttestation(
  payload: AttestationPayload,
  keyRef: string
): Promise<SignedAttestation> {
  // Resolve private key — keep reference only for the duration of signing
  const privateKeyBytes = await resolveKeyRef(keyRef);

  // Canonical JSON → bytes
  const canonical = canonicalJson(payload);
  const messageBytes = Buffer.from(canonical, 'utf-8');

  // Sign with Ed25519
  const privateKey = new Uint8Array(privateKeyBytes);
  const sig = await ed.signAsync(messageBytes, privateKey.slice(0, 32));

  // Derive public key for key ID
  const pubKey = await ed.getPublicKeyAsync(privateKey.slice(0, 32));
  const signingKeyId = Buffer.from(pubKey).toString('base64');

  return {
    attestation: payload,
    signature: Buffer.from(sig).toString('base64'),
    signingKeyId,
    algorithm: 'ed25519',
  };
}

export async function generateKeypair(): Promise<{ privateKey: string; publicKey: string }> {
  const privateKey = ed.utils.randomPrivateKey();
  const publicKey = await ed.getPublicKeyAsync(privateKey);
  return {
    privateKey: Buffer.from(privateKey).toString('base64'),
    publicKey: Buffer.from(publicKey).toString('base64'),
  };
}
