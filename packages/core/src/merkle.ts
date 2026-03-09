import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import type { FileEntry } from './ingestion.js';

export interface MerkleEntry {
  path: string;
  fileHash: string; // SHA-256 of raw file bytes, lowercase hex
  leafHash: string; // SHA-256 of "leaf:" + path + ":" + fileHash
}

export interface MerkleResult {
  root: string; // final Merkle root, lowercase hex
  hashAlgorithm: 'SHA-256';
  entries: MerkleEntry[];
}

function sha256(data: string | Buffer): string {
  return crypto
    .createHash('sha256')
    .update(typeof data === 'string' ? Buffer.from(data, 'utf-8') : data)
    .digest('hex');
}

/**
 * Computes the Merkle root from an array of leaf hashes.
 *
 * Algorithm:
 * - Binary tree: pair adjacent nodes at each level.
 * - Internal node: SHA-256("node:" + leftHash + ":" + rightHash)
 * - Odd-node strategy: PROMOTE — if a level has an odd number of nodes,
 *   the last node is promoted unpaired to the next level.
 * - Empty tree: SHA-256("empty") — fixed constant.
 */
function computeRoot(hashes: string[]): string {
  if (hashes.length === 0) {
    // Empty tree root: a fixed, well-known constant
    return sha256('empty');
  }

  let level = [...hashes];

  while (level.length > 1) {
    const next: string[] = [];
    for (let i = 0; i < level.length; i += 2) {
      if (i + 1 < level.length) {
        // Pair two adjacent nodes
        next.push(sha256(`node:${level[i]}:${level[i + 1]}`));
      } else {
        // Odd node: PROMOTE unpaired to next level
        next.push(level[i]!);
      }
    }
    level = next;
  }

  return level[0]!;
}

export async function buildMerkleTree(files: FileEntry[]): Promise<MerkleResult> {
  // Sort entries by relativePath lexicographically before tree construction
  const sorted = [...files].sort((a, b) =>
    a.relativePath.localeCompare(b.relativePath)
  );

  const entries: MerkleEntry[] = [];

  for (const file of sorted) {
    const rawBytes = await fs.readFile(file.absolutePath);
    const fileHash = sha256(rawBytes);
    const leafHash = sha256(`leaf:${file.relativePath}:${fileHash}`);
    entries.push({ path: file.relativePath, fileHash, leafHash });
  }

  const root = computeRoot(entries.map((e) => e.leafHash));

  return { root, hashAlgorithm: 'SHA-256', entries };
}
