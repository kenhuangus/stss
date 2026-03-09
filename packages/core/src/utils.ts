import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

/** Returns the path to a binary if it exists on PATH, otherwise null. */
export async function which(bin: string): Promise<string | null> {
  try {
    const { stdout } = await execFileAsync('which', [bin]);
    return stdout.trim() || null;
  } catch {
    return null;
  }
}

/** Resolve a key ref in the format env://VAR_NAME or file://path */
export async function resolveKeyRef(keyRef: string): Promise<Buffer> {
  if (keyRef.startsWith('env://')) {
    const varName = keyRef.slice(6);
    const val = process.env[varName];
    if (!val) throw new Error(`Key ref ${keyRef}: env var ${varName} not set`);
    return Buffer.from(val, 'base64');
  }
  if (keyRef.startsWith('file://')) {
    const { readFile } = await import('node:fs/promises');
    const filePath = keyRef.slice(7);
    const content = await readFile(filePath, 'utf-8');
    return Buffer.from(content.trim(), 'base64');
  }
  if (keyRef.startsWith('keychain://')) {
    console.warn('[stss] keychain key refs are not implemented; falling back to env://STSS_SIGNING_KEY');
    return resolveKeyRef('env://STSS_SIGNING_KEY');
  }
  throw new Error(`Unsupported key ref format: ${keyRef}`);
}

/** Canonical JSON — sorted keys, no extra whitespace */
export function canonicalJson(obj: unknown): string {
  return JSON.stringify(sortKeys(obj));
}

function sortKeys(obj: unknown): unknown {
  if (Array.isArray(obj)) return obj.map(sortKeys);
  if (obj !== null && typeof obj === 'object') {
    const sorted: Record<string, unknown> = {};
    for (const key of Object.keys(obj as Record<string, unknown>).sort()) {
      sorted[key] = sortKeys((obj as Record<string, unknown>)[key]);
    }
    return sorted;
  }
  return obj;
}
