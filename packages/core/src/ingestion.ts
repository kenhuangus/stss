import fs from 'node:fs/promises';
import path from 'node:path';
import ignoreModule from 'ignore';
import type { Ignore } from 'ignore';
// CJS default export compatibility shim
const ignore = ignoreModule as unknown as ((options?: object) => Ignore);

export interface FileEntry {
  relativePath: string; // normalized with forward slashes
  absolutePath: string;
  sizeBytes: number;
}

const DEFAULT_IGNORE_PATTERNS = [
  '.git/',
  'node_modules/',
  '.venv/',
  'build/',
  'dist/',
  '__pycache__/',
  '*.pyc',
  '.DS_Store',
];

async function walkDir(
  dir: string,
  skillRoot: string,
  ig: Ignore,
  results: FileEntry[]
): Promise<void> {
  let entries: import('node:fs').Dirent[];
  try {
    entries = await fs.readdir(dir, { withFileTypes: true });
  } catch {
    return;
  }

  for (const entry of entries) {
    const absolutePath = path.join(dir, entry.name);
    const relativePath = path
      .relative(skillRoot, absolutePath)
      .replace(/\\/g, '/');

    // Never follow symlinks
    if (entry.isSymbolicLink()) continue;

    if (ig.ignores(relativePath)) continue;

    if (entry.isDirectory()) {
      // Also check with trailing slash for directory patterns
      if (ig.ignores(relativePath + '/')) continue;
      await walkDir(absolutePath, skillRoot, ig, results);
    } else if (entry.isFile()) {
      const stat = await fs.stat(absolutePath);
      results.push({ relativePath, absolutePath, sizeBytes: stat.size });
    }
  }
}

export async function ingestSkillDirectory(
  skillRoot: string,
  ignorePatterns?: string[]
): Promise<FileEntry[]> {
  const ig = ignore();

  if (ignorePatterns !== undefined) {
    ig.add(ignorePatterns);
  } else {
    ig.add(DEFAULT_IGNORE_PATTERNS);

    // Load .stssignore if present
    const stssIgnorePath = path.join(skillRoot, '.stssignore');
    try {
      const content = await fs.readFile(stssIgnorePath, 'utf-8');
      ig.add(content);
    } catch {
      // File not found or unreadable — ignore
    }
  }

  const results: FileEntry[] = [];
  await walkDir(skillRoot, skillRoot, ig, results);

  // Sort lexicographically by relativePath
  results.sort((a, b) => a.relativePath.localeCompare(b.relativePath));

  return results;
}
