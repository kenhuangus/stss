import fs from 'node:fs/promises';
import path from 'node:path';
import type { FileEntry } from './ingestion.js';
import type { Finding } from './scanner/types.js';

export interface ChainFinding extends Finding {
  chain: string[]; // [entry_file, ..., terminal_file]
  terminalFinding: Finding; // the flagged finding at the end of the chain
}

// Import resolution for Python, JS/TS, and Shell
function extractImports(content: string, filePath: string): string[] {
  const ext = path.extname(filePath).toLowerCase();
  const refs: string[] = [];

  if (ext === '.py') {
    // Python: import X, from X import Y, importlib.import_module
    const importPat = /^\s*import\s+([\w.]+)/gm;
    let m: RegExpExecArray | null;
    while ((m = importPat.exec(content)) !== null) {
      if (m[1]) refs.push(m[1]);
    }

    // from X import Y — try both X (the module) and X.Y (the submodule)
    const fromPat = /^\s*from\s+([\w.]+)\s+import\s+([\w,\s*]+)/gm;
    while ((m = fromPat.exec(content)) !== null) {
      if (m[1]) {
        refs.push(m[1]); // the base module
        // Also try each imported name as a submodule (e.g. from utils import helper → utils.helper)
        const names = (m[2] ?? '').split(',').map((n) => n.trim()).filter(Boolean);
        for (const name of names) {
          if (/^\w+$/.test(name)) refs.push(`${m[1]}.${name}`);
        }
      }
    }

    const importlibPat = /importlib\.import_module\s*\(\s*['"]([^'"]+)['"]/g;
    while ((m = importlibPat.exec(content)) !== null) {
      if (m[1]) refs.push(m[1]);
    }
  } else if (ext === '.js' || ext === '.ts' || ext === '.mjs' || ext === '.cjs') {
    // JS/TS: require(), import ... from, await import()
    const patterns = [
      /require\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
      /(?:^|\s)import\s+(?:[\w*{}\s,]+\s+from\s+)?['"]([^'"]+)['"]/gm,
      /await\s+import\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
    ];
    for (const pat of patterns) {
      let m: RegExpExecArray | null;
      while ((m = pat.exec(content)) !== null) {
        if (m[1]) refs.push(m[1]);
      }
    }
  } else if (ext === '.sh' || ext === '.bash' || ext === '') {
    // Shell: source, ., bash <file>, sh <file>
    const patterns = [
      /(?:source|\.)\s+([\w./]+)/g,
      /bash\s+([\w./]+)/g,
      /sh\s+([\w./]+)/g,
    ];
    for (const pat of patterns) {
      let m: RegExpExecArray | null;
      while ((m = pat.exec(content)) !== null) {
        if (m[1]) refs.push(m[1]);
      }
    }
  }

  return refs;
}

function resolveImportToPath(
  importRef: string,
  importerPath: string,
  fileMap: Map<string, FileEntry>
): string | null {
  const importerDir = path.dirname(importerPath);

  // Convert Python module paths to file paths (e.g. "utils.helper" -> "utils/helper.py")
  const ext = path.extname(importerPath).toLowerCase();
  let candidates: string[] = [];

  if (ext === '.py') {
    // Try dotted module path → relative file
    const asPath = importRef.replace(/\./g, '/');
    candidates = [
      `${asPath}.py`,
      `${asPath}/__init__.py`,
      path.join(importerDir, `${asPath}.py`).replace(/\\/g, '/'),
      path.join(importerDir, `${asPath}/__init__.py`).replace(/\\/g, '/'),
    ];
  } else {
    // JS/TS relative imports
    if (importRef.startsWith('.')) {
      const base = path.join(importerDir, importRef).replace(/\\/g, '/');
      candidates = [
        base,
        `${base}.ts`,
        `${base}.js`,
        `${base}/index.ts`,
        `${base}/index.js`,
      ];
    }
  }

  for (const candidate of candidates) {
    // Normalize
    const normalized = candidate.replace(/^\/+/, '');
    if (fileMap.has(normalized)) return normalized;
    // Also try without leading ./
    const stripped = normalized.replace(/^\.\//, '');
    if (fileMap.has(stripped)) return stripped;
  }

  return null;
}

export async function traceImportChains(
  files: FileEntry[],
  staticFindings: Finding[],
  _skillRoot: string
): Promise<ChainFinding[]> {
  // Build file map: relativePath → FileEntry
  const fileMap = new Map<string, FileEntry>();
  for (const f of files) fileMap.set(f.relativePath, f);

  // Build import graph: file → set of files it imports
  const importGraph = new Map<string, Set<string>>();
  for (const file of files) {
    importGraph.set(file.relativePath, new Set());
  }

  for (const file of files) {
    let content: string;
    try {
      content = await fs.readFile(file.absolutePath, 'utf-8');
    } catch {
      continue;
    }

    const imports = extractImports(content, file.relativePath);
    for (const ref of imports) {
      const resolved = resolveImportToPath(ref, file.relativePath, fileMap);
      if (resolved && resolved !== file.relativePath) {
        importGraph.get(file.relativePath)!.add(resolved);
      }
    }
  }

  // Build reverse graph: file → set of files that import it
  const reverseGraph = new Map<string, Set<string>>();
  for (const file of files) {
    reverseGraph.set(file.relativePath, new Set());
  }
  for (const [importer, imported] of importGraph) {
    for (const dep of imported) {
      if (!reverseGraph.has(dep)) reverseGraph.set(dep, new Set());
      reverseGraph.get(dep)!.add(importer);
    }
  }

  // For each static finding, walk reverse graph to find entry points
  const chainFindings: ChainFinding[] = [];
  const seen = new Set<string>(); // deduplicate entry→terminal pairs

  for (const finding of staticFindings) {
    const terminalFile = finding.location.file;

    // BFS/DFS to find all entry points that can reach terminalFile
    const visited = new Set<string>();
    const queue: Array<{ file: string; chain: string[] }> = [
      { file: terminalFile, chain: [terminalFile] },
    ];

    while (queue.length > 0) {
      const item = queue.shift()!;
      if (visited.has(item.file)) continue;
      visited.add(item.file);

      const importers = reverseGraph.get(item.file) ?? new Set();

      if (importers.size === 0 && item.chain.length > 1) {
        // item.file is an entry point (nothing imports it), and there's a chain
        const chainKey = `${item.chain[item.chain.length - 1]}→${terminalFile}`;
        if (!seen.has(chainKey)) {
          seen.add(chainKey);
          const fullChain = [...item.chain].reverse();
          chainFindings.push({
            id: `CHAIN-${String(chainFindings.length + 1).padStart(3, '0')}`,
            category: 'cross_file_chain',
            severity: finding.severity,
            location: { file: fullChain[0]! },
            message: `Import chain leads to: ${finding.message} (in ${terminalFile})`,
            source: 'static',
            chain: fullChain,
            terminalFinding: finding,
          });
        }
      } else {
        for (const importer of importers) {
          if (!visited.has(importer)) {
            queue.push({ file: importer, chain: [...item.chain, importer] });
          }
        }
      }
    }
  }

  return chainFindings;
}
