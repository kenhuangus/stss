import fs from 'node:fs/promises';
import path from 'node:path';
import { z } from 'zod';
import type { Finding, Severity } from '../scanner/types.js';

export interface SkillId {
  namespace: string;
  name: string;
  version?: string;
}

export interface RegistryAdapter {
  name: string;
  fetch(skillId: SkillId): Promise<Finding[]>;
}

const CACHE_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

const CacheSchema = z.object({
  timestamp: z.number(),
  findings: z.array(z.object({
    id: z.string(),
    severity: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']),
    category: z.string(),
    location: z.object({ file: z.string(), line: z.number().optional() }),
    message: z.string(),
    remediation: z.string().optional(),
    source: z.literal('registry'),
  })),
});

function mapSeverity(s: string): Severity {
  const u = s.toUpperCase();
  if (u === 'CRITICAL' || u === 'C') return 'CRITICAL';
  if (u === 'HIGH' || u === 'H') return 'HIGH';
  if (u === 'MEDIUM' || u === 'MODERATE' || u === 'M') return 'MEDIUM';
  if (u === 'LOW' || u === 'L') return 'LOW';
  return 'INFO';
}

export class SkillsShAdapter implements RegistryAdapter {
  name = 'skills.sh';

  constructor(private readonly cacheDir: string = '.stss/registry-cache') {}

  private cacheKey(skillId: SkillId): string {
    return `${skillId.namespace}-${skillId.name}.json`;
  }

  private cachePath(skillId: SkillId): string {
    return path.join(this.cacheDir, this.cacheKey(skillId));
  }

  private async readCache(skillId: SkillId): Promise<Finding[] | null> {
    try {
      const raw = await fs.readFile(this.cachePath(skillId), 'utf-8');
      const data = CacheSchema.parse(JSON.parse(raw));
      if (Date.now() - data.timestamp < CACHE_TTL_MS) {
        return data.findings as Finding[];
      }
    } catch {
      // cache miss or parse error
    }
    return null;
  }

  private async writeCache(skillId: SkillId, findings: Finding[]): Promise<void> {
    try {
      await fs.mkdir(this.cacheDir, { recursive: true });
      await fs.writeFile(
        this.cachePath(skillId),
        JSON.stringify({ timestamp: Date.now(), findings })
      );
    } catch {
      // Non-fatal
    }
  }

  async fetch(skillId: SkillId): Promise<Finding[]> {
    const cached = await this.readCache(skillId);
    if (cached !== null) return cached;

    try {
      const url = `https://skills.sh/${skillId.namespace}/${skillId.name}`;
      const response = await fetch(url, {
        headers: { 'Accept': 'application/json' },
        signal: AbortSignal.timeout(10000),
      });

      if (!response.ok) {
        console.warn(`[stss] skills.sh fetch failed: ${response.status} for ${url}`);
        return [];
      }

      const data = await response.json() as {
        malicious?: boolean;
        findings?: Array<{
          id?: string;
          severity: string;
          category?: string;
          message: string;
          file?: string;
        }>;
      };

      const findings: Finding[] = [];

      // Synthetic CRITICAL finding if marked malicious
      if (data.malicious) {
        findings.push({
          id: 'REG-MALICIOUS',
          severity: 'CRITICAL',
          category: 'shell',
          location: { file: 'registry' },
          message: 'skills.sh registry has flagged this skill as malicious',
          source: 'registry',
        });
      }

      for (const f of data.findings ?? []) {
        findings.push({
          id: f.id ?? `REG-${String(findings.length + 1).padStart(3, '0')}`,
          severity: mapSeverity(f.severity),
          category: (f.category as Finding['category']) ?? 'shell',
          location: { file: f.file ?? 'registry' },
          message: f.message,
          source: 'registry',
        });
      }

      await this.writeCache(skillId, findings);
      return findings;
    } catch (err) {
      console.warn('[stss] Registry adapter fetch failed, continuing without registry findings:', err);
      return [];
    }
  }
}
