import type { FileEntry } from '../ingestion.js';

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type Category =
  | 'filesystem'
  | 'shell'
  | 'network'
  | 'secrets'
  | 'obfuscation'
  | 'prompt_injection'
  | 'context_poisoning'
  | 'consent_gap'
  | 'cross_file_chain';

export interface Finding {
  id: string;
  severity: Severity;
  category: Category;
  location: { file: string; line?: number };
  message: string;
  remediation?: string;
  source: 'static' | 'llm' | 'registry';
}

export interface ScannerAdapter {
  name: string;
  scan(files: FileEntry[], skillRoot: string): Promise<Finding[]>;
}
