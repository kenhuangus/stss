export type { Finding, Severity, Category, ScannerAdapter } from './types.js';
export { RegexAdapter } from './regex-adapter.js';
export { SemgrepAdapter } from './semgrep-adapter.js';

import type { ScannerAdapter } from './types.js';
import { RegexAdapter } from './regex-adapter.js';
import { SemgrepAdapter } from './semgrep-adapter.js';

export function createAdapter(adapterName: string): ScannerAdapter {
  switch (adapterName) {
    case 'semgrep':
      return new SemgrepAdapter();
    case 'regex':
    default:
      if (adapterName && adapterName !== 'regex') {
        console.warn(`[stss] Unknown adapter "${adapterName}"; not implemented, falling back to semgrep/regex`);
      }
      return new RegexAdapter();
  }
}
