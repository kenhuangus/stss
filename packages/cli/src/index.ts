#!/usr/bin/env node
import { Command } from 'commander';
import chalk from 'chalk';
import fs from 'node:fs/promises';
import path from 'node:path';
import {
  generateKeypair,
  scan,
  scanAndSign,
  verify,
  loadPolicyAsync,
  DEFAULT_POLICY,
  type Finding,
  type SignedAttestation,
} from '@stss/core';

const program = new Command();

program
  .name('stss')
  .description('Skill Trust & Signing Service')
  .version('1.0.0');

// ── keygen ─────────────────────────────────────────────────────────────────────

program
  .command('keygen')
  .description('Generate an Ed25519 keypair for signing attestations')
  .option('--out-dir <dir>', 'Output directory', './keys')
  .action(async (opts: { outDir: string }) => {
    try {
      await fs.mkdir(opts.outDir, { recursive: true });
      const kp = await generateKeypair();
      const privPath = path.join(opts.outDir, 'stss-private.key');
      const pubPath = path.join(opts.outDir, 'stss-public.key');
      await fs.writeFile(privPath, kp.privateKey);
      await fs.writeFile(pubPath, kp.publicKey);

      console.log(chalk.green('✓ Keypair generated'));
      console.log(`  Private key: ${privPath}`);
      console.log(`  Public key:  ${pubPath}`);
      console.log('');
      console.log('Usage:');
      console.log(`  export STSS_SIGNING_KEY=$(cat ${privPath})`);
      console.log(`  export STSS_PUBLIC_KEY=$(cat ${pubPath})`);
      console.log('  stss scan-and-sign <skill-path> --skill-id ns/name@1.0.0');
    } catch (err) {
      console.error(chalk.red('Error:'), err);
      process.exit(2);
    }
  });

// ── scan ───────────────────────────────────────────────────────────────────────

program
  .command('scan <path>')
  .description('Scan a skill directory for security findings')
  .option('--output <file>', 'Write findings JSON to file')
  .option('--policy <file>', 'Policy YAML file')
  .option('--llm-audit', 'Enable LLM audit pass')
  .option('--registry-audit', 'Enable registry audit pass')
  .action(async (skillPath: string, opts: { output?: string; policy?: string; llmAudit?: boolean; registryAudit?: boolean }) => {
    try {
      const policy = opts.policy ? await loadPolicyAsync(opts.policy) : DEFAULT_POLICY;
      const result = await scan(path.resolve(skillPath), {
        policy,
        llmAudit: opts.llmAudit,
        registryAudit: opts.registryAudit,
      });

      printFindings(result.allFindings);
      printSummary(result.policyResult.summary);

      if (opts.output) {
        await fs.writeFile(opts.output, JSON.stringify(result.allFindings, null, 2));
        console.log(chalk.gray(`\nFindings written to ${opts.output}`));
      }

      const hasCriticalOrHigh = result.allFindings.some(
        (f) => f.severity === 'CRITICAL' || f.severity === 'HIGH'
      );
      process.exit(hasCriticalOrHigh ? 1 : 0);
    } catch (err) {
      console.error(chalk.red('Error:'), err);
      process.exit(2);
    }
  });

// ── scan-and-sign ──────────────────────────────────────────────────────────────

program
  .command('scan-and-sign <path>')
  .description('Full pipeline: scan, evaluate policy, Merkle, sign')
  .requiredOption('--skill-id <id>', 'Skill identifier (namespace/name@version)')
  .option('--policy <file>', 'Policy YAML file')
  .option('--out <file>', 'Output attestation JSON file', 'attestation.json')
  .option('--key-ref <ref>', 'Signing key reference (env://VAR or file://path)')
  .option('--llm-audit', 'Enable LLM audit pass')
  .option('--registry-audit', 'Enable registry audit pass')
  .action(async (skillPath: string, opts: { skillId: string; policy?: string; out: string; keyRef?: string; llmAudit?: boolean; registryAudit?: boolean }) => {
    try {
      const policy = opts.policy ? await loadPolicyAsync(opts.policy) : DEFAULT_POLICY;
      const [nsName, version = '1.0.0'] = opts.skillId.split('@');
      const slashIdx = (nsName ?? '').indexOf('/');
      const namespace = slashIdx >= 0 ? (nsName ?? '').slice(0, slashIdx) : 'default';
      const name = slashIdx >= 0 ? (nsName ?? '').slice(slashIdx + 1) : (nsName ?? '');

      let result;
      try {
        result = await scanAndSign(
          path.resolve(skillPath),
          { namespace, name, version },
          { policy, keyRef: opts.keyRef, llmAudit: opts.llmAudit, registryAudit: opts.registryAudit }
        );
      } catch (err: unknown) {
        // Policy FAIL
        const e = err as { policyResult?: { decision?: string; reason?: string; summary?: Record<string, number> }; allFindings?: Finding[] };
        if (e.policyResult?.decision === 'FAIL') {
          printFindings(e.allFindings ?? []);
          console.error(chalk.red.bold('\n✗ Policy FAIL: ') + e.policyResult.reason);
          process.exit(1);
        }
        throw err;
      }

      await fs.writeFile(opts.out, JSON.stringify(result.signedAttestation, null, 2));

      console.log(chalk.green.bold('✓ Attestation signed'));
      console.log(`  Merkle root: ${result.signedAttestation.attestation.merkle.root}`);
      console.log(`  Output:      ${opts.out}`);
      process.exit(0);
    } catch (err) {
      console.error(chalk.red('Error:'), err);
      process.exit(2);
    }
  });

// ── verify ─────────────────────────────────────────────────────────────────────

program
  .command('verify <path>')
  .description('Verify a skill against a signed attestation')
  .requiredOption('--attestation <file>', 'Signed attestation JSON file')
  .option('--public-key <key>', 'Base64 public key or file:// path')
  .option('--policy <file>', 'Local policy override YAML')
  .option('--require-llm-audit', 'Fail if attestation was produced without LLM audit')
  .action(async (skillPath: string, opts: { attestation: string; publicKey?: string; policy?: string; requireLlmAudit?: boolean }) => {
    try {
      const attestationJson = await fs.readFile(opts.attestation, 'utf-8');
      const signedAttestation: SignedAttestation = JSON.parse(attestationJson);

      const localPolicy = opts.policy ? await loadPolicyAsync(opts.policy) : undefined;

      const result = await verify(path.resolve(skillPath), signedAttestation, {
        publicKey: opts.publicKey,
        localPolicy,
        requireLlmAudit: opts.requireLlmAudit,
      });

      if (result.status === 'OK') {
        console.log(chalk.green.bold('✓ Verification passed'));
        console.log(`  Status: ${result.status}`);
        console.log(`  Reason: ${result.reason}`);
        process.exit(0);
      } else {
        console.log(chalk.red.bold('✗ Verification failed'));
        console.log(`  Status: ${result.status}`);
        console.log(`  Reason: ${result.reason}`);
        process.exit(1);
      }
    } catch (err) {
      console.error(chalk.red('Error:'), err);
      process.exit(2);
    }
  });

program.parse();

// ── Formatting helpers ────────────────────────────────────────────────────────

function severityColor(sev: string): (s: string) => string {
  switch (sev) {
    case 'CRITICAL': return chalk.red.bold;
    case 'HIGH': return chalk.red;
    case 'MEDIUM': return chalk.yellow;
    case 'LOW': return chalk.cyan;
    default: return chalk.gray;
  }
}

function printFindings(findings: Finding[]): void {
  if (findings.length === 0) {
    console.log(chalk.green('No findings.'));
    return;
  }

  const header = ['SEVERITY', 'CATEGORY', 'FILE', 'LINE', 'MESSAGE'];
  const rows = findings.map((f) => [
    f.severity,
    f.category,
    f.location.file,
    String(f.location.line ?? ''),
    f.message.slice(0, 60),
  ]);

  const colWidths = header.map((h, i) =>
    Math.max(h.length, ...rows.map((r) => (r[i] ?? '').length))
  );

  const fmt = (row: string[], color?: (s: string) => string) => {
    const line = row.map((cell, i) => cell.padEnd(colWidths[i] ?? 0)).join('  ');
    return color ? color(line) : line;
  };

  console.log(fmt(header));
  console.log('-'.repeat(colWidths.reduce((a, b) => a + b + 2, 0)));
  for (const [i, row] of rows.entries()) {
    const sev = findings[i]!.severity;
    console.log(fmt(row, severityColor(sev)));
  }
}

function printSummary(summary: { critical: number; high: number; medium: number; low: number; info: number }): void {
  console.log('');
  console.log('Summary:');
  if (summary.critical > 0) console.log(chalk.red.bold(`  CRITICAL: ${summary.critical}`));
  if (summary.high > 0) console.log(chalk.red(`  HIGH:     ${summary.high}`));
  if (summary.medium > 0) console.log(chalk.yellow(`  MEDIUM:   ${summary.medium}`));
  if (summary.low > 0) console.log(chalk.cyan(`  LOW:      ${summary.low}`));
  if (summary.info > 0) console.log(chalk.gray(`  INFO:     ${summary.info}`));
}
