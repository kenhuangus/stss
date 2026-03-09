#!/usr/bin/env node
import { Command } from 'commander';
import chalk from 'chalk';
import fs from 'node:fs/promises';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import {
  scan,
  scanAndSign,
  loadPolicyAsync,
  DEFAULT_POLICY,
  ingestSkillDirectory,
  type Policy,
  type Finding,
} from '@stss/core';

const execFileAsync = promisify(execFile);

const program = new Command();

program
  .name('stss-hub')
  .description('STSS Hub — install, update, and batch-scan skills')
  .version('1.0.0');

// ── Directory layout helpers ──────────────────────────────────────────────────

interface HubDirs {
  workspace: string;
  skills: string;
  skillsRaw: string;
  quarantine: string;
  stss: string;
  attestations: string;
  registryCache: string;
}

function hubDirs(workspaceDir: string): HubDirs {
  const stss = path.join(workspaceDir, '.stss');
  return {
    workspace: workspaceDir,
    skills: path.join(workspaceDir, 'skills'),
    skillsRaw: path.join(workspaceDir, 'skills_raw'),
    quarantine: path.join(workspaceDir, 'skills_quarantine'),
    stss,
    attestations: path.join(stss, 'attestations'),
    registryCache: path.join(stss, 'registry-cache'),
  };
}

async function ensureDirs(dirs: HubDirs): Promise<void> {
  for (const d of Object.values(dirs)) {
    await fs.mkdir(d, { recursive: true });
  }
}

// ── init ──────────────────────────────────────────────────────────────────────

program
  .command('init')
  .description('Initialize hub workspace directory structure')
  .option('--workspace-dir <dir>', 'Workspace directory', '.')
  .action(async (opts: { workspaceDir: string }) => {
    try {
      const dirs = hubDirs(path.resolve(opts.workspaceDir));
      await ensureDirs(dirs);

      const configPath = path.join(dirs.stss, 'config.yaml');
      const configExists = await fs.access(configPath).then(() => true).catch(() => false);
      if (!configExists) {
        await fs.writeFile(configPath, `stss_hub:
  version: "1.0.0"
  default_policy: ".stss/policy.yaml"
  signing_key_ref: "env://STSS_SIGNING_KEY"
`);
      }

      const stssignorePath = path.join(dirs.workspace, '.stssignore');
      const ignoreExists = await fs.access(stssignorePath).then(() => true).catch(() => false);
      if (!ignoreExists) {
        await fs.writeFile(stssignorePath, `# STSS ignore patterns
node_modules/
.venv/
build/
dist/
__pycache__/
*.pyc
.DS_Store
`);
      }

      console.log(chalk.green('✓ Hub workspace initialized'));
      console.log(`  skills/            — verified skills land here`);
      console.log(`  skills_raw/        — staging area`);
      console.log(`  skills_quarantine/ — failed skills`);
      console.log(`  .stss/             — attestations and config`);
      console.log('');
      console.log('Next steps:');
      console.log('  stss-hub install <namespace/name@version> --local-path ./my-skill');
    } catch (err) {
      console.error(chalk.red('Error:'), err);
      process.exit(2);
    }
  });

// ── install ────────────────────────────────────────────────────────────────────

program
  .command('install <skill-id>')
  .description('Install and verify a skill')
  .option('--workspace-dir <dir>', 'Workspace directory', '.')
  .option('--local-path <dir>', 'Local skill directory to install from')
  .option('--policy <file>', 'Policy YAML file')
  .option('--key-ref <ref>', 'Signing key ref')
  .option('--llm-audit', 'Enable LLM audit')
  .option('--registry-audit', 'Enable registry audit')
  .action(async (skillId: string, opts: {
    workspaceDir: string; localPath?: string; policy?: string;
    keyRef?: string; llmAudit?: boolean; registryAudit?: boolean;
  }) => {
    try {
      const dirs = hubDirs(path.resolve(opts.workspaceDir));
      await ensureDirs(dirs);

      const [nsName, version = '1.0.0'] = skillId.split('@');
      const slashIdx = (nsName ?? '').indexOf('/');
      const namespace = slashIdx >= 0 ? (nsName ?? '').slice(0, slashIdx) : 'default';
      const name = slashIdx >= 0 ? (nsName ?? '').slice(slashIdx + 1) : (nsName ?? '');
      const dirName = `${namespace}-${name}`;

      const rawDir = path.join(dirs.skillsRaw, dirName);

      if (opts.localPath) {
        // Copy from local path
        await fs.cp(path.resolve(opts.localPath), rawDir, { recursive: true });
      } else {
        // Try clawdhub
        try {
          await execFileAsync('clawdhub', ['install', skillId, '--workdir', dirs.skillsRaw]);
        } catch {
          console.error(chalk.red('Error: no install source; use --local-path or install clawdhub'));
          process.exit(2);
        }
      }

      const policy = opts.policy ? await loadPolicyAsync(opts.policy) : DEFAULT_POLICY;

      let result;
      try {
        result = await scanAndSign(
          rawDir,
          { namespace, name, version },
          { policy, keyRef: opts.keyRef ?? policy.signingKeyRef, llmAudit: opts.llmAudit, registryAudit: opts.registryAudit }
        );
      } catch (err: unknown) {
        const e = err as { policyResult?: { decision?: string; reason?: string }; allFindings?: Finding[] };
        if (e.policyResult?.decision === 'FAIL') {
          // Quarantine
          const qDir = path.join(dirs.quarantine, dirName);
          await fs.cp(rawDir, qDir, { recursive: true });

          const report = buildReport(e.allFindings ?? [], e.policyResult.reason ?? 'Policy FAIL');
          await fs.writeFile(path.join(qDir, 'STSS_REPORT.md'), report);

          console.error(chalk.red.bold(`✗ Skill quarantined — see skills_quarantine/${dirName}/STSS_REPORT.md`));
          process.exit(1);
        }
        throw err;
      }

      // Copy to skills/
      const skillsDir = path.join(dirs.skills, dirName);
      await fs.cp(rawDir, skillsDir, { recursive: true });

      // Save attestation
      const attestationPath = path.join(dirs.attestations, `${dirName}-${version}.json`);
      await fs.writeFile(attestationPath, JSON.stringify(result.signedAttestation, null, 2));

      console.log(chalk.green.bold('✓ Skill installed and verified'));
      console.log(`  Location:    ${skillsDir}`);
      console.log(`  Attestation: ${attestationPath}`);
    } catch (err) {
      console.error(chalk.red('Error:'), err);
      process.exit(2);
    }
  });

// ── update ─────────────────────────────────────────────────────────────────────

program
  .command('update')
  .description('Re-verify one or all installed skills')
  .option('--all', 'Update all installed skills')
  .option('[skill-id]', 'Specific skill to update')
  .option('--workspace-dir <dir>', 'Workspace directory', '.')
  .action(async (opts: { all?: boolean; workspaceDir: string }) => {
    try {
      const dirs = hubDirs(path.resolve(opts.workspaceDir));
      const skillsDirs = await fs.readdir(dirs.skills);

      for (const dirName of skillsDirs) {
        const skillPath = path.join(dirs.skills, dirName);
        const stat = await fs.stat(skillPath);
        if (!stat.isDirectory()) continue;

        console.log(chalk.blue(`Updating ${dirName}...`));
        try {
          const result = await scan(skillPath, { policy: DEFAULT_POLICY });
          if (result.policyResult.decision === 'FAIL') {
            console.log(chalk.red(`  ✗ ${dirName}: FAIL`));
          } else {
            console.log(chalk.green(`  ✓ ${dirName}: ${result.policyResult.decision}`));
          }
        } catch (err) {
          console.error(chalk.red(`  Error updating ${dirName}:`), err);
        }
      }
    } catch (err) {
      console.error(chalk.red('Error:'), err);
      process.exit(2);
    }
  });

// ── scan ─────────────────────────────────────────────────────────────────────

program
  .command('scan')
  .description('Batch scan all skills in skills_raw/ (or skills/)')
  .option('--workspace-dir <dir>', 'Workspace directory', '.')
  .option('--llm-audit', 'Enable LLM audit')
  .option('--registry-audit', 'Enable registry audit')
  .action(async (opts: { workspaceDir: string; llmAudit?: boolean; registryAudit?: boolean }) => {
    try {
      const dirs = hubDirs(path.resolve(opts.workspaceDir));

      let targetDir = dirs.skillsRaw;
      let targetEntries = await fs.readdir(targetDir).catch(() => []);
      if (targetEntries.length === 0) {
        targetDir = dirs.skills;
        targetEntries = await fs.readdir(targetDir).catch(() => []);
      }

      if (targetEntries.length === 0) {
        console.log(chalk.gray('No skills found.'));
        return;
      }

      console.log(chalk.bold('Skill                          Status   Critical  High  Medium'));
      console.log('-'.repeat(70));

      for (const entry of targetEntries) {
        const skillPath = path.join(targetDir, entry);
        const stat = await fs.stat(skillPath).catch(() => null);
        if (!stat?.isDirectory()) continue;

        try {
          const result = await scan(skillPath, {
            policy: DEFAULT_POLICY,
            llmAudit: opts.llmAudit,
            registryAudit: opts.registryAudit,
          });
          const s = result.policyResult.summary;
          const statusColor = result.policyResult.decision === 'PASS' ? chalk.green
            : result.policyResult.decision === 'PASS_WITH_WARNINGS' ? chalk.yellow
            : chalk.red;
          console.log(
            `${entry.padEnd(30)} ${statusColor(result.policyResult.decision.padEnd(8))} ${String(s.critical).padEnd(9)} ${String(s.high).padEnd(5)} ${s.medium}`
          );
        } catch {
          console.log(`${entry.padEnd(30)} ${chalk.red('ERROR')}`);
        }
      }
    } catch (err) {
      console.error(chalk.red('Error:'), err);
      process.exit(2);
    }
  });

// ── init-hooks ────────────────────────────────────────────────────────────────

program
  .command('init-hooks')
  .description('Install git pre-commit hook and GitHub Actions workflow')
  .option('--workspace-dir <dir>', 'Workspace directory', '.')
  .action(async (opts: { workspaceDir: string }) => {
    try {
      const ws = path.resolve(opts.workspaceDir);

      // Git pre-commit hook
      const hooksDir = path.join(ws, '.git', 'hooks');
      await fs.mkdir(hooksDir, { recursive: true });
      const preCommitPath = path.join(hooksDir, 'pre-commit');
      await fs.writeFile(preCommitPath, PRE_COMMIT_HOOK);
      await fs.chmod(preCommitPath, 0o755);

      // GitHub Actions workflow
      const workflowsDir = path.join(ws, '.github', 'workflows');
      await fs.mkdir(workflowsDir, { recursive: true });
      await fs.writeFile(path.join(workflowsDir, 'stss-verify.yml'), GH_WORKFLOW);

      console.log(chalk.green('✓ Git hooks and CI workflow installed'));
      console.log(`  .git/hooks/pre-commit`);
      console.log(`  .github/workflows/stss-verify.yml`);
    } catch (err) {
      console.error(chalk.red('Error:'), err);
      process.exit(2);
    }
  });

program.parse();

// ── Helpers ───────────────────────────────────────────────────────────────────

function buildReport(findings: Finding[], reason: string): string {
  const lines = [
    '# STSS Security Report',
    '',
    `**Policy Decision**: FAIL`,
    `**Reason**: ${reason}`,
    '',
    '## Findings',
    '',
    '| Severity | Category | File | Line | Message |',
    '|----------|----------|------|------|---------|',
  ];
  for (const f of findings) {
    lines.push(`| ${f.severity} | ${f.category} | ${f.location.file} | ${f.location.line ?? ''} | ${f.message} |`);
  }
  return lines.join('\n');
}

const PRE_COMMIT_HOOK = `#!/bin/sh
# STSS pre-commit hook — auto-generated
# Detects staged skill directories and scans them

STAGED=$(git diff --cached --name-only | grep -E '(SKILL\\.md|skills/)')
if [ -z "$STAGED" ]; then exit 0; fi

SKILL_ROOTS=$(echo "$STAGED" | xargs -I{} dirname {} | sort -u)
FAILED=0

for ROOT in $SKILL_ROOTS; do
  if [ -f "$ROOT/SKILL.md" ] || [ -d "$ROOT" ]; then
    echo "STSS: scanning $ROOT..."
    npx stss scan "$ROOT"
    if [ $? -ne 0 ]; then FAILED=1; fi
  fi
done

if [ $FAILED -ne 0 ]; then
  echo "STSS: CRITICAL or HIGH findings detected. Commit blocked."
  echo "Run 'stss scan <path>' to see details."
  exit 1
fi
`;

const GH_WORKFLOW = `name: STSS Skill Verification
on:
  pull_request:
    paths:
      - 'skills/**'
      - '**/SKILL.md'

jobs:
  stss-verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: '20' }
      - run: npm install -g stss
      - name: Verify changed skills
        run: |
          CHANGED=$(git diff --name-only origin/\${{ github.base_ref }}...HEAD | grep -E '(SKILL\\.md|skills/)' | xargs -I{} dirname {} | sort -u)
          for ROOT in $CHANGED; do
            if [ -f "$ROOT/SKILL.md" ]; then
              echo "Verifying $ROOT..."
              ATTESTATION=".stss/attestations/$(basename $ROOT).json"
              if [ -f "$ATTESTATION" ]; then
                stss verify "$ROOT" --attestation "$ATTESTATION"
              else
                stss scan "$ROOT"
              fi
            fi
          done
`;
