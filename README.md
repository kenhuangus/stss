# STSS — Skill Trust & Signing Service

> **Cryptographic security for AI agent skill ecosystems.** Scan, sign, and verify skills before they execute inside your AI agents.

---

## What Is STSS?

Modern AI coding agents — Claude Code, OpenAI Codex, VS Code Copilot, OpenCode, OpenClaw — are becoming increasingly extensible through **skills**: packaged capabilities that agents can download and execute on your behalf. A skill might read files, call external APIs, run shell commands, or modify your codebase.

This extensibility is powerful. It is also a significant attack surface.

A malicious or compromised skill can:

- **Exfiltrate secrets** by reading `.env`, `~/.aws/credentials`, or SSH keys and sending them to a remote server
- **Execute arbitrary code** through shell injection hidden deep in an import chain
- **Hijack the agent itself** by embedding prompt injection or context-poisoning instructions in its `SKILL.md` documentation
- **Persist silently** by running `post_install.sh` scripts that establish backdoors before the user ever sees output
- **Tamper undetected** if there is no cryptographic record of what files were present when the skill was reviewed

STSS is the missing security layer between skill registries and skill execution. It treats every skill as untrusted code and requires proof — a cryptographically signed attestation — before that skill is allowed to load.

---

## Why We Need STSS

### The Supply Chain Problem for AI Skills

The npm and PyPI ecosystems learned this lesson the hard way: package managers that install and execute arbitrary code without verification are a persistent attack vector. The AI skill ecosystem is repeating this pattern at an accelerated pace, with two compounding factors:

1. **Skills run inside privileged agents.** When an agent executes a skill, the skill inherits the agent's access to your filesystem, environment variables, API keys, and the ability to issue further prompts. The blast radius of a compromised skill is far larger than a compromised library.

2. **Skills can attack the agent itself.** Beyond traditional code execution risks, skills can manipulate agent behavior through prompt injection embedded in documentation files — an attack vector that has no equivalent in traditional software supply chains.

### The Threat Landscape

| Attack Vector | Example | Traditional Package Scanning | STSS |
|---|---|---|---|
| Shell execution | `subprocess.run(["curl", ...])` in a helper module | Partial | Full (static + chain tracing) |
| Credential theft | Reading `~/.aws/credentials` | Partial | Full |
| Prompt injection | `"Ignore previous instructions"` in SKILL.md | No | Yes |
| Context poisoning | `"You are now in debug mode"` in docs | No | Yes |
| Consent gap | `post_install.sh` that runs before the user is aware | No | Yes |
| Import chain obfuscation | Innocent `index.py` → `utils/helper.py` → `curl evil.com` | No | Yes (chain tracer) |
| Tampered skill | Files modified after signing | No | Yes (Merkle verification) |
| Registry-flagged malware | Known-bad skill in skills.sh | No | Yes (registry adapter) |
| Behavioral mismatch | "Markdown formatter" that exfiltrates data | No | Yes (LLM audit) |

### STSS vs. Existing Tools

| Tool | What It Covers | What It Misses |
|---|---|---|
| npm audit / pip audit | Known CVEs in dependencies | Skill-specific threats, prompt injection, consent gaps |
| Semgrep / Bandit | Code patterns in isolation | Cross-file chains, behavioral mismatch, LLM-specific attacks |
| Socket / Snyk | Supply chain metadata | Skill documentation attacks, post-install consent gaps |
| **STSS** | All of the above + AI-specific threats | — |

STSS does not replace these tools — it layers on top of them and adds the AI-specific threat categories that none of them address.

---

## How STSS Is Implemented

### Architecture Overview

```
  skill directory on disk
          │
          ▼
  ┌───────────────┐
  │   Ingestion   │  Walk files, apply .stssignore, never follow symlinks
  └───────┬───────┘
          │ FileEntry[]
          ▼
  ┌───────────────────────────────────────────────────────┐
  │                    Scan Pipeline                      │
  │                                                       │
  │  ┌─────────────────┐   ┌──────────────────────────┐  │
  │  │  RegexAdapter   │   │     SemgrepAdapter        │  │
  │  │  (default,      │   │  (if semgrep on PATH,     │  │
  │  │   zero deps)    │   │   falls back to regex)    │  │
  │  └────────┬────────┘   └────────────┬─────────────┘  │
  │           │                         │                 │
  │           └────────────┬────────────┘                 │
  │                        │ Finding[]                    │
  │           ┌────────────▼────────────┐                 │
  │           │     Hook Detector       │  consent_gap    │
  │           │  (install scripts,      │  findings       │
  │           │   manifest hooks)       │                 │
  │           └────────────┬────────────┘                 │
  │                        │                              │
  │           ┌────────────▼────────────┐                 │
  │           │     Chain Tracer        │  cross_file     │
  │           │  (Python/JS/TS/Shell    │  findings       │
  │           │   import graphs)        │                 │
  │           └────────────┬────────────┘                 │
  │                        │                              │
  │           ┌────────────▼────────────┐                 │
  │           │     Caterpillar        │  credential,    │
  │           │  (auto-detected,       │  exfiltration,  │
  │           │   free)                │  supply chain   │
  │           └────────────┬────────────┘  findings       │
  │                        │                              │
  │           ┌────────────▼────────────┐                 │
  │           │      LLM Auditor        │  behavioral,    │
  │           │  (Claude API, opt-in)   │  contextual     │
  │           └────────────┬────────────┘  findings       │
  │                        │                              │
  │           ┌────────────▼────────────┐                 │
  │           │    Registry Adapter     │  registry       │
  │           │  (skills.sh, opt-in)    │  findings       │
  │           └────────────┬────────────┘                 │
  └────────────────────────┼──────────────────────────────┘
                           │ All Finding[]
                           ▼
                  ┌─────────────────┐
                  │  Policy Engine  │  PASS / PASS_WITH_WARNINGS / FAIL
                  └────────┬────────┘
                           │
               ┌───────────┴──────────────┐
               │ PASS or PASS_WITH_WARNINGS│
               ▼                          │
      ┌─────────────────┐                 │ FAIL
      │   Merkle Tree   │                 ▼
      │  SHA-256, det.  │      skill quarantined
      │  PROMOTE strat. │      STSS_REPORT.md written
      └────────┬────────┘
               │ root hash
               ▼
      ┌─────────────────┐
      │  Ed25519 Signer │  signs canonical JSON of attestation payload
      └────────┬────────┘
               │
               ▼
        attestation.json   ←── stored alongside skill, checked at load time
```

### Technology Stack

| Component | Technology |
|---|---|
| Language | TypeScript, strict mode throughout |
| Package manager | pnpm workspaces |
| Cryptography | `@noble/ed25519` (Ed25519), Node.js built-in `crypto` (SHA-256) |
| Validation | Zod — all external data validated before use, no unsafe casts |
| Static scanning | Custom RegexAdapter (zero deps) + SemgrepAdapter (optional) + [Caterpillar](https://github.com/alice-dot-io/caterpillar) (auto-detected) |
| Policy | YAML — `js-yaml` + Zod schema, supports snake_case and camelCase |
| Ignore rules | `ignore` package (gitignore syntax) |
| Shell analysis | `shellcheck` (if on PATH) with regex fallback |
| LLM audit | Anthropic Claude API (opt-in) |
| Registry | skills.sh API with 24h disk cache |
| CLI | `commander.js` + `chalk` |
| Testing | Vitest — 10 acceptance tests, all passing |

### Core Modules

| Module | Responsibility |
|---|---|
| `ingestion.ts` | Recursive async dir walk; symlink-safe; `.stssignore` support |
| `merkle.ts` | Deterministic SHA-256 Merkle tree; odd-node PROMOTE strategy; empty-tree constant |
| `scanner/regex-adapter.ts` | 9-category pattern scanner; per-file, per-line, with escalation logic |
| `scanner/semgrep-adapter.ts` | Shells out to `semgrep`; parses JSON output; falls back to regex |
| `hook-detector.ts` | Finds install scripts by name and manifest reference; runs shellcheck/regex on their contents |
| `chain-tracer.ts` | Builds import graph (Python/JS/TS/Shell); reverse BFS from finding to entry point |
| `caterpillar.ts` | Auto-detects [Caterpillar](https://github.com/alice-dot-io/caterpillar) on PATH; shells out for credential theft, exfiltration, and supply chain findings; offline or authenticated mode |
| `policy.ts` | Zod-validated YAML loader; neverSign / requireApproval / autoApprove decision logic |
| `llm-auditor.ts` | Calls Claude API with structured audit context; maps response to `Finding[]` |
| `registry-adapters/skillssh.ts` | Fetches skills.sh audit page; 24h TTL cache; synthetic CRITICAL on malicious flag |
| `signer.ts` | Ed25519 sign over canonical JSON; key held in memory only during signing |
| `verifier.ts` | Signature check → Merkle recompute → optional policy re-evaluation |
| `pipeline.ts` | Orchestrates the full scan → sign flow |

### Security Design Invariants

- **All file I/O is async** — no blocking calls in the scan path
- **Merkle tree is 100% deterministic** — identical files always produce the same root
- **Private keys are ephemeral** — resolved from ref, used, and the reference is discarded
- **LLM and registry passes are non-blocking** — any failure produces a warning; the scan always completes
- **All external data is Zod-validated** — policy YAML, attestation JSON, registry responses, LLM output
- **Exit codes are consistent** — `0` success, `1` security failure, `2` tool error

---

## Quickstart

Five commands from zero to a verified, signed skill:

```bash
# 1. Initialize a hub workspace
stss-hub init --workspace-dir .

# 2. Generate a signing keypair
stss keygen --out-dir ./keys

# 3. Export keys as environment variables
export STSS_SIGNING_KEY=$(cat ./keys/stss-private.key)
export STSS_PUBLIC_KEY=$(cat ./keys/stss-public.key)

# 4. Scan and sign a skill
stss scan-and-sign ./my-skill \
  --skill-id myorg/my-skill@1.0.0 \
  --out attestation.json

# 5. Verify the skill before loading
stss verify ./my-skill \
  --attestation attestation.json \
  --public-key "$STSS_PUBLIC_KEY"
```

---

## Installation

```bash
# CLI tools
npm install -g stss stss-hub

# Or from source (requires pnpm)
git clone https://github.com/kenhuangus/stss
cd stss
pnpm install
pnpm build
```

---

## Integrating STSS with AI Agent Platforms

STSS is designed to be platform-agnostic. It never modifies the host agent — it works entirely by controlling what enters skill directories and verifying attestations before load. The following examples show how to integrate it with the most common AI agent skill ecosystems.

---

### Claude Code

Claude Code loads skills from `~/.claude/skills/` (or a workspace-local `skills/` directory). STSS sits in front of that directory, scanning and signing before skills are allowed in.

**Setup:**

```bash
# Initialize STSS hub in your Claude Code workspace
stss-hub init --workspace-dir ~/.claude

# Generate and export your signing key
stss keygen --out-dir ~/.claude/keys
export STSS_SIGNING_KEY=$(cat ~/.claude/keys/stss-private.key)
export STSS_PUBLIC_KEY=$(cat ~/.claude/keys/stss-public.key)
```

**Installing a skill through STSS:**

```bash
# Install a skill from a local directory — STSS scans, signs, then copies to skills/
stss-hub install anthropic/web-search@1.2.0 \
  --workspace-dir ~/.claude \
  --local-path ./web-search-skill \
  --llm-audit \
  --registry-audit
```

**Verifying before Claude Code loads it:**

Add this to your shell profile or Claude Code startup script:

```bash
# Verify all installed skills on startup
for attestation in ~/.claude/.stss/attestations/*.json; do
  skill_name=$(basename "$attestation" .json | sed 's/-[0-9]*\.[0-9]*\.[0-9]*//')
  skill_dir=~/.claude/skills/${skill_name}
  if [ -d "$skill_dir" ]; then
    stss verify "$skill_dir" \
      --attestation "$attestation" \
      --public-key "$STSS_PUBLIC_KEY" || {
      echo "STSS: skill $skill_name failed verification — removing from skills/"
      rm -rf "$skill_dir"
    }
  fi
done
```

**Enforce in CI** (for teams sharing a `.claude/skills/` directory via version control):

```yaml
# .github/workflows/claude-skills-verify.yml
name: Verify Claude Code Skills
on:
  push:
    paths: ['.claude/skills/**']

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm install -g stss
      - name: Verify all skills
        env:
          STSS_PUBLIC_KEY: ${{ secrets.STSS_PUBLIC_KEY }}
        run: |
          for skill_dir in .claude/skills/*/; do
            attestation=".claude/.stss/attestations/$(basename $skill_dir).json"
            [ -f "$attestation" ] && stss verify "$skill_dir" --attestation "$attestation"
          done
```

---

### OpenClaw

OpenClaw uses a `skills/` directory in your workspace root and loads skills by name from `clawdhub`. STSS integrates as a wrapper around the `clawdhub install` workflow.

**Setup:**

```bash
# Initialize STSS hub (creates skills/, skills_raw/, skills_quarantine/, .stss/)
stss-hub init --workspace-dir .

# Install pre-commit hook so every committed skill change is scanned
stss-hub init-hooks
```

**Installing skills through STSS hub:**

```bash
# STSS calls clawdhub internally, then scans before promoting to skills/
stss-hub install openclaw/git-tools@2.0.1
stss-hub install openclaw/code-reviewer@1.5.0 --llm-audit

# If a skill fails — it lands in skills_quarantine/ with a full report
cat skills_quarantine/openclaw-suspicious-skill/STSS_REPORT.md
```

**Batch scan all installed skills:**

```bash
stss-hub scan --registry-audit
```

```
Skill                          Status   Critical  High  Medium
----------------------------------------------------------------------
openclaw-git-tools             PASS     0         0     0
openclaw-code-reviewer         PASS_WITH_WARNINGS  0    0     1
openclaw-risky-skill           FAIL     1         2     3
```

**Policy for OpenClaw teams:**

```yaml
# .stss/policy.yaml
stss_policy:
  version: "2.1.0"
  never_sign:
    - severity: [CRITICAL, HIGH]
      action: BLOCK
  require_approval:
    - severity: [MEDIUM]
      action: HUMAN_REVIEW
  auto_approve:
    - severity: [LOW, INFO]
      action: SIGN
  scanner_adapter: "regex"
  signing_key_ref: "env://STSS_SIGNING_KEY"
  registry_audit:
    enabled: true
    adapters: ["skills.sh"]
    fail_on_registry_malicious: true
```

---

### OpenAI Codex

Codex agents support skill/plugin directories for extending agent capabilities. Point STSS at your Codex skills directory before the agent runtime starts.

**Scanning Codex skills:**

```bash
# Scan a Codex skill directory
stss scan ./codex-skills/data-analyzer \
  --policy policy.yaml \
  --output findings.json

# Sign after review
stss scan-and-sign ./codex-skills/data-analyzer \
  --skill-id myorg/data-analyzer@1.0.0 \
  --key-ref env://STSS_SIGNING_KEY \
  --out ./codex-skills/data-analyzer/attestation.json
```

**Pre-flight verification script** (wrap your Codex agent launch):

```bash
#!/bin/bash
# verify-codex-skills.sh — run before launching Codex agent

SKILLS_DIR="./codex-skills"
PUBLIC_KEY="${STSS_PUBLIC_KEY}"
FAILED=0

for skill_dir in "$SKILLS_DIR"/*/; do
  attestation="${skill_dir}attestation.json"
  if [ ! -f "$attestation" ]; then
    echo "ERROR: No attestation found for $(basename $skill_dir)"
    FAILED=1
    continue
  fi

  stss verify "$skill_dir" \
    --attestation "$attestation" \
    --public-key "$PUBLIC_KEY" \
    --require-llm-audit || FAILED=1
done

if [ "$FAILED" -ne 0 ]; then
  echo "Skill verification failed. Aborting agent launch."
  exit 1
fi

echo "All skills verified. Launching Codex agent..."
exec codex-agent "$@"
```

**In your `Makefile` or task runner:**

```makefile
run-agent: verify-skills
	codex-agent --skills-dir ./codex-skills

verify-skills:
	bash verify-codex-skills.sh

sign-skills:
	for dir in codex-skills/*/; do \
	  name=$$(basename $$dir); \
	  stss scan-and-sign $$dir \
	    --skill-id myorg/$$name@1.0.0 \
	    --out $$dir/attestation.json; \
	done
```

---

### VS Code Skills (Copilot Extensions / Language Model Tools)

VS Code extensions that expose Language Model Tools (skills) can be verified using STSS before they are added to a shared development environment or distributed to a team.

**Scanning a VS Code extension skill directory:**

```bash
# Typical VS Code extension skill layout
stss scan ./vscode-extensions/my-lm-tool \
  --policy strict-policy.yaml \
  --llm-audit \
  --output scan-results.json
```

**Strict policy for VS Code skills** (tighter than default — no MEDIUM allowed):

```yaml
# strict-policy.yaml
stss_policy:
  version: "2.1.0"
  never_sign:
    - severity: [CRITICAL, HIGH, MEDIUM]
      action: BLOCK
  auto_approve:
    - severity: [LOW, INFO]
      action: SIGN
  scanner_adapter: "regex"
  signing_key_ref: "env://STSS_SIGNING_KEY"
  llm_audit:
    enabled: true
    adapter: "claude"
    model: "claude-sonnet-4-20250514"
    api_key_ref: "env://ANTHROPIC_API_KEY"
    escalate_on_behavioral_mismatch: true
    escalate_on_context_poisoning: true
    escalate_on_consent_gap: true
  registry_audit:
    enabled: true
    adapters: ["skills.sh"]
    fail_on_registry_malicious: true
```

**Team distribution workflow:**

```bash
# Developer signs the extension skill after review
stss scan-and-sign ./vscode-extensions/my-lm-tool \
  --skill-id myteam/my-lm-tool@2.1.0 \
  --policy strict-policy.yaml \
  --llm-audit \
  --registry-audit \
  --out ./vscode-extensions/my-lm-tool/stss-attestation.json

# Commit the attestation alongside the extension
git add vscode-extensions/my-lm-tool/stss-attestation.json
git commit -m "chore: sign my-lm-tool@2.1.0 after STSS review"
```

**CI gate for VS Code skill PRs:**

```yaml
# .github/workflows/vscode-skills-gate.yml
name: VS Code Skill Security Gate
on:
  pull_request:
    paths: ['vscode-extensions/**']

jobs:
  stss-gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm install -g stss
      - name: Scan changed extensions
        env:
          STSS_PUBLIC_KEY: ${{ secrets.STSS_PUBLIC_KEY }}
        run: |
          CHANGED=$(git diff --name-only origin/${{ github.base_ref }}...HEAD \
            | grep '^vscode-extensions/' | cut -d/ -f1-2 | sort -u)
          for ext_dir in $CHANGED; do
            [ -d "$ext_dir" ] || continue
            attestation="$ext_dir/stss-attestation.json"
            if [ -f "$attestation" ]; then
              stss verify "$ext_dir" --attestation "$attestation" --require-llm-audit
            else
              echo "No attestation for $ext_dir — running scan"
              stss scan "$ext_dir" --policy strict-policy.yaml && exit 1
            fi
          done
```

---

### OpenCode Skills

OpenCode is an open-source terminal AI coding agent with a skills directory at `~/.opencode/skills/`. STSS plugs in as a verification layer before skills are sourced.

**Setup:**

```bash
# One-time setup
stss-hub init --workspace-dir ~/.opencode
stss keygen --out-dir ~/.opencode/keys

# Add to your shell profile
export STSS_SIGNING_KEY=$(cat ~/.opencode/keys/stss-private.key)
export STSS_PUBLIC_KEY=$(cat ~/.opencode/keys/stss-public.key)
```

**Installing an OpenCode skill safely:**

```bash
# Stage the skill
cp -r ~/downloads/opencode-skill-example ~/.opencode/skills_raw/myorg-example/

# Scan and sign — promotes to skills/ only on PASS
stss-hub install myorg/example@1.0.0 \
  --workspace-dir ~/.opencode \
  --local-path ~/downloads/opencode-skill-example \
  --policy ~/.opencode/.stss/policy.yaml
```

**Shell wrapper for OpenCode:**

Replace your `opencode` invocation with this wrapper to enforce verification on every startup:

```bash
#!/bin/bash
# ~/.local/bin/opencode-safe

SKILLS_DIR=~/.opencode/skills
ATTESTATIONS_DIR=~/.opencode/.stss/attestations

echo "STSS: verifying skills before launch..."

for skill_dir in "$SKILLS_DIR"/*/; do
  [ -d "$skill_dir" ] || continue
  skill_name=$(basename "$skill_dir")

  # Find latest attestation for this skill
  attestation=$(ls -t "$ATTESTATIONS_DIR/${skill_name}"*.json 2>/dev/null | head -1)

  if [ -z "$attestation" ]; then
    echo "STSS WARNING: $skill_name has no attestation — skipping skill"
    continue
  fi

  if ! stss verify "$skill_dir" --attestation "$attestation" 2>/dev/null; then
    echo "STSS ERROR: $skill_name failed verification — disabling skill"
    mv "$skill_dir" ~/.opencode/skills_quarantine/ 2>/dev/null
  fi
done

echo "STSS: verification complete"
exec opencode "$@"
```

**Community skill policy** (for sharing skills publicly):

```yaml
# Publish this policy alongside your skill in the registry
stss_policy:
  version: "2.1.0"
  never_sign:
    - severity: [CRITICAL, HIGH]
      action: BLOCK
    - pattern: "eval\\(|exec\\("
      action: BLOCK
  require_approval:
    - severity: [MEDIUM]
      action: HUMAN_REVIEW
  auto_approve:
    - severity: [LOW, INFO]
      action: SIGN
  scanner_adapter: "regex"
  signing_key_ref: "env://STSS_SIGNING_KEY"
  registry_audit:
    enabled: true
    adapters: ["skills.sh"]
    fail_on_registry_malicious: true
```

---

## Directory Layout

After running `stss-hub init`, your workspace will look like this:

```
workspace/
├── skills/                         # Host-visible — only verified skills land here
│   └── myorg-my-skill/
│       ├── SKILL.md
│       └── src/
├── skills_raw/                     # Staging area — skills awaiting verification
│   └── myorg-my-skill/
├── skills_quarantine/              # Failed skills — quarantined with a STSS report
│   └── myorg-bad-skill/
│       ├── SKILL.md
│       └── STSS_REPORT.md          # Full findings table explaining the failure
└── .stss/
    ├── attestations/               # <namespace>-<name>-<version>.json
    │   └── myorg-my-skill-1.0.0.json
    ├── registry-cache/             # Cached registry adapter responses (24h TTL)
    │   └── myorg-my-skill.json
    └── config.yaml                 # Hub configuration
```

---

## Commands

### `stss scan`

Scan a skill directory and print a findings table.

```bash
stss scan <path> [options]

Options:
  --output <file>      Write findings as JSON to a file
  --policy <file>      Policy YAML file (default: built-in default policy)
  --llm-audit          Enable LLM-powered behavioral analysis (opt-in)
  --registry-audit     Enable skills.sh registry lookup (opt-in)
```

**Exit codes**: `0` = no CRITICAL/HIGH findings, `1` = CRITICAL/HIGH found, `2` = tool error

**Example output**:

```
SEVERITY  CATEGORY    FILE              LINE  MESSAGE
--------  ----------  ----------------  ----  ------------------------------------------
HIGH      shell       src/runner.py     2     Shell execution pattern detected
CRITICAL  consent_gap post_install.sh   1     Setup/install script detected
MEDIUM    network     src/fetcher.ts    8     Outbound network call detected

Summary:
  CRITICAL: 1
  HIGH:     1
  MEDIUM:   1
```

---

### `stss scan-and-sign`

Full pipeline: scan → policy evaluation → Merkle tree → sign attestation.

```bash
stss scan-and-sign <path> --skill-id <ns/name@version> [options]

Required:
  --skill-id <id>      Skill identifier (format: namespace/name@version)

Options:
  --policy <file>      Policy YAML file
  --out <file>         Output attestation file (default: attestation.json)
  --key-ref <ref>      Signing key reference
  --llm-audit          Enable LLM audit
  --registry-audit     Enable registry audit
```

**Exit codes**: `0` = signed successfully, `1` = policy FAIL, `2` = tool error

On success:
```
✓ Attestation signed
  Merkle root: a3f9c2d1e8b4...
  Output:      attestation.json
```

---

### `stss verify`

Verify a skill directory against a previously signed attestation.

```bash
stss verify <path> --attestation <file> [options]

Required:
  --attestation <file>   Signed attestation JSON

Options:
  --public-key <key>     Base64 public key or file://path (falls back to env://STSS_PUBLIC_KEY)
  --policy <file>        Stricter local policy override
  --require-llm-audit    Fail if attestation was produced without LLM audit
```

Verification checks in order:

1. **Signature** — Ed25519 signature over canonical JSON of the attestation payload
2. **Integrity** — recomputes the Merkle root from current disk contents and compares
3. **Policy** (optional) — re-evaluates the summary against a local policy override

**Exit codes**: `0` = OK, `1` = verification failed, `2` = tool error

---

### `stss-hub`

Workspace management CLI for environments hosting multiple skills.

```bash
stss-hub init [--workspace-dir .]          # Create directory structure and config
stss-hub install <skill-id> [options]      # Scan, sign, and install a skill
stss-hub update --all                      # Re-verify all installed skills
stss-hub scan [--llm-audit]               # Batch scan skills_raw/ or skills/
stss-hub init-hooks                        # Install git pre-commit hook + CI workflow
```

---

## Policy Configuration

```yaml
stss_policy:
  version: "2.1.0"

  never_sign:
    - severity: [CRITICAL, HIGH]
      action: BLOCK
    - pattern: "eval\\(|exec\\("          # regex match on finding message
      action: BLOCK

  require_approval:
    - severity: [MEDIUM]
      action: HUMAN_REVIEW               # treated as BLOCK in v1

  auto_approve:
    - severity: [LOW, INFO]
      action: SIGN

  scanner_adapter: "regex"               # "regex" (default) or "semgrep"
  signing_key_ref: "env://STSS_SIGNING_KEY"

  llm_audit:
    enabled: false
    adapter: "claude"
    model: "claude-sonnet-4-20250514"
    api_key_ref: "env://ANTHROPIC_API_KEY"
    escalate_on_behavioral_mismatch: true
    escalate_on_context_poisoning: true
    escalate_on_consent_gap: true

  registry_audit:
    enabled: false
    adapters: ["skills.sh"]
    fail_on_registry_malicious: true
```

### Default Policy Severity Table

| Severity | Default Decision |
|---|---|
| CRITICAL | FAIL |
| HIGH | FAIL |
| MEDIUM | FAIL |
| LOW | PASS\_WITH\_WARNINGS |
| INFO | PASS\_WITH\_WARNINGS |
| _(no findings)_ | PASS |

---

## Key Generation

```bash
stss keygen --out-dir ./keys
```

| File | Purpose |
|---|---|
| `stss-private.key` | Base64 Ed25519 private key — never commit, never share |
| `stss-public.key` | Base64 Ed25519 public key — distribute to verifiers, store in CI secrets |

**Key ref formats:**

| Format | Description |
|---|---|
| `env://VAR_NAME` | Read from environment variable (recommended for CI) |
| `file://path/to/key` | Read from file |
| `keychain://stss/...` | macOS Keychain (stub — falls back to `env://STSS_SIGNING_KEY`) |

---

## Enforcement Modes

| Mode | Behavior | Recommended For |
|---|---|---|
| `observe_only` | Scan and log; host application unaffected | Initial rollout, auditing |
| `warn_unverified` | Print warnings; skill still loads | Gradual adoption |
| `enforce_verified` | Block skills without a valid attestation | Production environments |

---

## Threat Detection

| Category | Severity | What Is Caught |
|---|---|---|
| `filesystem` | HIGH | `.ssh`, `.env`, `/etc/passwd`, `~/.aws`, `id_rsa`, `.npmrc` access |
| `shell` | HIGH | `subprocess`, `exec()`, `eval()`, `child_process`, `execSync`, `shelljs` |
| `network` | HIGH / CRITICAL | `fetch`, `axios`, `requests`, `urllib` — CRITICAL if paired with hardcoded IP/URL |
| `secrets` | HIGH | `process.env`, `os.environ`, hex/base64 strings adjacent to `key`/`secret`/`token`/`password` |
| `obfuscation` | HIGH | base64-decode + exec, `fromCharCode` chains (≥5), `unescape` + eval |
| `prompt_injection` | MEDIUM | Adversarial instructions in SKILL.md: "ignore previous", "you are now operating as" |
| `context_poisoning` | MEDIUM | Mode-switching language: "debug mode", "you have been granted", headings before shell commands |
| `consent_gap` | CRITICAL | `post_install.sh`, `setup.sh`, `install.sh` and any network calls within them |
| `cross_file_chain` | (inherited) | Import paths (Python/JS/TS/Shell) that lead from an innocent entry to flagged code |

**`.stssignore`** — exclude paths from scanning (gitignore syntax):

```
tests/fixtures/
*.snap
vendor/
```

---

## LLM Audit

LLM audit uses Claude to catch threats that pattern matching cannot:

- **Behavioral coherence** — does the code match the skill's declared purpose?
- **Context poisoning** — does SKILL.md try to reframe the agent's identity?
- **Consent gaps** — are there silent execution paths the user never approved?
- **Cross-file attack chains** — do indirect imports lead to malicious terminal code?

```bash
export ANTHROPIC_API_KEY=sk-ant-...
stss scan ./my-skill --llm-audit --policy policy.yaml
```

- LLM audit is **opt-in** and requires `llm_audit.enabled: true` in policy
- Only activates when MEDIUM+ static findings exist, or a `SKILL.md` is present
- API failures log a warning and do not abort the scan
- Use `stss verify --require-llm-audit` to enforce that a skill was LLM-audited

---

## Registry Audit

Cross-references skills against the [skills.sh](https://skills.sh) community registry (Gen, Socket, Snyk findings).

```bash
stss scan ./my-skill --registry-audit --policy policy.yaml
```

- Results cached to `.stss/registry-cache/` with a **24-hour TTL**
- Skills flagged as `"malicious"` by the registry produce a synthetic `CRITICAL` finding
- Network failures log a warning and do not abort the scan

---

## CI Integration

### GitHub Actions

```yaml
name: STSS Skill Verification
on:
  pull_request:
    paths: ['skills/**', '**/SKILL.md']

jobs:
  stss-verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: '20' }
      - run: npm install -g stss
      - name: Verify changed skills
        env:
          STSS_PUBLIC_KEY: ${{ secrets.STSS_PUBLIC_KEY }}
        run: |
          CHANGED=$(git diff --name-only origin/${{ github.base_ref }}...HEAD \
            | grep -E '(SKILL\.md|skills/)' | xargs -I{} dirname {} | sort -u)
          for ROOT in $CHANGED; do
            [ -f "$ROOT/SKILL.md" ] || continue
            ATTESTATION=".stss/attestations/$(basename $ROOT).json"
            if [ -f "$ATTESTATION" ]; then
              stss verify "$ROOT" --attestation "$ATTESTATION"
            else
              stss scan "$ROOT"
            fi
          done
```

### Git Pre-commit Hook

```bash
stss-hub init-hooks
```

Installs `.git/hooks/pre-commit` — automatically scans staged skill directories and blocks commits on CRITICAL or HIGH findings.

---

## Architecture

```
stss/
├── packages/
│   ├── core/                   # @stss/core — all security logic
│   │   └── src/
│   │       ├── ingestion.ts            # Async recursive dir walk
│   │       ├── merkle.ts               # SHA-256 Merkle tree
│   │       ├── scanner/
│   │       │   ├── types.ts            # Finding, ScannerAdapter interfaces
│   │       │   ├── regex-adapter.ts    # Default zero-dependency scanner
│   │       │   └── semgrep-adapter.ts  # Optional semgrep wrapper
│   │       ├── hook-detector.ts        # Consent gap detection
│   │       ├── chain-tracer.ts         # Cross-file import chain analysis
│   │       ├── policy.ts               # YAML policy + decision engine
│   │       ├── llm-auditor.ts          # Claude API behavioral analysis
│   │       ├── registry-adapters/
│   │       │   └── skillssh.ts         # skills.sh integration
│   │       ├── signer.ts               # Ed25519 signing
│   │       ├── verifier.ts             # Signature + Merkle verification
│   │       └── pipeline.ts             # Full orchestration
│   ├── cli/                    # stss binary (commander.js + chalk)
│   └── hub/                    # stss-hub binary
├── package.json
├── pnpm-workspace.yaml
└── tsconfig.base.json
```

### Attestation Payload

```json
{
  "attestation": {
    "schemaVersion": "stss/1.0",
    "skill": { "namespace": "myorg", "name": "my-skill", "version": "1.0.0" },
    "scan": {
      "timestamp": "2026-03-09T14:00:00Z",
      "toolVersion": "1.0.0",
      "summary": { "critical": 0, "high": 0, "medium": 0, "low": 1, "info": 0 },
      "llmAuditPerformed": true,
      "registryAuditPerformed": true,
      "consentGapAnalysis": true,
      "crossFileChainAnalysis": true
    },
    "policy": { "name": "default", "decision": "PASS_WITH_WARNINGS" },
    "merkle": { "root": "a3f9c2d1e8b4...", "hashAlgorithm": "SHA-256" },
    "fileHashes": [
      { "path": "SKILL.md", "hash": "d4e5f6..." },
      { "path": "src/index.ts", "hash": "7a8b9c..." }
    ]
  },
  "signature": "<base64-ed25519-signature>",
  "signingKeyId": "<base64-public-key>",
  "algorithm": "ed25519"
}
```

---

## License

MIT
