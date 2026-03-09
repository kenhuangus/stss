# STSS — Skill Trust & Signing Service

A security layer for AI agent skill ecosystems. STSS scans skill directories for threats, computes cryptographic integrity proofs, and issues signed attestations that can be verified before skills are loaded.

**Core principle**: STSS never modifies host application code. It works entirely by controlling what enters skill directories.

---

## Table of Contents

- [Quickstart](#quickstart)
- [How It Works](#how-it-works)
- [Installation](#installation)
- [Key Generation](#key-generation)
- [Directory Layout](#directory-layout)
- [Commands](#commands)
  - [stss scan](#stss-scan)
  - [stss scan-and-sign](#stss-scan-and-sign)
  - [stss verify](#stss-verify)
  - [stss-hub](#stss-hub)
- [Policy Configuration](#policy-configuration)
- [Enforcement Modes](#enforcement-modes)
- [Threat Detection](#threat-detection)
- [LLM Audit](#llm-audit)
- [Registry Audit](#registry-audit)
- [CI Integration](#ci-integration)
- [Architecture](#architecture)

---

## Quickstart

Five commands from zero to a verified, signed skill:

```bash
# 1. Initialize a hub workspace
stss-hub init --workspace-dir .

# 2. Generate a signing keypair
stss keygen --out-dir ./keys

# 3. Export the private key
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

## How It Works

```
skill directory
      │
      ▼
 ┌─────────────┐     ┌──────────────────┐     ┌──────────────────┐
 │  Ingestion  │────▶│  Static Scanner  │────▶│  Hook Detector   │
 └─────────────┘     └──────────────────┘     └──────────────────┘
      │                      │                         │
      │               ┌──────▼──────┐                  │
      │               │Chain Tracer │                  │
      │               └──────┬──────┘                  │
      │                      │         ┌───────────────▼────────────┐
      │                      └─────────▶    All Findings Merged     │
      │                                └──────────────┬─────────────┘
      │                                               │
      ▼                                        ┌──────▼──────┐
 ┌──────────┐                                  │Policy Engine│
 │  Merkle  │                                  └──────┬──────┘
 │   Tree   │                                         │ PASS / PASS_WITH_WARNINGS
 └────┬─────┘                                         │
      │                                        ┌──────▼──────┐
      └───────────────────────────────────────▶│   Signer    │
                                               └──────┬──────┘
                                                      │
                                               signed attestation.json
```

1. **Ingest** — walks the skill directory, respects `.stssignore`, never follows symlinks
2. **Scan** — runs static analysis across 9 threat categories
3. **Detect hooks** — identifies setup scripts and install hooks that could execute silently
4. **Trace chains** — follows import graphs to find indirect paths to dangerous code
5. **Evaluate policy** — applies configurable rules to produce a PASS/FAIL decision
6. **Merkle + Sign** — builds a deterministic content hash and signs an attestation with Ed25519
7. **Verify** — at load time, re-computes the Merkle root and checks the signature

---

## Installation

```bash
# CLI tools
npm install -g stss stss-hub

# Or from source (requires pnpm)
git clone https://github.com/yourorg/stss
cd stss
pnpm install
pnpm build
```

---

## Key Generation

```bash
stss keygen --out-dir ./keys
```

This writes two files:

| File | Purpose |
|------|---------|
| `stss-private.key` | Base64-encoded Ed25519 private key — keep secret |
| `stss-public.key` | Base64-encoded Ed25519 public key — distribute to verifiers |

**Supported key ref formats** for `--key-ref` and `signing_key_ref`:

| Format | Description |
|--------|-------------|
| `env://VAR_NAME` | Read base64 key from environment variable (recommended) |
| `file://path/to/key` | Read base64 key from file |
| `keychain://stss/...` | macOS Keychain (stub — falls back to `env://STSS_SIGNING_KEY`) |

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

On success, prints:
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

Hub management CLI for workspaces hosting multiple skills.

```bash
# Initialize workspace structure
stss-hub init [--workspace-dir .]

# Install and verify a skill from a local directory
stss-hub install myorg/my-skill@1.0.0 --local-path ./my-skill

# Install via clawdhub (if installed)
stss-hub install myorg/my-skill@1.0.0

# Batch scan all skills in skills_raw/
stss-hub scan [--llm-audit] [--registry-audit]

# Re-verify installed skills
stss-hub update --all

# Install git pre-commit hook and GitHub Actions workflow
stss-hub init-hooks
```

---

## Policy Configuration

Create a `policy.yaml` to customize enforcement rules:

```yaml
stss_policy:
  version: "2.1.0"

  # Block signing if any of these conditions are met
  never_sign:
    - severity: [CRITICAL, HIGH]
      action: BLOCK
    - pattern: "eval\\(|exec\\("    # regex match on finding message
      action: BLOCK

  # Require human review (currently treated as BLOCK in v1)
  require_approval:
    - severity: [MEDIUM]
      action: HUMAN_REVIEW

  # Auto-approve low-severity findings
  auto_approve:
    - severity: [LOW, INFO]
      action: SIGN

  # Scanner backend: "regex" (default, zero deps) or "semgrep"
  scanner_adapter: "regex"

  # Signing key reference
  signing_key_ref: "env://STSS_SIGNING_KEY"

  # Optional: LLM-powered audit (see LLM Audit section)
  llm_audit:
    enabled: false
    adapter: "claude"
    model: "claude-sonnet-4-20250514"
    api_key_ref: "env://ANTHROPIC_API_KEY"
    escalate_on_behavioral_mismatch: true
    escalate_on_context_poisoning: true
    escalate_on_consent_gap: true

  # Optional: Registry audit (see Registry Audit section)
  registry_audit:
    enabled: false
    adapters: ["skills.sh"]
    fail_on_registry_malicious: true
```

Apply with `--policy policy.yaml` on any command.

### Default Policy

When no policy file is provided, STSS uses this built-in default:

| Severity | Decision |
|----------|---------|
| CRITICAL | FAIL |
| HIGH | FAIL |
| MEDIUM | FAIL |
| LOW | PASS\_WITH\_WARNINGS |
| INFO | PASS\_WITH\_WARNINGS |
| _(no findings)_ | PASS |

---

## Enforcement Modes

| Mode | Behavior | Recommended For |
|------|----------|--------------------|
| `observe_only` | Scan and log findings; host application is unaffected | Initial rollout, auditing |
| `warn_unverified` | Print warnings for unverified skills; skill still loads | Gradual adoption |
| `enforce_verified` | Block any skill that fails verification or has no attestation | Production environments |

Configure enforcement mode in `.stss/config.yaml` or pass via environment to your skill loader.

---

## Threat Detection

STSS scans across nine threat categories:

| Category | Severity | Description |
|----------|----------|-------------|
| `filesystem` | HIGH | Sensitive path access: `.ssh`, `.env`, `/etc/passwd`, AWS credentials, SSH keys |
| `shell` | HIGH | Shell execution: `subprocess`, `exec()`, `eval()`, `child_process`, `execSync` |
| `network` | HIGH / CRITICAL | Outbound calls: `fetch`, `axios`, `requests`, `urllib` — escalated to CRITICAL if a hardcoded IP or non-localhost URL is present |
| `secrets` | HIGH | Environment variable reads and hex/base64 strings near keyword `key`, `secret`, `token`, `password` |
| `obfuscation` | HIGH | Base64-decode + exec chains, `fromCharCode` sequences, `unescape` + eval |
| `prompt_injection` | MEDIUM | Adversarial instructions in SKILL.md: "ignore previous instructions", "you are now operating as" |
| `context_poisoning` | MEDIUM | Mode-switching language in docs: "debug mode", "you have been granted", headings followed by shell commands |
| `consent_gap` | CRITICAL | Setup scripts (`post_install.sh`, `setup.sh`, etc.) that may run silently; outbound network calls in install hooks |
| `cross_file_chain` | (inherited) | Import chains that lead from an innocent entry point to a flagged file in Python, JS/TS, and shell scripts |

### `.stssignore`

Place a `.stssignore` file in your skill root to exclude files from scanning (gitignore syntax):

```
# .stssignore
tests/fixtures/
*.snap
vendor/
```

Default ignores: `.git/`, `node_modules/`, `.venv/`, `build/`, `dist/`, `__pycache__/`, `*.pyc`, `.DS_Store`

---

## LLM Audit

The LLM audit pass uses a large language model to evaluate threats that static analysis cannot reliably catch:

1. **Behavioral coherence** — does the skill's actual code match its declared purpose?
2. **Context poisoning** — does SKILL.md attempt to reframe the agent's operating context?
3. **Consent gaps** — are there install-time scripts that execute without explicit user approval?
4. **Cross-file attack chains** — do import chains lead from an innocent entry to malicious terminal code?

### Enabling LLM Audit

LLM audit is **opt-in** and requires an Anthropic API key:

```bash
export ANTHROPIC_API_KEY=sk-ant-...

stss scan ./my-skill --llm-audit --policy policy.yaml
```

In `policy.yaml`:

```yaml
stss_policy:
  llm_audit:
    enabled: true
    adapter: "claude"
    model: "claude-sonnet-4-20250514"
    api_key_ref: "env://ANTHROPIC_API_KEY"
    escalate_on_behavioral_mismatch: true
    escalate_on_context_poisoning: true
    escalate_on_consent_gap: true
```

### Cost Considerations

- The LLM pass sends skill file contents to the Anthropic API. Review your data handling obligations before enabling in production.
- The pass only activates when there are MEDIUM+ static findings **or** a `SKILL.md` is present.
- If the API call fails, STSS logs a warning and continues — the LLM pass never blocks a scan from completing.
- To verify that a skill was LLM-audited, use `stss verify --require-llm-audit`.

---

## Registry Audit

STSS integrates with the [skills.sh](https://skills.sh) registry to cross-reference community security reports (including Gen, Socket, and Snyk findings).

### Enabling Registry Audit

```bash
stss scan ./my-skill --registry-audit --policy policy.yaml
```

In `policy.yaml`:

```yaml
stss_policy:
  registry_audit:
    enabled: true
    adapters: ["skills.sh"]
    fail_on_registry_malicious: true
```

### Behavior

- Results are cached to `.stss/registry-cache/<namespace>-<name>.json` with a **24-hour TTL**
- If skills.sh marks a skill as `"malicious"`, STSS emits a synthetic `CRITICAL` finding
- If the network request fails, STSS logs a warning and continues — the registry pass never blocks a scan

---

## CI Integration

### GitHub Actions

Run `stss-hub init-hooks` to generate `.github/workflows/stss-verify.yml`, or add it manually:

```yaml
name: STSS Skill Verification
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
        env:
          STSS_PUBLIC_KEY: ${{ secrets.STSS_PUBLIC_KEY }}
        run: |
          CHANGED=$(git diff --name-only origin/${{ github.base_ref }}...HEAD \
            | grep -E '(SKILL\.md|skills/)' | xargs -I{} dirname {} | sort -u)
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
```

Store your public key in GitHub Secrets as `STSS_PUBLIC_KEY`.

### Git Pre-commit Hook

```bash
stss-hub init-hooks
```

This installs `.git/hooks/pre-commit` to automatically scan any staged skill directories before each commit. Commits are blocked if CRITICAL or HIGH findings are detected.

---

## Architecture

```
stss/
├── packages/
│   ├── core/                   # @stss/core — all security logic
│   │   └── src/
│   │       ├── ingestion.ts    # Recursive file walker with ignore rules
│   │       ├── merkle.ts       # SHA-256 Merkle tree (deterministic, PROMOTE strategy)
│   │       ├── scanner/
│   │       │   ├── types.ts            # Finding, ScannerAdapter interfaces
│   │       │   ├── regex-adapter.ts    # Default zero-dependency scanner
│   │       │   └── semgrep-adapter.ts  # semgrep wrapper with regex fallback
│   │       ├── hook-detector.ts        # Consent gap / install script detection
│   │       ├── chain-tracer.ts         # Cross-file import chain analysis
│   │       ├── policy.ts               # YAML policy loader + decision engine
│   │       ├── llm-auditor.ts          # Claude API behavioral analysis
│   │       ├── registry-adapters/
│   │       │   └── skillssh.ts         # skills.sh registry integration
│   │       ├── signer.ts               # Ed25519 attestation signing
│   │       ├── verifier.ts             # Signature + Merkle verification
│   │       └── pipeline.ts             # Full scan orchestration
│   ├── cli/                    # stss CLI binary
│   └── hub/                    # stss-hub workspace management CLI
├── package.json                # pnpm workspace root
├── pnpm-workspace.yaml
└── tsconfig.base.json
```

### Key Design Invariants

- All file I/O is async — no blocking `fs.readFileSync` in the scan path
- Merkle tree construction is 100% deterministic — same files always produce the same root
- Private keys are held in memory only for the duration of a single signing operation
- LLM and registry passes are non-blocking — failures produce warnings, not errors
- All external data (policy YAML, attestation JSON, registry responses) is validated with Zod before use
- Exit codes are consistent: `0` = success, `1` = security failure, `2` = tool error

### Attestation Payload

Signed attestations are self-contained JSON files:

```json
{
  "attestation": {
    "schemaVersion": "stss/1.0",
    "skill": { "namespace": "myorg", "name": "my-skill", "version": "1.0.0" },
    "scan": {
      "timestamp": "2026-03-09T14:00:00Z",
      "toolVersion": "1.0.0",
      "summary": { "critical": 0, "high": 0, "medium": 0, "low": 1, "info": 0 },
      "llmAuditPerformed": false,
      "registryAuditPerformed": false,
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
