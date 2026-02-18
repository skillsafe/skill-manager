---
name: skillsafe
description: Scan, save, share, install, and verify skills from the SkillSafe secured skill registry. Use when the user wants to manage AI coding skills with security scanning and dual-side verification.
allowed-tools: Bash, Read, Write
---

# SkillSafe — Secured Skill Registry Client

You have access to `skillsafe.py`, a Python client for the SkillSafe skill registry. It scans skills for security issues (dangerous functions, hardcoded secrets, prompt injection), saves them to the registry, shares them via links, installs them with cryptographic verification, and searches the registry.

## Setup

Before running any command, ensure the CLI script exists. If `scripts/skillsafe.py` does not exist in this skill's directory, download it:

```bash
mkdir -p <skill-dir>/scripts && curl -fsSL https://skillsafe.ai/scripts/skillsafe.py -o <skill-dir>/scripts/skillsafe.py
```

This is only needed for first-time installation from URL. If installed via `skillsafe install`, the script is already included.

## Available Commands

Run all commands using `python3` and the script at `scripts/skillsafe.py` inside this skill's directory.

### Auth — Sign in via browser
```bash
python3 <skill-dir>/scripts/skillsafe.py auth
```
First checks if a saved API key in `~/.skillsafe/config.json` is still valid. If valid, prints account info and exits. If the key is missing, expired, or revoked, opens your browser to sign in (via Google or API key) and saves a new API key. The CLI waits for browser authorization automatically.

### Scan — Security scan a skill directory
```bash
python3 <skill-dir>/scripts/skillsafe.py scan <path>
```
Runs 4 scan passes:
1. **Python AST analysis** — detects `eval()`, `exec()`, `os.system()`, `subprocess.*`, etc.
2. **JS/TS regex analysis** — detects `eval()`, `new Function()`, `child_process`, etc.
3. **Secret detection** — AWS keys, GitHub tokens, private keys, generic API keys
4. **Prompt injection** — detects manipulation patterns in .md files

### Save — Save a skill to the registry (private by default)
```bash
python3 <skill-dir>/scripts/skillsafe.py save <path> --version <semver> [--description <d>] [--category <c>] [--tags <t>]
```
Scans the skill, creates a tar.gz archive, computes a SHA-256 tree hash, and uploads to the registry. Skills are saved privately by default — only you can access them. No email verification required.

### Share — Create a share link for a saved skill
```bash
python3 <skill-dir>/scripts/skillsafe.py share @<namespace>/<skill-name> --version <ver> [--public] [--expires <1d|7d|30d|never>]
```
Creates a share link for a specific version. By default the link is private (only people with the link can access it). Use `--public` to make the skill discoverable via search. Requires email verification and a scan report on the version.

### Install — Install a skill from the registry
```bash
python3 <skill-dir>/scripts/skillsafe.py install @<namespace>/<skill-name> [--version <ver>] [--skills-dir <dir>] [--tool <name>]
```
Downloads the archive, verifies the tree hash matches, scans the downloaded files, submits a verification report, and installs. Use `--tool <name>` to install into a known tool's skills directory (`--tool claude`, `--tool cursor`, `--tool windsurf`). Use `--skills-dir <path>` for a custom path.

### Search — Search the registry
```bash
python3 <skill-dir>/scripts/skillsafe.py search "<query>" [--category <c>] [--sort popular|recent|verified|trending|hot]
```
Searches publicly shared skills only.

### Info — Get skill details
```bash
python3 <skill-dir>/scripts/skillsafe.py info @<namespace>/<skill-name>
```

### List — Show all installed skills
```bash
python3 <skill-dir>/scripts/skillsafe.py list
```
Shows skills from multiple locations: known tool directories (`~/.claude/skills/`, `~/.cursor/skills/`, `~/.windsurf/skills/`), SkillSafe registry skills (`~/.skillsafe/skills/`), and project-level skills. Use `--skills-dir <path>` to include additional directories.

### Backup — Back up a skill to the vault
```bash
python3 <skill-dir>/scripts/skillsafe.py backup <path> [--name <vault-name>]
```
Creates a tar.gz archive of a skill directory and uploads it to the SkillSafe vault for safe cloud backup. Useful for backing up skills before modifying them.

### Restore — Restore a skill from the vault
```bash
python3 <skill-dir>/scripts/skillsafe.py restore <name> [--skills-dir <dir>] [--tool <name>] [-o <dir>]
```
Downloads a skill from the vault and extracts it. Use `--tool <name>` to restore into a known tool's skills directory (`--tool claude`, `--tool cursor`, `--tool windsurf`). Use `--skills-dir <path>` for a custom path.

## How to Use

When the user asks to scan, save, share, install, list, backup, or search for skills:

1. Determine which command to run based on the user's request
2. Run the appropriate command using `Bash`
3. Show the user the output

Common user requests and which command to use:
- "sign in" / "log in" / "authenticate" -> `auth`
- "list my skills" / "what skills do I have" -> `list`
- "scan this for security issues" -> `scan <path>`
- "save my skill" / "upload my skill" -> `save <path> --version <ver>`
- "share my skill" / "publish my skill" -> `share @ns/name --version <ver>` (add `--public` for search visibility)
- "install a skill" -> `install @ns/name --tool <name>` (or `--skills-dir <path>`)
- "back up my skill" -> `backup <path>`
- "restore my skill" -> `restore <name> --tool <name>` (or `--skills-dir <path>`)

## Configuration

Credentials are stored in `~/.skillsafe/config.json`. Installed skills live in `~/.skillsafe/skills/` by default, or in any tool's skills directory when using `--tool <name>` (claude, cursor, windsurf) or `--skills-dir <path>`.

## Security Model

SkillSafe uses a **save-first** model: skills are saved privately by default, then shared via links when ready. Shared skills require **dual-side verification**: the sharer scans before sharing, the consumer independently re-scans after download, and the server compares both reports. Tree hashes (SHA-256 of the archive) detect tampering. Verdicts are:
- **verified** — scans match, safe to install
- **divergent** — scans disagree, user decides
- **critical** — tree hash mismatch, possible tampering, abort
