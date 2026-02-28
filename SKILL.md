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

**Installing into the current tool's skills directory:** Use `--tool <name>` for known tools (`claude`, `cursor`, `windsurf`, `openclaw`). If you are running inside a different tool not listed here, use `--skills-dir <path>` with the tool's skills directory path instead — do not attempt to write files directly outside the tool's workspace.

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
python3 <skill-dir>/scripts/skillsafe.py save <path> [--version <semver>] [--description <d>] [--category <c>] [--tags <t>] [--changelog <msg>]
```
Scans the skill, computes a SHA-256 tree hash, and uploads to the registry. Skills are saved privately by default — only you can access them. No email verification required. Use `--changelog` to describe what changed in this version (shown in `info`). If `--version` is omitted, the CLI auto-increments the patch version from the latest (e.g., 1.0.2 → 1.0.3). If the skill's content is unchanged from the latest version, the save is skipped.

### Share — Create a share link for a saved skill
```bash
python3 <skill-dir>/scripts/skillsafe.py share @<namespace>/<skill-name> --version <ver> [--public] [--expires <1d|7d|30d|never>]
```
Creates a share link for a specific version. By default the link is private (only people with the link can access it). Use `--public` to make the skill discoverable via search. Requires email verification and a scan report on the version.

### Install — Install a skill from the registry
```bash
python3 <skill-dir>/scripts/skillsafe.py install @<namespace>/<skill-name> [--version <ver>] [--skills-dir <dir>] [--tool <name>]
```
Downloads the archive, verifies the tree hash matches, scans the downloaded files, submits a verification report, and installs. Use `--tool <name>` to install into a known tool's skills directory (`--tool claude`, `--tool cursor`, `--tool windsurf`, `--tool openclaw`). Use `--skills-dir <path>` for any other tool — pass the parent directory and the skill will be placed in a subdirectory named after the skill.

After install, a `.skillsafe.json` metadata file is written into the skill directory with the namespace, name, version, and tree hash. The installer also injects `improvable: true` and `registry` fields into the skill's SKILL.md frontmatter if not already present.

### Search — Search the registry
```bash
python3 <skill-dir>/scripts/skillsafe.py search "<query>" [--category <c>] [--sort popular|recent|verified|trending|hot]
```
Searches publicly shared skills only.

### Yank — Block downloads of a broken version
```bash
python3 <skill-dir>/scripts/skillsafe.py yank @<namespace>/<skill-name> --version <ver> [--reason <msg>]
```
Marks a version as yanked — it remains visible in `info` but cannot be downloaded. Use when a published version has a bug or security issue. Other versions are unaffected.

### Info — Get skill details
```bash
python3 <skill-dir>/scripts/skillsafe.py info @<namespace>/<skill-name>
```

### List — Show all installed skills
```bash
python3 <skill-dir>/scripts/skillsafe.py list
```
Shows skills from multiple locations: known tool directories (`~/.claude/skills/`, `~/.cursor/skills/`, `~/.windsurf/skills/`), SkillSafe registry skills (`~/.skillsafe/skills/`), and project-level skills. Use `--skills-dir <path>` to include additional directories.

## Improving & Iterating on Skills

Use this workflow when the user wants to edit an existing skill, publish a new version, or roll back to an older one.

### Step 1 — Install locally for editing

```bash
python3 <skill-dir>/scripts/skillsafe.py install @<namespace>/<name> --tool claude
```

After install, a `.skillsafe.json` metadata file is written into the skill directory with the namespace, name, version, and tree hash.

### Step 2 — Edit the skill

Read and modify `SKILL.md` (instructions) and any supporting files in the installed directory. Base improvements on user feedback about what worked or didn't. If unsure where the skill was installed, run `list` to find the path.

### Step 3 — Save the improved version

```bash
python3 <skill-dir>/scripts/skillsafe.py save <path-to-skill-dir> --changelog "[type] what changed"
```

No `--version` needed — the CLI auto-increments the patch version. If the content is unchanged, the save is skipped. Use changelog prefixes to categorize: `[example]`, `[patch]`, `[instruction]`, `[bugfix]`.

### Step 4 — Optionally share

```bash
python3 <skill-dir>/scripts/skillsafe.py share @<namespace>/<name> --version <new-version> [--public]
```

### Step 5 — Revert to a previous version if needed

```bash
python3 <skill-dir>/scripts/skillsafe.py install @<namespace>/<name> --version <old-version> --tool claude
```

## Self-Improving Skills

Skills can self-improve based on usage feedback. When a skill has `improvable: true` in its frontmatter, the main agent orchestrates an observe-improve-save loop after each execution.

### Frontmatter Fields

Add these optional fields to opt into self-improvement:

```yaml
---
name: my-skill
description: What this skill does
context: fork
improvable: true
registry: "@namespace/skill-name"
allowed-tools: Bash, Read, Write
---
```

- **`improvable: true`** — Signals that this skill opts into the self-improvement loop. When present, the main agent observes execution and user feedback, then edits and saves a new version when warranted.
- **`registry: "@ns/name"`** — The skill's registry coordinates. Used by the auto-save flow so the agent doesn't need to derive namespace and name separately. Read from `.skillsafe.json` if not in frontmatter.
- **`context: fork`** — Skills should run in a sub-agent (separate context) so the main agent can observe the full execution and user reaction without being inside the skill's execution flow.

### How It Works

1. **Sub-agent execution**: The main agent reads the skill's SKILL.md and spawns a sub-agent with `context: fork`. The sub-agent executes the skill instructions and returns the result.

2. **Feedback detection**: After the sub-agent completes, the main agent observes the user's next 1-3 messages for feedback signals:
   - **Positive**: user says "thanks", "good job", "perfect", or proceeds without corrections
   - **Negative**: user says "wrong", "no", "try again", manually corrects output, or asks for a different approach
   - **Error recovery**: the sub-agent hit a tool error (e.g., command not found) and used a workaround

3. **Improvement**: When feedback warrants it, the main agent edits the skill files directly:
   - **Add examples** — append successful (input, output) pairs to a `## Examples` section in SKILL.md
   - **Patch scripts** — fix commands that failed (e.g., replace `jq` with `python3 -m json.tool` when jq is missing)
   - **Fix instructions** — clarify SKILL.md text based on user corrections

4. **Save new version**: The main agent saves the improved skill:
   ```bash
   python3 <skillsafe-cli>/scripts/skillsafe.py save <skill-dir> --changelog "[patch] replaced jq with python3 fallback"
   ```
   The version auto-increments. The changelog describes what was improved and why.

5. **Confirm to user**: The main agent tells the user what was improved and the new version number.

### Changelog Convention

Use a bracketed prefix to categorize improvement type:
- `[example]` — Added a concrete example of correct behavior
- `[patch]` — Fixed a script or command (tool fallback, error handling, platform compatibility)
- `[instruction]` — Clarified or corrected SKILL.md instructions
- `[bugfix]` — Fixed a bug in the skill's logic

### Skill Template Sections

Skills that opt into self-improvement should include these optional sections:

#### Feedback Signals

Define what counts as positive/negative feedback specific to this skill:

```markdown
## Feedback Signals

### Positive
- User accepts the generated output without edits
- Tests pass after the skill's changes

### Negative
- User reverts the skill's changes
- Tests fail after the skill's changes
- User says the output format is wrong
```

#### Improvement Guide

Define what types of improvements the main agent should make:

```markdown
## Improvement Guide

### When a command fails
Add platform detection and fallback commands. Prefer widely-available tools.

### When output format is wrong
Add a concrete example to the Examples section showing the correct format.

### When instructions are misunderstood
Add DO and DO NOT lists to clarify edge cases.
```

### Rate Limiting

To avoid rapid-fire saves:
- Only improve after explicit user feedback, not on every sub-agent error
- Maximum one improvement save per skill per conversation
- If the same skill fails after an improvement, ask the user before making another edit

## How to Use

When the user asks to scan, save, share, install, list, or search for skills:

1. Determine which command to run based on the user's request
2. Run the appropriate command using `Bash`
3. Show the user the output

Common user requests and which command to use:
- "sign in" / "log in" / "authenticate" -> `auth`
- "list my skills" / "what skills do I have" -> `list`
- "scan this for security issues" -> `scan <path>`
- "save my skill" / "upload my skill" -> `save <path>` (auto-versions) or `save <path> --version <ver>`
- "share my skill" / "publish my skill" -> `share @ns/name --version <ver>` (add `--public` for search visibility)
- "install a skill" -> `install @ns/name --tool <name>` (or `--skills-dir <path>`)
- "improve this skill" / "make this skill better" / "update the skill instructions" -> edit + save workflow (see "Improving & Iterating on Skills")
- "push a new version" / "publish my changes" -> `save <path> --changelog "what changed"`
- "revert to previous version" / "go back to the old skill" / "undo skill changes" -> `install @ns/name --version <old> --tool claude`
- "yank this version" / "block this version" / "this version is broken" -> `yank @ns/name --version <ver> --reason "..."`

## Configuration

Credentials are stored in `~/.skillsafe/config.json`. Installed skills live in `~/.skillsafe/skills/` by default, or in any tool's skills directory when using `--tool <name>` (claude, cursor, windsurf) or `--skills-dir <path>`.

## Security Model

SkillSafe uses a **save-first** model: skills are saved privately by default, then shared via links when ready. Shared skills require **dual-side verification**: the sharer scans before sharing, the consumer independently re-scans after download, and the server compares both reports. Tree hashes (SHA-256 of the archive) detect tampering. Verdicts are:
- **verified** — scans match, safe to install
- **divergent** — scans disagree, user decides
- **critical** — tree hash mismatch, possible tampering, abort
