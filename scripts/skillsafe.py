#!/usr/bin/env python3
"""
SkillSafe — secured skill registry client for AI coding tools.

A single-file Python client (stdlib only) that can scan, save, share, install,
and verify skills from the SkillSafe registry. Designed to run inside
Claude Code, Cursor, Windsurf, and similar AI-assisted development tools.

Usage:
    python skillsafe.py auth                              # browser login
    python skillsafe.py scan <path>
    python skillsafe.py save <path> --version <ver> [--description <d>] [--category <c>] [--tags <t>]
    python skillsafe.py share <@namespace/skill> --version <ver> [--public] [--expires <1d|7d|30d|never>]
    python skillsafe.py install <@namespace/skill> [--version <ver>] [--skills-dir <dir>] [--tool <name>]
    python skillsafe.py install <share-link> [--skills-dir <dir>] [--tool <name>]
    python skillsafe.py search <query> [--category <c>] [--sort <s>]
    python skillsafe.py info <@namespace/skill>
    python skillsafe.py list
    python skillsafe.py whoami
    python skillsafe.py backup <path> [--name <name>] [--version <ver>]
    python skillsafe.py restore <@namespace/name> [--skills-dir <dir>] [--tool <name>] [-o <dir>]

Also importable as a module:
    from skillsafe import Scanner, SkillSafeClient
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import io
import json
import os
import re
import secrets
import sys
import tarfile
import tempfile
import textwrap
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Python version guard
# ---------------------------------------------------------------------------

if sys.version_info < (3, 12):
    print("Error: Python 3.12+ is required (for tarfile security filters).", file=sys.stderr)
    sys.exit(1)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VERSION = "0.1.0"
RULESET_VERSION = "2025.01.01"
SCANNER_TOOL = "skillsafe-scanner-py"
DEFAULT_API_BASE = "https://api.skillsafe.ai"

CONFIG_DIR = Path.home() / ".skillsafe"
CONFIG_FILE = CONFIG_DIR / "config.json"
SKILLS_DIR = CONFIG_DIR / "skills"
CACHE_DIR = CONFIG_DIR / "cache"

TOOL_SKILLS_DIRS: Dict[str, Path] = {
    "claude": Path.home() / ".claude" / "skills",
    "cursor": Path.home() / ".cursor" / "skills",
    "windsurf": Path.home() / ".windsurf" / "skills",
}
TOOL_DISPLAY_NAMES: Dict[str, str] = {
    "claude": "Claude Code",
    "cursor": "Cursor",
    "windsurf": "Windsurf",
}

MAX_ARCHIVE_SIZE = 10 * 1024 * 1024  # 10 MB

# Skill names reserved by SkillSafe (managed/updated by skillsafe.ai)
RESERVED_SKILL_NAMES = {"skillsafe"}

# File extensions we scan as text
TEXT_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs",
    ".md", ".txt", ".json", ".yaml", ".yml", ".toml",
    ".sh", ".bash", ".zsh", ".fish",
    ".html", ".css", ".xml", ".csv",
    ".env", ".cfg", ".ini", ".conf",
}

# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class SkillSafeError(Exception):
    """Error returned by the SkillSafe API."""

    def __init__(self, code: str, message: str, status: int = 0):
        self.code = code
        self.message = message
        self.status = status
        super().__init__(f"[{code}] {message}")


class ScanError(Exception):
    """Error during local security scanning."""
    pass


# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------


def load_config() -> Dict[str, Any]:
    """Load ~/.skillsafe/config.json or return empty dict."""
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE, "r") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                print("Warning: Config file corrupted, using defaults", file=sys.stderr)
                return {}
    return {}


def save_config(cfg: Dict[str, Any]) -> None:
    """Write config to ~/.skillsafe/config.json, creating dirs as needed."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_FILE, "w") as f:
        json.dump(cfg, f, indent=2)
        f.write("\n")
    # Restrict permissions so other users cannot read the API key
    os.chmod(CONFIG_FILE, 0o600)


def require_config() -> Dict[str, Any]:
    """Load config or exit with an error if not configured."""
    cfg = load_config()
    if not cfg.get("api_key"):
        print("Error: Not authenticated. Run 'skillsafe auth <username>' first.", file=sys.stderr)
        sys.exit(1)
    return cfg


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------

# ANSI colours (disabled if not a TTY)
_USE_COLOR = hasattr(sys.stdout, "isatty") and sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def _c(code: str, text: str) -> str:
    if _USE_COLOR:
        return f"\033[{code}m{text}\033[0m"
    return text


def red(t: str) -> str:
    return _c("31", t)


def yellow(t: str) -> str:
    return _c("33", t)


def green(t: str) -> str:
    return _c("32", t)


def cyan(t: str) -> str:
    return _c("36", t)


def bold(t: str) -> str:
    return _c("1", t)


def dim(t: str) -> str:
    return _c("2", t)


SEVERITY_COLOR = {
    "critical": red,
    "high": red,
    "medium": yellow,
    "low": cyan,
    "info": dim,
}


def format_severity(sev: str) -> str:
    fn = SEVERITY_COLOR.get(sev, str)
    return fn(sev.upper().ljust(8))


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------


class Scanner:
    """
    Security scanner for skill directories.

    Performs four scan passes:
      1. Python static analysis (AST-based)
      2. JavaScript / TypeScript static analysis (regex-based)
      3. Secret detection (regex on all text files)
      4. Prompt injection detection (regex on .md files)
    """

    # -- Dangerous Python function patterns (AST-based) ---------------------

    # (func_type, match_spec, rule_id, severity, message)
    # func_type: "name" for bare Name nodes, "attr" for Attribute nodes
    _PY_DANGEROUS_CALLS: List[Tuple[str, Any, str, str, str]] = [
        ("name", "eval", "py_eval", "high", "eval() can execute arbitrary code"),
        ("name", "exec", "py_exec", "high", "exec() can execute arbitrary code"),
        ("name", "compile", "py_compile", "medium", "compile() can compile arbitrary code"),
        ("name", "__import__", "py_dunder_import", "high", "__import__() enables dynamic imports"),
        ("attr", ("importlib", "import_module"), "py_importlib", "high", "importlib.import_module() enables dynamic imports"),
        ("attr", ("os", "system"), "py_os_system", "high", "os.system() executes shell commands"),
        ("attr", ("os", "popen"), "py_os_popen", "high", "os.popen() executes shell commands"),
        ("attr", ("subprocess", "call"), "py_subprocess_call", "high", "subprocess.call() executes external commands"),
        ("attr", ("subprocess", "run"), "py_subprocess_run", "high", "subprocess.run() executes external commands"),
        ("attr", ("subprocess", "Popen"), "py_subprocess_popen", "high", "subprocess.Popen() executes external commands"),
        ("attr", ("subprocess", "check_output"), "py_subprocess_check_output", "high", "subprocess.check_output() executes external commands"),
        ("attr", ("subprocess", "check_call"), "py_subprocess_check_call", "high", "subprocess.check_call() executes external commands"),
        ("attr", ("subprocess", "getoutput"), "py_subprocess_getoutput", "high", "subprocess.getoutput() executes external commands"),
        ("attr", ("subprocess", "getstatusoutput"), "py_subprocess_getstatusoutput", "high", "subprocess.getstatusoutput() executes external commands"),
    ]

    # -- JS / TS dangerous patterns (regex) ---------------------------------

    _JS_PATTERNS: List[Tuple[str, str, str, str]] = [
        (r"\beval\s*\(", "js_eval", "high", "eval() can execute arbitrary code"),
        (r"\bnew\s+Function\s*\(", "js_function_constructor", "high", "Function() constructor can execute arbitrary code"),
        (r"""require\s*\(\s*['"]child_process['"]\s*\)""", "js_child_process", "high", "child_process module enables shell command execution"),
        (r"\b(?:execSync|execFileSync)\s*\(", "js_exec_sync", "high", "execSync() executes shell commands synchronously"),
        (r"\b(?:spawnSync)\s*\(", "js_spawn_sync", "high", "spawnSync() executes external commands"),
        (r"""import\s+.*\bfrom\s+['"]child_process['"]""", "js_child_process_import", "high", "child_process ES module import enables shell command execution"),
        (r"""import\s+.*\bfrom\s+['"]fs['"]""", "js_fs_import", "medium", "fs ES module import enables filesystem access"),
    ]

    # Compiled once
    _JS_COMPILED: Optional[List[Tuple[re.Pattern, str, str, str]]] = None

    # -- Secret detection patterns ------------------------------------------

    _SECRET_PATTERNS: List[Tuple[str, str, str, str]] = [
        (r"AKIA[0-9A-Z]{16}", "aws_access_key", "critical", "AWS Access Key ID detected"),
        (r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----", "private_key", "critical", "Private key detected"),
        (r"gh[pousr]_[A-Za-z0-9_]{36,}", "github_token", "critical", "GitHub token detected"),
        (r"xox[bpars]-[0-9a-zA-Z\-]{10,}", "slack_token", "high", "Slack token detected"),
        (
            r"""['"]?[a-zA-Z_]*(?:api[_\-]?key|secret[_\-]?key|access[_\-]?token|auth[_\-]?token|password)['"]?\s*[:=]\s*['"][a-zA-Z0-9+/=_\-]{16,}['"]""",
            "generic_secret",
            "high",
            "Possible hardcoded secret or API key",
        ),
    ]

    _SECRET_COMPILED: Optional[List[Tuple[re.Pattern, str, str, str]]] = None

    # -- Prompt injection patterns ------------------------------------------

    _INJECTION_PATTERNS: List[Tuple[str, str, str, str]] = [
        (r"ignore\s+(?:all\s+)?(?:(?:previous|prior|above)\s+)?instructions", "prompt_ignore_instructions", "high", "Prompt injection: ignore instructions"),
        (r"you\s+are\s+now", "prompt_role_hijack", "high", "Prompt injection: role hijacking"),
        (r"system\s+prompt", "prompt_system_prompt", "medium", "Prompt injection: system prompt reference"),
        (r"disregard\s+(?:all\s+)?(?:(?:previous|prior)\s+)?instructions", "prompt_disregard", "high", "Prompt injection: disregard instructions"),
        (r"new\s+instructions\s*:", "prompt_new_instructions", "high", "Prompt injection: new instructions block"),
        (r"override\s+(?:(?:previous|prior)\s+)?instructions", "prompt_override", "high", "Prompt injection: override instructions"),
        (r"forget\s+(?:everything|all|previous)", "prompt_forget", "high", "Prompt injection: forget instructions"),
        (r"do\s+not\s+follow\s+(?:the\s+)?(?:(?:previous|prior|above)\s+)?instructions", "prompt_do_not_follow", "high", "Prompt injection: do not follow instructions"),
    ]

    _INJECTION_COMPILED: Optional[List[Tuple[re.Pattern, str, str, str]]] = None

    # -- Initialisation -----------------------------------------------------

    def __init__(self) -> None:
        # Lazy-compile regexes on first use
        if Scanner._JS_COMPILED is None:
            Scanner._JS_COMPILED = [
                (re.compile(p), rid, sev, msg) for p, rid, sev, msg in Scanner._JS_PATTERNS
            ]
        if Scanner._SECRET_COMPILED is None:
            Scanner._SECRET_COMPILED = [
                (re.compile(p), rid, sev, msg) for p, rid, sev, msg in Scanner._SECRET_PATTERNS
            ]
        if Scanner._INJECTION_COMPILED is None:
            Scanner._INJECTION_COMPILED = [
                (re.compile(p, re.IGNORECASE), rid, sev, msg) for p, rid, sev, msg in Scanner._INJECTION_PATTERNS
            ]

    # -- Public API ---------------------------------------------------------

    def scan(self, path: str | Path, tree_hash: Optional[str] = None) -> Dict[str, Any]:
        """
        Scan a skill directory and return a scan report dict.

        Args:
            path: Path to the skill directory.
            tree_hash: Optional pre-computed tree hash to embed in the report.

        Returns:
            Scan report dict matching the SkillSafe schema.
        """
        path = Path(path).resolve()
        if not path.is_dir():
            raise ScanError(f"Not a directory: {path}")

        all_findings: List[Dict[str, Any]] = []

        # Collect files
        files = self._collect_files(path)

        # Pass 1: Python AST analysis
        py_findings = []
        for fpath in files:
            if fpath.suffix == ".py":
                py_findings.extend(self._scan_python_ast(fpath, path))
        all_findings.extend(py_findings)

        # Pass 2: JS/TS regex analysis
        js_findings = []
        for fpath in files:
            if fpath.suffix in (".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"):
                js_findings.extend(self._scan_js_regex(fpath, path))
        all_findings.extend(js_findings)

        # Pass 3: Secret detection (all text files)
        secret_findings = []
        for fpath in files:
            if fpath.suffix in TEXT_EXTENSIONS:
                secret_findings.extend(self._scan_secrets(fpath, path))
        all_findings.extend(secret_findings)

        # Pass 4: Prompt injection (text-like files)
        _injection_extensions = {".md", ".txt", ".yaml", ".yml", ".rst"}
        injection_findings = []
        for fpath in files:
            if fpath.suffix.lower() in _injection_extensions:
                injection_findings.extend(self._scan_prompt_injection(fpath, path))
        all_findings.extend(injection_findings)

        # Build summary (deduplicated list for server comparison)
        findings_summary = [
            {"rule_id": f["rule_id"], "severity": f["severity"], "file": f["file"], "line": f["line"], "message": f["message"]}
            for f in all_findings
        ]

        is_clean = len(all_findings) == 0
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        report: Dict[str, Any] = {
            "schema_version": "1.0",
            "scanner": {
                "tool": SCANNER_TOOL,
                "version": VERSION,
                "ruleset_version": RULESET_VERSION,
            },
            "clean": is_clean,
            "findings_count": len(all_findings),
            "findings_summary": findings_summary,
            "timestamp": now,
        }
        if tree_hash:
            report["skill_tree_hash"] = tree_hash

        return report

    # -- File collection ----------------------------------------------------

    def _collect_files(self, root: Path) -> List[Path]:
        """Recursively collect files, skipping hidden dirs and common junk."""
        skip_dirs = {".git", ".svn", "node_modules", "__pycache__", ".venv", "venv", ".skillsafe"}
        result: List[Path] = []
        for dirpath, dirnames, filenames in os.walk(root):
            # Prune hidden / ignored directories in-place
            dirnames[:] = [d for d in dirnames if d not in skip_dirs and not d.startswith(".")]
            for fname in filenames:
                if fname.startswith("."):
                    continue
                result.append(Path(dirpath) / fname)
        return sorted(result)

    # -- Pass 1: Python AST -------------------------------------------------

    def _scan_python_ast(self, fpath: Path, root: Path) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        rel = str(fpath.relative_to(root))

        try:
            source = fpath.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source, filename=rel)
        except SyntaxError:
            # Can't parse — skip (could be Python 2, template, etc.)
            return findings
        except Exception:
            return findings

        source_lines = source.splitlines()

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func

            for func_type, match_spec, rule_id, severity, message in self._PY_DANGEROUS_CALLS:
                matched = False

                if func_type == "name" and isinstance(func, ast.Name):
                    if func.id == match_spec:
                        matched = True
                elif func_type == "attr" and isinstance(func, ast.Attribute):
                    mod_name, attr_name = match_spec
                    if func.attr == attr_name and isinstance(func.value, ast.Name) and func.value.id == mod_name:
                        matched = True

                if matched:
                    lineno = getattr(node, "lineno", 0)
                    context = source_lines[lineno - 1].strip() if 0 < lineno <= len(source_lines) else ""
                    findings.append({
                        "rule_id": rule_id,
                        "severity": severity,
                        "file": rel,
                        "line": lineno,
                        "message": message,
                        "context": context,
                    })
                    break  # One match per call node

        return findings

    # -- Pass 2: JS / TS regex ----------------------------------------------

    def _scan_js_regex(self, fpath: Path, root: Path) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        rel = str(fpath.relative_to(root))
        assert self._JS_COMPILED is not None

        try:
            lines = fpath.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception:
            return findings

        for lineno_0, line in enumerate(lines):
            stripped = line.lstrip()
            # Skip single-line comments
            if stripped.startswith("//"):
                continue
            # Skip pure JSDoc/block comment markers
            if stripped == "*" or stripped == "*/" or stripped.startswith("/*"):
                continue
            # For JSDoc `* text` lines, strip the leading `* ` and scan the remainder
            if stripped.startswith("* ") or stripped.startswith("*\t"):
                stripped = stripped[2:]
                # Fall through to scan the remainder

            for pattern, rule_id, severity, message in self._JS_COMPILED:
                if pattern.search(line):
                    findings.append({
                        "rule_id": rule_id,
                        "severity": severity,
                        "file": rel,
                        "line": lineno_0 + 1,
                        "message": message,
                        "context": stripped[:120],
                    })

        return findings

    # -- Pass 3: Secret detection -------------------------------------------

    def _scan_secrets(self, fpath: Path, root: Path) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        rel = str(fpath.relative_to(root))
        assert self._SECRET_COMPILED is not None

        try:
            lines = fpath.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception:
            return findings

        for lineno_0, line in enumerate(lines):
            for pattern, rule_id, severity, message in self._SECRET_COMPILED:
                if pattern.search(line):
                    findings.append({
                        "rule_id": rule_id,
                        "severity": severity,
                        "file": rel,
                        "line": lineno_0 + 1,
                        "message": message,
                        "context": _redact_line(line.strip(), 120),
                    })

        return findings

    # -- Pass 4: Prompt injection -------------------------------------------

    def _scan_prompt_injection(self, fpath: Path, root: Path) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        rel = str(fpath.relative_to(root))
        assert self._INJECTION_COMPILED is not None

        try:
            lines = fpath.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception:
            return findings

        for lineno_0, line in enumerate(lines):
            for pattern, rule_id, severity, message in self._INJECTION_COMPILED:
                if pattern.search(line):
                    findings.append({
                        "rule_id": rule_id,
                        "severity": severity,
                        "file": rel,
                        "line": lineno_0 + 1,
                        "message": message,
                        "context": line.strip()[:120],
                    })

        return findings


def _redact_line(line: str, max_len: int, is_secret: bool = True) -> str:
    """Truncate and redact lines that may contain secrets.

    For lines flagged as containing a detected secret, the middle portion
    is replaced with ``****`` so that the raw secret value is never
    included in the scan report uploaded to the server.  Non-secret lines
    are simply truncated.
    """
    if is_secret:
        # Always redact: show first 20 chars + **** + last 4 chars
        if len(line) > 24:
            return line[:20] + "****" + line[-4:]
        # Very short line — still mask the middle
        return line[:4] + "****"
    # Non-secret lines: just truncate
    if len(line) > max_len:
        return line[:max_len] + "..."
    return line


# ---------------------------------------------------------------------------
# Tree hash computation
# ---------------------------------------------------------------------------


def compute_tree_hash(data: bytes) -> str:
    """
    Compute the tree hash of an archive blob.

    Matches the server implementation in api/src/services/skills.ts:
        const archiveHash = await sha256Bytes(input.archiveData);
        const treeHash = `sha256:${archiveHash}`;
    """
    return "sha256:" + hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Archive creation
# ---------------------------------------------------------------------------


def create_archive(path: Path) -> bytes:
    """
    Create a tar.gz archive of a directory, returning the raw bytes.

    Produces deterministic output by sorting entries and zeroing timestamps.
    """
    path = path.resolve()
    buf = io.BytesIO()

    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        entries: List[Path] = []
        skip_dirs = {".git", ".svn", "node_modules", "__pycache__", ".venv", "venv", ".skillsafe"}
        for dirpath, dirnames, filenames in os.walk(path):
            dirnames[:] = sorted(d for d in dirnames if d not in skip_dirs and not d.startswith("."))
            for fname in sorted(filenames):
                if fname.startswith("."):
                    continue
                entries.append(Path(dirpath) / fname)

        MAX_FILE_COUNT = 5000
        if len(entries) > MAX_FILE_COUNT:
            raise SkillSafeError("too_many_files", f"Too many files ({len(entries)}). Maximum is {MAX_FILE_COUNT}.")

        for fpath in entries:
            # Guard against symlinks that escape the skill directory tree
            if fpath.is_symlink():
                resolved = fpath.resolve()
                if not str(resolved).startswith(str(path) + os.sep) and resolved != path:
                    print(f"Warning: Skipping symlink that escapes skill directory: {fpath} -> {resolved}", file=sys.stderr)
                    continue
            arcname = str(fpath.relative_to(path))
            info = tar.gettarinfo(name=str(fpath), arcname=arcname)
            # Zero out metadata for deterministic archives
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            info.mtime = 0
            with open(fpath, "rb") as f:
                tar.addfile(info, f)

    return buf.getvalue()


# ---------------------------------------------------------------------------
# HTTP API Client
# ---------------------------------------------------------------------------


class SkillSafeClient:
    """
    HTTP client for the SkillSafe API.

    Uses only urllib (stdlib) — no external dependencies.
    """

    def __init__(self, api_base: Optional[str] = None, api_key: Optional[str] = None):
        self.api_base = (api_base or DEFAULT_API_BASE).rstrip("/")
        # Reject insecure HTTP connections (allow localhost/127.0.0.1 for dev)
        if not self.api_base.startswith("https://"):
            parsed = urllib.parse.urlparse(self.api_base)
            if parsed.hostname not in ("localhost", "127.0.0.1"):
                raise SkillSafeError(
                    "insecure_connection",
                    f"Refusing to connect over insecure HTTP to {self.api_base}. Use HTTPS.",
                )
        self.api_key = api_key

    # -- Low-level request --------------------------------------------------

    def _request(
        self,
        method: str,
        path: str,
        *,
        body: Optional[bytes] = None,
        headers: Optional[Dict[str, str]] = None,
        content_type: Optional[str] = None,
        auth: bool = True,
        raw_response: bool = False,
    ) -> Any:
        """
        Make an HTTP request and return the parsed JSON response.

        If raw_response=True, return (response_bytes, response_headers) instead.
        """
        url = self.api_base + path
        hdrs: Dict[str, str] = headers or {}

        if "User-Agent" not in hdrs:
            hdrs["User-Agent"] = f"skillsafe-cli/{VERSION}"
        if auth and self.api_key:
            hdrs["Authorization"] = f"Bearer {self.api_key}"
        if content_type:
            hdrs["Content-Type"] = content_type

        req = urllib.request.Request(url, data=body, headers=hdrs, method=method)

        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = resp.read()
                if raw_response:
                    return data, resp.headers
                try:
                    return json.loads(data)
                except json.JSONDecodeError:
                    raise SkillSafeError("invalid_response", f"Server returned invalid JSON: {data[:200]!r}", 0)
        except urllib.error.HTTPError as e:
            error_body = e.read().decode("utf-8", errors="replace")
            try:
                err = json.loads(error_body)
                err_info = err.get("error", {})
                raise SkillSafeError(
                    code=err_info.get("code", "unknown"),
                    message=err_info.get("message", error_body),
                    status=e.code,
                )
            except SkillSafeError:
                raise
            except Exception:
                raise SkillSafeError("http_error", f"HTTP {e.code}: {error_body}", e.code)
        except urllib.error.URLError as e:
            raise SkillSafeError("connection_error", f"Cannot connect to {self.api_base}: {e.reason}", 0)

    # -- Multipart form-data builder ----------------------------------------

    @staticmethod
    def _build_multipart(fields: List[Tuple[str, str, bytes, str]]) -> Tuple[bytes, str]:
        """
        Build a multipart/form-data body.

        Each field is (name, filename_or_empty, data, content_type).
        Returns (body_bytes, content_type_header).
        """
        boundary = f"----SkillSafeBoundary{secrets.token_hex(16)}"
        parts: List[bytes] = []

        for name, filename, data, ct in fields:
            # Sanitize name field to prevent CRLF injection
            safe_name = name.replace("\r", "").replace("\n", "")
            header_lines = [f"--{boundary}"]
            if filename:
                # Sanitize filename: escape backslashes/quotes, strip CRLF to prevent header injection
                safe_filename = filename.replace("\\", "\\\\").replace('"', '\\"')
                safe_filename = safe_filename.replace("\r", "").replace("\n", "")
                header_lines.append(f'Content-Disposition: form-data; name="{safe_name}"; filename="{safe_filename}"')
            else:
                header_lines.append(f'Content-Disposition: form-data; name="{safe_name}"')
            header_lines.append(f"Content-Type: {ct}")
            header_lines.append("")
            header_bytes = "\r\n".join(header_lines).encode("utf-8")
            parts.append(header_bytes + b"\r\n" + data)

        body = b"\r\n".join(parts) + f"\r\n--{boundary}--\r\n".encode("utf-8")
        content_type = f"multipart/form-data; boundary={boundary}"
        return body, content_type

    # -- API methods --------------------------------------------------------

    def save(
        self,
        namespace: str,
        name: str,
        archive_bytes: bytes,
        metadata: Dict[str, Any],
        scan_report_json: Optional[str] = None,
    ) -> Dict[str, Any]:
        """POST /v1/skills/@{ns}/{name} — save a skill version (multipart)."""
        fields = [
            ("archive", f"{name}.tar.gz", archive_bytes, "application/gzip"),
            ("metadata", "", json.dumps(metadata).encode("utf-8"), "application/json"),
        ]
        if scan_report_json:
            fields.insert(1, ("scan_report", "", scan_report_json.encode("utf-8"), "application/json"))
        body, ct = self._build_multipart(fields)
        resp = self._request("POST", f"/v1/skills/@{namespace}/{name}", body=body, content_type=ct)
        return resp.get("data", resp)

    def share(
        self,
        namespace: str,
        name: str,
        version: str,
        visibility: str = "private",
        expires_in: Optional[str] = None,
    ) -> Dict[str, Any]:
        """POST /v1/skills/@{ns}/{name}/versions/{ver}/share — create a share link."""
        payload: Dict[str, Any] = {"visibility": visibility}
        if expires_in:
            payload["expires_in"] = expires_in
        body = json.dumps(payload).encode("utf-8")
        resp = self._request(
            "POST",
            f"/v1/skills/@{namespace}/{name}/versions/{version}/share",
            body=body,
            content_type="application/json",
        )
        return resp.get("data", resp)

    def download_via_share(self, share_id: str) -> Tuple[bytes, str, str]:
        """
        GET /v1/share/{share_id}/download — download archive via share link.

        Returns (archive_bytes, tree_hash, version).
        """
        data, headers = self._request(
            "GET", f"/v1/share/{share_id}/download", raw_response=True, auth=False
        )
        tree_hash = headers.get("X-SkillSafe-Tree-Hash", "")
        version = headers.get("X-SkillSafe-Version", "")
        return data, tree_hash, version

    def download(self, namespace: str, name: str, version: str) -> Tuple[bytes, str]:
        """
        GET /v1/skills/@{ns}/{name}/download/{version} — download an archive.

        Returns (archive_bytes, tree_hash_from_header).
        """
        data, headers = self._request(
            "GET", f"/v1/skills/@{namespace}/{name}/download/{version}", raw_response=True
        )
        tree_hash = headers.get("X-SkillSafe-Tree-Hash", "")
        return data, tree_hash

    def verify(
        self, namespace: str, name: str, version: str, scan_report: Dict[str, Any]
    ) -> Dict[str, Any]:
        """POST /v1/skills/@{ns}/{name}/versions/{version}/verify — submit verification."""
        body = json.dumps({"scan_report": scan_report}).encode("utf-8")
        resp = self._request(
            "POST",
            f"/v1/skills/@{namespace}/{name}/versions/{version}/verify",
            body=body,
            content_type="application/json",
        )
        return resp.get("data", resp)

    def search(
        self,
        query: Optional[str] = None,
        category: Optional[str] = None,
        sort: str = "popular",
        limit: int = 20,
    ) -> Dict[str, Any]:
        """GET /v1/skills/search — search the registry."""
        params: Dict[str, str] = {"sort": sort, "limit": str(limit)}
        if query:
            params["q"] = query
        if category:
            params["category"] = category
        qs = urllib.parse.urlencode(params)
        resp = self._request("GET", f"/v1/skills/search?{qs}", auth=False)
        return resp

    def get_metadata(self, namespace: str, name: str, auth: bool = False) -> Dict[str, Any]:
        """GET /v1/skills/@{ns}/{name} — skill metadata."""
        resp = self._request("GET", f"/v1/skills/@{namespace}/{name}", auth=auth)
        return resp.get("data", resp)

    def resolve_next_version(self, namespace: str, name: str) -> str:
        """Resolve the next patch version for a skill, or 0.1.0 if it doesn't exist."""
        try:
            meta = self.get_metadata(namespace, name, auth=True)
            latest = meta.get("latest_version")
            if not latest:
                return "0.1.0"
            # Parse major.minor.patch and increment patch
            m = re.match(r'^(\d+)\.(\d+)\.(\d+)', latest)
            if not m:
                return "0.1.0"
            major, minor, patch = int(m.group(1)), int(m.group(2)), int(m.group(3))
            return f"{major}.{minor}.{patch + 1}"
        except SkillSafeError:
            return "0.1.0"

    def get_versions(self, namespace: str, name: str, limit: int = 20) -> Dict[str, Any]:
        """GET /v1/skills/@{ns}/{name}/versions — version list."""
        resp = self._request("GET", f"/v1/skills/@{namespace}/{name}/versions?limit={limit}", auth=False)
        return resp

    def get_account(self) -> Dict[str, Any]:
        """GET /v1/account — retrieve own account details (requires auth)."""
        resp = self._request("GET", "/v1/account")
        return resp.get("data", resp)


# ---------------------------------------------------------------------------
# CLI Commands
# ---------------------------------------------------------------------------


def parse_skill_ref(ref: str) -> Tuple[str, str]:
    """
    Parse '@namespace/skill-name' into (namespace, name).

    Accepts with or without the leading '@'.
    Namespace and name must contain only alphanumeric characters (case-insensitive),
    hyphens, underscores, and dots.
    """
    ref = ref.lstrip("@")
    if "/" not in ref:
        raise SkillSafeError("invalid_reference", f"Invalid skill reference '{ref}'. Expected format: @namespace/skill-name")
    parts = ref.split("/", 1)
    namespace, name = parts[0], parts[1]
    if not namespace or not name:
        raise SkillSafeError("invalid_reference", "Invalid skill reference: namespace and name must not be empty")
    # Validate characters to prevent path traversal and other injection
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9_-]{0,38}$', namespace):
        raise SkillSafeError("invalid_reference", f"Invalid namespace '{namespace}'. Use alphanumeric characters, hyphens, and underscores (1-39 chars).")
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9._-]{0,100}$', name):
        raise SkillSafeError("invalid_reference", f"Invalid skill name '{name}'. Use alphanumeric characters, dots, hyphens, and underscores (1-101 chars).")
    return namespace, name


def _validate_skill_name(name: str) -> None:
    """Validate a skill name derived from a directory name or --name flag.

    Uses the same regex as parse_skill_ref to ensure consistency.
    Prints an error and exits if the name is invalid.
    """
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9._-]{0,100}$', name):
        print(f"Error: Invalid skill name '{name}'. Use alphanumeric characters, dots, hyphens, and underscores (1-101 chars, must start with alphanumeric).", file=sys.stderr)
        sys.exit(1)


def _validate_saved_key(api_base: str) -> bool:
    """
    Check if a saved API key exists and is still valid.

    Returns True if the saved key is valid (auth not needed), False otherwise.
    """
    cfg = load_config()
    api_key = cfg.get("api_key")
    if not api_key:
        return False

    saved_base = cfg.get("api_base", DEFAULT_API_BASE)
    if saved_base != api_base:
        return False  # different server, need fresh auth
    client = SkillSafeClient(api_base=api_base, api_key=api_key)

    try:
        account = client.get_account()
    except SkillSafeError:
        return False
    except Exception:
        return False

    # Key is valid — update config with latest account info in case it changed
    cfg["account_id"] = account.get("account_id", cfg.get("account_id", ""))
    cfg["username"] = account.get("username", cfg.get("username", ""))
    cfg["namespace"] = f"@{account.get('username', '')}" if account.get("username") else cfg.get("namespace", "")
    save_config(cfg)

    print(green("Already authenticated."))
    print(f"  Account:   {cfg['account_id']}")
    print(f"  Username:  {cfg['username']}")
    print(f"  Namespace: {cfg['namespace']}")
    print(f"  API key:   {dim(api_key[:10] + '...')}")
    print(f"  Config:    {CONFIG_FILE}")
    print(f"\n  To re-authenticate, delete {CONFIG_FILE} and run auth again.")
    return True


def cmd_whoami(args: argparse.Namespace) -> None:
    """Show current authentication status and account info."""
    cfg = load_config()
    api_key = cfg.get("api_key")

    if not api_key:
        print(red("Not authenticated."))
        print(f"\n  Run {bold('skillsafe auth')} to get started.")
        sys.exit(1)

    # Show local config info
    print(f"\n  {bold('Local config')}")
    print(f"  Username:    {cfg.get('username', dim('unknown'))}")
    print(f"  Namespace:   {cfg.get('namespace', dim('unknown'))}")
    print(f"  API key:     {dim(api_key[:10] + '...')}")
    print(f"  API base:    {cfg.get('api_base', DEFAULT_API_BASE)}")
    print(f"  Config file: {CONFIG_FILE}")

    # Verify against server
    api_base = cfg.get("api_base", DEFAULT_API_BASE)
    client = SkillSafeClient(api_base=api_base, api_key=api_key)

    try:
        account = client.get_account()
    except SkillSafeError as e:
        if e.status == 401:
            print(f"\n  {red('Session expired.')} Run {bold('skillsafe auth')} to sign in again.")
            sys.exit(1)
        print(f"\n  {yellow('Could not verify account:')} {e.message}")
        sys.exit(1)
    except (urllib.error.URLError, OSError) as e:
        print(f"\n  {yellow('Could not connect to API.')} {e}")
        print(f"  Local config appears valid. Use {bold('--api-base')} to change the server.")
        sys.exit(1)

    # Show verified account details
    print(f"\n  {bold('Account')} {green('(verified)')}")
    print(f"  Email:       {account.get('email') or dim('not set')}")

    email_verified = account.get("email_verified", False)
    if email_verified:
        print(f"  Verified:    {green('yes')}")
    else:
        print(f"  Verified:    {yellow('no')}")

    print(f"  Tier:        {account.get('tier', 'free')}")

    # Storage usage
    used = account.get("storage_used_bytes", 0)
    used_mb = used / (1024 * 1024)
    print(f"  Storage:     {used_mb:.1f} MB used")

    print(f"  Skills:      {account.get('shared_skill_count', 0)} shared")
    print(f"  Member since: {(account.get('created_at') or '-')[:10]}")
    print()


def cmd_auth(args: argparse.Namespace) -> None:
    """Authenticate via browser login."""
    api_base: str = getattr(args, "api_base", DEFAULT_API_BASE)

    # Check if a saved key is already valid
    if _validate_saved_key(api_base):
        return

    # Saved key missing or invalid — start browser-based login flow
    _auth_browser(api_base)


def _detect_tool() -> str:
    """Detect which AI coding tool is invoking the CLI based on script path.

    Works with any tool that follows the ``~/.<tool>/skills/`` convention,
    not just the ones listed in TOOL_SKILLS_DIRS.  For example a script
    installed at ``~/.copilot/skills/skillsafe/scripts/skillsafe.py``
    will return ``"copilot"``.
    """
    try:
        script_path = Path(__file__).resolve()
        home = Path.home().resolve()
        rel = script_path.relative_to(home)
        # Expected layout: .<tool>/skills/<skill>/...
        parts = rel.parts  # e.g. ('.cursor', 'skills', 'skillsafe', ...)
        if (
            len(parts) >= 3
            and parts[0].startswith(".")
            and parts[1] == "skills"
        ):
            return parts[0].lstrip(".")  # e.g. "cursor"
    except (ValueError, IndexError):
        pass
    return "cli"


def _auth_browser(api_base: str) -> None:
    """Authenticate via browser-based device authorization flow."""
    client = SkillSafeClient(api_base=api_base)

    # Detect the invoking tool for a richer API key label (e.g. "cursor")
    label = _detect_tool()

    # Step 1: Create a CLI auth session
    print("Starting browser login...\n")
    try:
        payload = json.dumps({"label": label}).encode()
        result = client._request(
            "POST", "/v1/auth/cli", auth=False,
            body=payload, content_type="application/json",
        )
        data = result.get("data", result)
        session_id: str = data["session_id"]
        login_url: str = data["login_url"]
    except SkillSafeError as e:
        print(f"Error: {e.message}", file=sys.stderr)
        sys.exit(1)
    except (KeyError, TypeError):
        print("Error: Unexpected response from server.", file=sys.stderr)
        sys.exit(1)

    # Step 2: Open browser
    print(f"  Opening browser to sign in...")
    print(f"  If the browser doesn't open, visit this URL:\n")
    print(f"    {bold(login_url)}\n")

    try:
        webbrowser.open(login_url)
    except Exception:
        pass  # URL is already printed as fallback

    # Step 3: Poll for approval
    print("  Waiting for browser authorization", end="", flush=True)

    poll_interval = 2  # seconds
    max_wait = 300  # 5 minutes
    elapsed = 0

    while elapsed < max_wait:
        time.sleep(poll_interval)
        elapsed += poll_interval

        try:
            resp = client._request("GET", f"/v1/auth/cli/{session_id}", auth=False)
            data = resp.get("data", resp)
            status = data.get("status")

            if status == "approved":
                print()  # newline after dots
                _save_auth_result(data, api_base)
                return

            # Still pending — print a dot
            print(".", end="", flush=True)

        except KeyboardInterrupt:
            print()
            print("\n  Authentication cancelled.", file=sys.stderr)
            sys.exit(1)
        except SkillSafeError as e:
            print()
            if e.status == 410:
                print(f"\n  {red('Session expired.')} Please try again.", file=sys.stderr)
            else:
                print(f"\n  Error: {e.message}", file=sys.stderr)
            sys.exit(1)
        except Exception:
            print(".", end="", flush=True)

    # Timeout
    print()
    print(f"\n  {red('Timed out')} waiting for browser authorization.", file=sys.stderr)
    print(f"  You can still sign in at: {login_url}", file=sys.stderr)
    sys.exit(1)


def _save_auth_result(data: Dict[str, Any], api_base: str) -> None:
    """Save the credentials from a successful browser auth to config."""
    api_key = data.get("api_key")
    if not api_key or not isinstance(api_key, str) or not api_key.strip():
        print("Error: Server returned invalid or empty API key. Authentication failed.", file=sys.stderr)
        sys.exit(1)
    cfg = {
        "account_id": data.get("account_id", ""),
        "username": data.get("username", ""),
        "namespace": data.get("namespace", ""),
        "api_key": api_key,
        "api_base": api_base,
    }
    save_config(cfg)

    SKILLS_DIR.mkdir(parents=True, exist_ok=True)
    CACHE_DIR.mkdir(parents=True, exist_ok=True)

    print(green("\n  Authenticated successfully."))
    print(f"  Account:   {cfg['account_id']}")
    print(f"  Username:  {cfg['username']}")
    print(f"  Namespace: {cfg['namespace']}")
    print(f"  API key:   {dim(cfg['api_key'][:10] + '...')}")
    print(f"  Config:    {CONFIG_FILE}")


def cmd_scan(args: argparse.Namespace) -> Optional[Dict[str, Any]]:
    """Scan a skill directory for security issues."""
    path = Path(args.path).resolve()
    if not path.is_dir():
        print(f"Error: {path} is not a directory.", file=sys.stderr)
        sys.exit(1)

    print(f"Scanning {bold(str(path))}...\n")
    scanner = Scanner()

    try:
        report = scanner.scan(path)
    except ScanError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    _print_scan_results(report)

    # Optionally write report to file
    if getattr(args, "output", None):
        out_path = Path(args.output)
        with open(out_path, "w") as f:
            json.dump(report, f, indent=2)
            f.write("\n")
        print(f"\nReport written to {out_path}")

    return report


def cmd_save(args: argparse.Namespace) -> None:
    """Save a skill to the registry (private by default)."""
    cfg = require_config()
    path = Path(args.path).resolve()
    version: str = args.version
    description: Optional[str] = getattr(args, "description", None)
    category: Optional[str] = getattr(args, "category", None)
    tags_raw: Optional[str] = getattr(args, "tags", None)

    if not path.is_dir():
        print(f"Error: {path} is not a directory.", file=sys.stderr)
        sys.exit(1)

    # Validate semver format before doing any expensive work
    semver_re = r'^\d+\.\d+\.\d+(-[a-zA-Z0-9.]+)?(\+[a-zA-Z0-9.]+)?$'
    if not re.match(semver_re, version):
        print(f"Error: Invalid version '{version}'. Expected semantic version (e.g. 1.0.0, 2.1.0-beta.1).", file=sys.stderr)
        sys.exit(1)

    name = path.name
    namespace = cfg["username"]

    _validate_skill_name(name)

    if name in RESERVED_SKILL_NAMES:
        print(f"Error: '{name}' is a reserved name and cannot be used as a skill name.", file=sys.stderr)
        sys.exit(1)

    print(f"Saving {bold(f'@{namespace}/{name}')} v{version}...\n")

    # Step 1: Create archive
    print("  Creating archive...")
    archive_bytes = create_archive(path)
    size_kb = len(archive_bytes) / 1024
    if len(archive_bytes) > MAX_ARCHIVE_SIZE:
        print(f"Error: Archive is {size_kb:.0f} KB, exceeds 10 MB limit.", file=sys.stderr)
        sys.exit(1)
    print(f"  Archive size: {size_kb:.1f} KB")

    # Step 2: Compute tree hash
    tree_hash = compute_tree_hash(archive_bytes)
    print(f"  Tree hash:    {dim(tree_hash[:30])}...")

    # Step 3: Scan (optional but recommended)
    print("  Scanning for security issues...")
    scanner = Scanner()
    report = scanner.scan(path, tree_hash=tree_hash)
    _print_scan_results(report, indent=2)

    # Step 4: Save to registry
    print("\n  Uploading to registry...")
    metadata: Dict[str, Any] = {"version": version}
    if description:
        metadata["description"] = description
    if category:
        metadata["category"] = category
    if tags_raw:
        metadata["tags"] = [t.strip() for t in tags_raw.split(",")]

    client = SkillSafeClient(api_base=cfg.get("api_base", DEFAULT_API_BASE), api_key=cfg["api_key"])

    try:
        result = client.save(namespace, name, archive_bytes, metadata, scan_report_json=json.dumps(report))
    except SkillSafeError as e:
        print(f"\n  Error: {e.message}", file=sys.stderr)
        sys.exit(1)

    print(green(f"\n  Saved @{namespace}/{name}@{version}"))
    print(f"  Skill ID:   {result.get('skill_id')}")
    print(f"  Version ID: {result.get('version_id')}")
    print(f"  Tree hash:  {result.get('tree_hash')}")
    print(f"\n  To share this skill, run:")
    print(f"    skillsafe share @{namespace}/{name} --version {version}")


def cmd_share(args: argparse.Namespace) -> None:
    """Create a share link for a saved skill."""
    cfg = require_config()
    namespace, name = parse_skill_ref(args.skill)
    version: str = args.version
    public: bool = getattr(args, "public", False)
    expires: Optional[str] = getattr(args, "expires", None)

    visibility = "public" if public else "private"

    print(f"Sharing {bold(f'@{namespace}/{name}')} v{version} ({visibility})...\n")

    client = SkillSafeClient(api_base=cfg.get("api_base", DEFAULT_API_BASE), api_key=cfg["api_key"])

    try:
        result = client.share(namespace, name, version, visibility=visibility, expires_in=expires)
    except SkillSafeError as e:
        print(f"  Error: {e.message}", file=sys.stderr)
        sys.exit(1)

    api_base = cfg.get("api_base", DEFAULT_API_BASE)
    share_url = f"{api_base}{result.get('share_url', '')}"

    print(green(f"  Share link created."))
    print(f"  Share ID:    {result.get('share_id')}")
    print(f"  Visibility:  {result.get('visibility')}")
    if result.get("expires_at"):
        print(f"  Expires:     {result.get('expires_at')}")
    print(f"  Share URL:   {bold(share_url)}")
    if visibility == "public":
        print(f"\n  This skill is now discoverable via search.")
    else:
        print(f"\n  Share this URL with others to give them access.")


def cmd_install(args: argparse.Namespace) -> None:
    """Install a skill from the registry."""
    cfg = require_config()

    # Detect share link references (shr_ prefix or URL containing /share/shr_)
    skill_ref = args.skill
    share_id: Optional[str] = None
    if skill_ref.startswith("shr_"):
        share_id = skill_ref
    elif "/share/shr_" in skill_ref:
        share_id = skill_ref.split("/share/")[-1].split("?")[0]

    client = SkillSafeClient(api_base=cfg.get("api_base", DEFAULT_API_BASE), api_key=cfg["api_key"])

    if share_id:
        # Share link install path
        print(f"Installing via share link {bold(share_id)}...\n")

        print("  Downloading archive via share link...")
        try:
            archive_bytes, server_tree_hash, version = client.download_via_share(share_id)
        except SkillSafeError as e:
            print(f"  Error: {e.message}", file=sys.stderr)
            sys.exit(1)
        print(f"  Downloaded {len(archive_bytes) / 1024:.1f} KB")

        if not version:
            version = "unknown"

        # Try to extract namespace/name from archive's SKILL.md
        namespace = "shared"
        name = share_id
        try:
            with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as tar:
                for member in tar.getmembers():
                    if member.name == "SKILL.md" or member.name.endswith("/SKILL.md"):
                        f = tar.extractfile(member)
                        if f:
                            text = f.read().decode("utf-8", errors="replace")
                            for line in text.splitlines():
                                if line.startswith("name:"):
                                    name = line[len("name:"):].strip()
                                    break
                        break
        except Exception:
            pass  # Use defaults if we can't parse SKILL.md

    else:
        namespace, name = parse_skill_ref(skill_ref)
        version = getattr(args, "version", None)

        # Step 1: Resolve version
        if not version:
            print(f"Resolving latest version of {bold(f'@{namespace}/{name}')}...")
            try:
                meta = client.get_metadata(namespace, name, auth=True)
                version = meta.get("latest_version")
                if not version:
                    print("Error: No published versions found.", file=sys.stderr)
                    sys.exit(1)
            except SkillSafeError as e:
                print(f"Error: {e.message}", file=sys.stderr)
                sys.exit(1)

        # Validate version format to prevent path traversal via malicious server response
        semver_re = r'^\d+\.\d+\.\d+(-[a-zA-Z0-9.]+)?(\+[a-zA-Z0-9.]+)?$'
        if not re.match(semver_re, version):
            print(f"Error: Invalid version '{version}'. Expected semantic version (e.g. 1.0.0).", file=sys.stderr)
            sys.exit(1)

        print(f"Installing {bold(f'@{namespace}/{name}')} v{version}...\n")

        # Step 2: Download
        print("  Downloading archive...")
        try:
            archive_bytes, server_tree_hash = client.download(namespace, name, version)
        except SkillSafeError as e:
            print(f"  Error: {e.message}", file=sys.stderr)
            sys.exit(1)
        print(f"  Downloaded {len(archive_bytes) / 1024:.1f} KB")

    # Step 3: Verify tree hash
    local_tree_hash = compute_tree_hash(archive_bytes)
    if not server_tree_hash:
        print("Warning: Server did not provide a tree hash. Cannot verify archive integrity.", file=sys.stderr)
        print("Aborting installation for safety.", file=sys.stderr)
        sys.exit(1)
    if local_tree_hash != server_tree_hash:
        print(red("\n  CRITICAL: Tree hash mismatch — possible tampering!"))
        print(f"    Server:  {server_tree_hash}")
        print(f"    Local:   {local_tree_hash}")
        print("  Aborting installation.")
        sys.exit(1)
    print(f"  Tree hash verified: {dim(local_tree_hash[:30])}...")

    # Step 4: Extract to temp dir and scan
    with tempfile.TemporaryDirectory() as tmpdir:
        tmppath = Path(tmpdir)
        print("  Extracting archive...")
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as tar:
            tar.extractall(path=tmppath, filter="data")

        print("  Scanning downloaded skill...")
        scanner = Scanner()
        consumer_report = scanner.scan(tmppath, tree_hash=local_tree_hash)
        _print_scan_results(consumer_report, indent=2)

    # Step 5: Submit verification
    print("\n  Submitting verification report...")
    try:
        verdict_result = client.verify(namespace, name, version, consumer_report)
        verdict = verdict_result.get("verdict", "unknown")
        details = verdict_result.get("details", {})
    except SkillSafeError as e:
        if e.status == 403:
            # Expected for self-verify scenarios
            print(f"  Verification skipped: {e.message}")
            verdict = "skipped"
        else:
            print(f"  Warning: Verification failed due to error: {e.message}", file=sys.stderr)
            print("  Continuing without verification.", file=sys.stderr)
            verdict = "error"
        details = {}

    # Step 6: Display verdict and prompt
    if verdict == "verified":
        print(green("  Verified: publisher and consumer scans match."))
    elif verdict == "divergent":
        print(yellow("  WARNING: Scan reports diverge."))
        for key, val in details.items():
            print(f"    {key}: {val}")
        if sys.stdin.isatty():
            try:
                answer = input("  Install anyway? [y/N] ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                answer = "n"
        else:
            answer = "n"
            print("  Non-interactive mode: skipping divergent skill.")
        if answer != "y":
            print("  Installation cancelled.")
            return
    elif verdict == "critical":
        print(red("  CRITICAL: Tree hash mismatch detected by server!"))
        for key, val in details.items():
            print(f"    {key}: {val}")
        print("  Aborting installation.")
        sys.exit(1)
    elif verdict in ("skipped", "error"):
        pass  # Already printed reason above
    else:
        print(f"  Verdict: {verdict}")

    # Step 7: Install to skills directory
    skills_dir = _resolve_skills_dir(args)

    if skills_dir:
        # Install directly into an agent's skills directory
        install_dir = skills_dir / name
        install_dir.mkdir(parents=True, exist_ok=True)

        print(f"\n  Installing to {install_dir}...")
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as tar:
            tar.extractall(path=install_dir, filter="data")

        print(green(f"\n  Installed @{namespace}/{name}@{version}"))
        print(f"  Location: {install_dir}")
    else:
        # Install to ~/.skillsafe/skills/@ns/name/version/
        install_dir = SKILLS_DIR / f"@{namespace}" / name / version
        install_dir.mkdir(parents=True, exist_ok=True)

        print(f"\n  Installing to {install_dir}...")
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as tar:
            tar.extractall(path=install_dir, filter="data")

        # Update 'current' symlink
        current_link = install_dir.parent / "current"
        if current_link.is_symlink() or current_link.exists():
            current_link.unlink()
        if not re.match(r'^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][a-zA-Z0-9.]+)?$', version):
            print(red(f"  Invalid version format: {version}"))
            return
        current_link.symlink_to(version)

        print(green(f"\n  Installed @{namespace}/{name}@{version}"))
        print(f"  Location: {install_dir}")

    # Update lockfile if in a project directory
    _update_lockfile(namespace, name, version, local_tree_hash)


def cmd_search(args: argparse.Namespace) -> None:
    """Search the skill registry."""
    query: Optional[str] = getattr(args, "query", None)
    category: Optional[str] = getattr(args, "category", None)
    sort: str = getattr(args, "sort", "popular")
    limit: int = getattr(args, "limit", 20)

    cfg = load_config()
    client = SkillSafeClient(api_base=cfg.get("api_base", DEFAULT_API_BASE))

    try:
        resp = client.search(query=query, category=category, sort=sort, limit=limit)
    except SkillSafeError as e:
        print(f"Error: {e.message}", file=sys.stderr)
        sys.exit(1)
    except (urllib.error.URLError, OSError) as e:
        print(f"Error: Could not connect to the API. {e}", file=sys.stderr)
        sys.exit(1)

    skills = resp.get("data", [])
    if not skills:
        print("No skills found.")
        return

    print(f"Found {len(skills)} skill(s):\n")

    # Table header
    print(f"  {'SKILL':<35} {'VERSION':<10} {'STARS':<7} {'INSTALLS':<10} DESCRIPTION")
    print(f"  {'─' * 35} {'─' * 10} {'─' * 7} {'─' * 10} {'─' * 30}")

    for s in skills:
        ns = s.get("namespace", "")
        nm = s.get("name_display", s.get("name", ""))
        ref = f"{ns}/{nm}"
        ver = s.get("latest_version", "-")
        stars = s.get("star_count", 0)
        installs = s.get("install_count", 0)
        desc = (s.get("description") or "")[:40]
        print(f"  {ref:<35} {ver:<10} {stars:<7} {installs:<10} {desc}")


def cmd_info(args: argparse.Namespace) -> None:
    """Show detailed information about a skill."""
    namespace, name = parse_skill_ref(args.skill)
    cfg = load_config()
    client = SkillSafeClient(api_base=cfg.get("api_base", DEFAULT_API_BASE))

    try:
        meta = client.get_metadata(namespace, name)
    except SkillSafeError as e:
        print(f"Error: {e.message}", file=sys.stderr)
        sys.exit(1)
    except (urllib.error.URLError, OSError) as e:
        print(f"Error: Could not connect to the API. {e}", file=sys.stderr)
        sys.exit(1)

    print(f"\n  {bold(meta.get('namespace', '') + '/' + meta.get('name_display', meta.get('name', '')))}")
    print()
    if meta.get("description"):
        print(f"  {meta['description']}")
        print()
    print(f"  Latest version:    {meta.get('latest_version', '-')}")
    print(f"  Category:          {meta.get('category', '-')}")
    print(f"  Tags:              {meta.get('tags', '-')}")
    print(f"  Installs:          {meta.get('install_count', 0)}")
    print(f"  Stars:             {meta.get('star_count', 0)}")
    print(f"  Verifications:     {meta.get('verification_count', 0)}")
    print(f"  Status:            {meta.get('status', '-')}")
    print(f"  Created:           {meta.get('created_at', '-')}")

    # Fetch versions
    try:
        ver_resp = client.get_versions(namespace, name, limit=10)
        versions = ver_resp.get("data", [])
        if versions:
            print(f"\n  Recent versions:")
            for v in versions:
                ver = v.get("version", "?")
                ts = (v.get("saved_at") or v.get("published_at") or "")[:10]
                yanked = " (yanked)" if v.get("yanked") else ""
                log = v.get("changelog") or ""
                log_short = f" — {log[:50]}" if log else ""
                print(f"    {ver:<12} {ts}{yanked}{log_short}")
    except SkillSafeError:
        pass  # Version list is optional

    print()


def _list_skills_in_dir(directory: Path) -> List[Tuple[str, str]]:
    """List skills in a flat skills directory (each subdirectory is a skill)."""
    results: List[Tuple[str, str]] = []
    if not directory.is_dir():
        return results
    for skill_dir in sorted(directory.iterdir()):
        if not skill_dir.is_dir():
            continue
        skill_md = skill_dir / "SKILL.md"
        desc = ""
        if skill_md.exists():
            try:
                text = skill_md.read_text(encoding="utf-8", errors="replace")
                for line in text.splitlines():
                    if line.startswith("description:"):
                        desc = line[len("description:"):].strip()[:60]
                        break
            except Exception:
                pass
        results.append((skill_dir.name, desc))
    return results


def cmd_list(args: argparse.Namespace) -> None:
    """List locally installed skills."""

    found_any = False

    # 1. Well-known agent skills directories
    for tool_key, agent_dir in TOOL_SKILLS_DIRS.items():
        label = TOOL_DISPLAY_NAMES.get(tool_key, tool_key)
        skills = _list_skills_in_dir(agent_dir)
        if skills:
            found_any = True
            print(f"{bold(f'{label} skills')} ({agent_dir}):\n")
            print(f"  {'SKILL':<30} DESCRIPTION")
            print(f"  {'─' * 30} {'─' * 50}")
            for name, desc in skills:
                print(f"  {name:<30} {desc}")
            print()

    # 2. Custom --skills-dir paths
    extra_dirs = getattr(args, "skills_dir", None) or []
    for dir_str in extra_dirs:
        extra_path = Path(dir_str).expanduser().resolve()
        skills = _list_skills_in_dir(extra_path)
        if skills:
            found_any = True
            print(f"{bold('Skills')} ({extra_path}):\n")
            print(f"  {'SKILL':<30} DESCRIPTION")
            print(f"  {'─' * 30} {'─' * 50}")
            for name, desc in skills:
                print(f"  {name:<30} {desc}")
            print()

    # 3. SkillSafe registry skills (~/.skillsafe/skills/)
    if SKILLS_DIR.is_dir():
        registry_skills: List[Tuple[str, str, str]] = []
        for ns_dir in sorted(SKILLS_DIR.iterdir()):
            if not ns_dir.is_dir():
                continue
            ns = ns_dir.name
            for skill_dir in sorted(ns_dir.iterdir()):
                if not skill_dir.is_dir():
                    continue
                current = skill_dir / "current"
                version = "?"
                if current.is_symlink():
                    version = current.resolve().name
                elif current.exists():
                    version = current.name
                else:
                    versions = [d.name for d in skill_dir.iterdir() if d.is_dir() and d.name != "current"]
                    version = sorted(versions)[-1] if versions else "?"
                registry_skills.append((f"{ns}/{skill_dir.name}", version, str(skill_dir)))

        if registry_skills:
            found_any = True
            print(f"{bold('SkillSafe registry skills')} ({SKILLS_DIR}):\n")
            print(f"  {'SKILL':<35} {'VERSION':<12} PATH")
            print(f"  {'─' * 35} {'─' * 12} {'─' * 40}")
            for ref, ver, path in registry_skills:
                print(f"  {ref:<35} {ver:<12} {path}")
            print()

    # 4. Project-level skills (.<tool>/skills/ in cwd)
    for tool_key in TOOL_SKILLS_DIRS:
        project_skills_dir = Path.cwd() / f".{tool_key}" / "skills"
        if project_skills_dir.is_dir():
            proj_skills = _list_skills_in_dir(project_skills_dir)
            if proj_skills:
                found_any = True
                label = TOOL_DISPLAY_NAMES.get(tool_key, tool_key)
                print(f"{bold(f'Project skills ({label})')} ({project_skills_dir}):\n")
                print(f"  {'SKILL':<30} DESCRIPTION")
                print(f"  {'─' * 30} {'─' * 50}")
                for name, desc in proj_skills:
                    print(f"  {name:<30} {desc}")
                print()

    if not found_any:
        print("No skills installed.")
        print()
        for tool_key, agent_dir in TOOL_SKILLS_DIRS.items():
            label = TOOL_DISPLAY_NAMES.get(tool_key, tool_key)
            print(f"  {label + ' skills dir:':<25} {agent_dir}")
        print(f"  {'SkillSafe skills dir:':<25} {SKILLS_DIR}")
        print(f"  {'Project skills dirs:':<25} ./<tool>/skills/")


def cmd_backup(args: argparse.Namespace) -> None:
    """Back up a local skill to the SkillSafe registry (private, auto-versioned)."""
    cfg = require_config()
    skill_path = Path(args.path).resolve()

    if not skill_path.is_dir():
        print(f"Error: {skill_path} is not a directory.", file=sys.stderr)
        sys.exit(1)

    name = args.name if hasattr(args, "name") and args.name else skill_path.name
    namespace = cfg["username"]

    _validate_skill_name(name)

    if name in RESERVED_SKILL_NAMES:
        print(f"Error: '{name}' is a reserved name and cannot be used as a skill name.", file=sys.stderr)
        sys.exit(1)

    client = SkillSafeClient(api_base=cfg.get("api_base", DEFAULT_API_BASE), api_key=cfg["api_key"])

    # Step 1: Resolve version
    version: Optional[str] = getattr(args, "version", None)
    if not version:
        print(f"Resolving next version of {bold(f'@{namespace}/{name}')}...")
        version = client.resolve_next_version(namespace, name)
    print(f"Backing up {bold(f'@{namespace}/{name}')} v{version}...\n")

    # Step 2: Create archive
    print("  Creating archive...")
    archive_bytes = create_archive(skill_path)
    size_kb = len(archive_bytes) / 1024

    if len(archive_bytes) > MAX_ARCHIVE_SIZE:
        print(f"Error: Archive is {size_kb:.0f} KB, exceeds 10 MB limit.", file=sys.stderr)
        sys.exit(1)
    print(f"  Archive size: {size_kb:.1f} KB")

    # Step 3: Compute tree hash
    tree_hash = compute_tree_hash(archive_bytes)
    print(f"  Tree hash:    {dim(tree_hash[:30])}...")

    # Step 4: Scan
    print("  Scanning for security issues...")
    scanner = Scanner()
    report = scanner.scan(skill_path, tree_hash=tree_hash)
    _print_scan_results(report, indent=2)

    # Step 5: Save to registry
    print("\n  Uploading to registry...")
    metadata: Dict[str, Any] = {"version": version}

    try:
        result = client.save(namespace, name, archive_bytes, metadata, scan_report_json=json.dumps(report))
    except SkillSafeError as e:
        # Handle version collision: re-resolve and retry once
        if e.status == 409 or e.status == 422:
            print(f"  Version {version} conflict, re-resolving...")
            version = client.resolve_next_version(namespace, name)
            metadata["version"] = version
            try:
                result = client.save(namespace, name, archive_bytes, metadata, scan_report_json=json.dumps(report))
            except SkillSafeError as e2:
                print(f"\n  Error: {e2.message}", file=sys.stderr)
                sys.exit(1)
        else:
            print(f"\n  Error: {e.message}", file=sys.stderr)
            sys.exit(1)
    except (urllib.error.URLError, OSError) as e:
        print(f"\n  Error: Could not connect to the API. {e}", file=sys.stderr)
        sys.exit(1)

    print(green(f"\n  Backed up @{namespace}/{name}@{version}"))
    print(f"  Skill ID:   {result.get('skill_id')}")
    print(f"  Version ID: {result.get('version_id')}")
    print(f"  Tree hash:  {result.get('tree_hash')}")
    print(f"  Restore with: skillsafe restore @{namespace}/{name}")


def cmd_restore(args: argparse.Namespace) -> None:
    """Restore a skill from the registry."""
    cfg = require_config()
    namespace = cfg["username"]

    # Parse skill name
    ref = args.name
    if "/" in ref:
        ref = ref.lstrip("@")
        parts = ref.split("/", 1)
        namespace = parts[0]
        skill_name = parts[1]
    else:
        skill_name = ref

    # Sanitize name to prevent path traversal
    if ".." in skill_name or "/" in skill_name or "\\" in skill_name or skill_name in (".", ""):
        print("Error: Invalid name (must not contain path separators or '..')", file=sys.stderr)
        sys.exit(1)

    # Determine target directory
    skills_dir = _resolve_skills_dir(args)
    if skills_dir:
        target_dir = skills_dir / skill_name
    elif getattr(args, "output", None):
        target_dir = Path(args.output).resolve()
    else:
        target_dir = Path.cwd() / skill_name

    print(f"Restoring {bold(f'@{namespace}/{skill_name}')} to {target_dir}...\n")

    client = SkillSafeClient(api_base=cfg.get("api_base", DEFAULT_API_BASE), api_key=cfg["api_key"])

    # Download from registry
    try:
        meta = client.get_metadata(namespace, skill_name, auth=True)
        version = meta.get("latest_version")
        if not version:
            print("Error: No versions found.", file=sys.stderr)
            sys.exit(1)

        print(f"  Downloading v{version} from registry...")
        archive_bytes, server_tree_hash = client.download(namespace, skill_name, version)
    except SkillSafeError as e:
        print(f"  Error: {e.message}", file=sys.stderr)
        sys.exit(1)
    except (urllib.error.URLError, OSError) as e:
        print(f"  Error: Could not connect to the API. {e}", file=sys.stderr)
        sys.exit(1)

    # Verify tree hash
    local_tree_hash = compute_tree_hash(archive_bytes)
    if not server_tree_hash:
        print("Warning: Server did not provide a tree hash. Cannot verify archive integrity.", file=sys.stderr)
        print("Aborting restore for safety.", file=sys.stderr)
        sys.exit(1)
    if local_tree_hash != server_tree_hash:
        print(red("\n  CRITICAL: Tree hash mismatch — possible tampering!"))
        print(f"    Server:  {server_tree_hash}")
        print(f"    Local:   {local_tree_hash}")
        print("  Aborting restore.")
        sys.exit(1)
    print(f"  Tree hash verified: {dim(local_tree_hash[:30])}...")
    print(f"  Downloaded {len(archive_bytes) / 1024:.1f} KB")

    # Extract to temp dir and scan before moving to target
    with tempfile.TemporaryDirectory() as tmpdir:
        tmppath = Path(tmpdir)
        print("  Extracting to temporary directory...")
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as tar:
            tar.extractall(path=tmppath, filter="data")

        # Scan restored files for security issues (warn but don't block)
        print("  Scanning restored skill...")
        scanner = Scanner()
        scan_report = scanner.scan(tmppath, tree_hash=local_tree_hash)
        _print_scan_results(scan_report, indent=2)

        if not scan_report.get("clean", True):
            print(yellow("\n  WARNING: Security issues found in restored skill."))

        # Submit verification report (dual-side verification)
        print("\n  Submitting verification report...")
        try:
            verify_resp = client.verify(namespace, skill_name, version, scan_report)
            verify_verdict = verify_resp.get("verdict", "unknown")
            if verify_verdict == "verified":
                print(green("  Verified: publisher and consumer scans match."))
            elif verify_verdict == "critical":
                print(red("  CRITICAL: Tree hash mismatch detected by server!"))
                print("  Aborting restore.")
                sys.exit(1)
            elif verify_verdict == "divergent":
                print(yellow("  WARNING: Scan reports diverge."))
        except SkillSafeError as e:
            if e.status == 403:
                pass  # Expected for self-restore
            else:
                print(f"  Warning: Verification failed: {e.message}", file=sys.stderr)

        # Extract to final target directory
        target_dir.mkdir(parents=True, exist_ok=True)
        print(f"  Extracting to {target_dir}...")
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as tar:
            tar.extractall(path=target_dir, filter="data")

    print(green(f"\n  Restored @{namespace}/{skill_name}"))
    print(f"  Location: {target_dir}")

    if skills_dir:
        print(f"\n  Skill is now available in: {skills_dir}")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _resolve_skills_dir(args: argparse.Namespace) -> Optional[Path]:
    """
    Resolve the target skills directory from CLI flags.

    --skills-dir <path>  → use that path directly
    --tool <name>        → look up in TOOL_SKILLS_DIRS
    (neither)            → return None (install to ~/.skillsafe/skills/)
    """
    skills_dir = getattr(args, "skills_dir", None)
    if skills_dir:
        return Path(skills_dir).expanduser().resolve()
    tool = getattr(args, "tool", None)
    if tool:
        if tool not in TOOL_SKILLS_DIRS:
            print(f"Error: Unknown tool '{tool}'. Supported tools: {', '.join(TOOL_SKILLS_DIRS.keys())}", file=sys.stderr)
            sys.exit(1)
        return TOOL_SKILLS_DIRS[tool]
    return None


def _print_scan_results(report: Dict[str, Any], indent: int = 0) -> None:
    """Pretty-print scan results."""
    prefix = " " * indent
    findings = report.get("findings_summary", [])

    if report.get("clean", True) and not findings:
        print(f"{prefix}{green('No security issues found.')}")
        return

    print(f"{prefix}{yellow(f'Found {len(findings)} issue(s):')}\n")
    for f in findings:
        sev = format_severity(f.get("severity", "info"))
        loc = f"{f.get('file', '?')}:{f.get('line', '?')}"
        msg = f.get("message", "")
        print(f"{prefix}  {sev} {loc:<35} {msg}")
        ctx = f.get("context", "")
        if ctx:
            print(f"{prefix}           {dim(ctx[:100])}")


def _update_lockfile(namespace: str, name: str, version: str, tree_hash: str) -> None:
    """Update skillsafe.lock in the current working directory (if it exists or cwd is a project)."""
    lockfile = Path.cwd() / "skillsafe.lock"

    lock_data: Dict[str, Any]
    if lockfile.exists():
        with open(lockfile, "r") as f:
            try:
                lock_data = json.load(f)
            except json.JSONDecodeError:
                print("Warning: Lockfile corrupted, starting fresh", file=sys.stderr)
                lock_data = {"lockfile_version": 1, "skills": {}}
    else:
        # Only create lockfile if there's a recognizable project marker
        project_markers = ["package.json", "pyproject.toml", "Cargo.toml", "go.mod", ".git"]
        if not any((Path.cwd() / m).exists() for m in project_markers):
            return
        lock_data = {"lockfile_version": 1, "skills": {}}

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    lock_data.setdefault("skills", {})[f"@{namespace}/{name}"] = {
        "version": version,
        "tree_hash": tree_hash,
        "installed_at": now,
    }

    with open(lockfile, "w") as f:
        json.dump(lock_data, f, indent=2)
        f.write("\n")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def main(argv: Optional[List[str]] = None) -> None:
    parser = argparse.ArgumentParser(
        prog="skillsafe",
        description="SkillSafe — secured skill registry client for AI coding tools.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            examples:
              skillsafe auth                              # browser login
              skillsafe scan ./my-skill
              skillsafe save ./my-skill --version 1.0.0
              skillsafe share @alice/my-skill --version 1.0.0
              skillsafe share @alice/my-skill --version 1.0.0 --public
              skillsafe install @alice/my-skill --tool claude
              skillsafe install @alice/my-skill --tool cursor
              skillsafe install @alice/my-skill --skills-dir ~/custom/skills
              skillsafe search "salesforce automation"
              skillsafe info @alice/my-skill
              skillsafe list
              skillsafe backup ~/.claude/skills/my-skill
              skillsafe restore my-skill --tool claude
              skillsafe restore my-skill --tool windsurf
              skillsafe whoami                             # check auth status
        """),
    )
    parser.add_argument("--api-base", default=None, help="API base URL (default: %(default)s)")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # -- auth ---------------------------------------------------------------
    p_auth = subparsers.add_parser("auth", help="Authenticate via browser login")

    # -- scan ---------------------------------------------------------------
    p_scan = subparsers.add_parser("scan", help="Scan a skill directory for security issues")
    p_scan.add_argument("path", help="Path to the skill directory")
    p_scan.add_argument("-o", "--output", help="Write JSON report to file")

    # -- save ---------------------------------------------------------------
    p_save = subparsers.add_parser("save", help="Save a skill to the registry (private by default)")
    p_save.add_argument("path", help="Path to the skill directory")
    p_save.add_argument("--version", required=True, help="Semantic version (e.g. 1.0.0)")
    p_save.add_argument("--description", help="Skill description")
    p_save.add_argument("--category", help="Skill category")
    p_save.add_argument("--tags", help="Comma-separated tags")

    # -- share --------------------------------------------------------------
    p_share = subparsers.add_parser("share", help="Create a share link for a saved skill")
    p_share.add_argument("skill", help="Skill reference (e.g. @alice/my-skill)")
    p_share.add_argument("--version", required=True, help="Version to share (e.g. 1.0.0)")
    p_share.add_argument("--public", action="store_true", help="Make skill discoverable via search")
    p_share.add_argument("--expires", choices=["1d", "7d", "30d", "never"], help="Link expiration (default: never)")

    # -- install ------------------------------------------------------------
    p_install = subparsers.add_parser("install", help="Install a skill from the registry")
    p_install.add_argument("skill", help="Skill reference (e.g. @alice/my-skill)")
    p_install.add_argument("--version", help="Specific version (default: latest)")
    install_target = p_install.add_mutually_exclusive_group()
    install_target.add_argument("--skills-dir", help="Install into a custom skills directory")
    install_target.add_argument("--tool", choices=list(TOOL_SKILLS_DIRS.keys()),
        help="Install into a known tool's skills dir (claude, cursor, windsurf)")

    # -- search -------------------------------------------------------------
    p_search = subparsers.add_parser("search", help="Search for skills")
    p_search.add_argument("query", nargs="?", help="Search query")
    p_search.add_argument("--category", help="Filter by category")
    p_search.add_argument("--sort", default="popular", choices=["popular", "recent", "verified", "trending", "hot"], help="Sort order")
    p_search.add_argument("--limit", type=int, default=20, help="Max results (default: 20)")

    # -- info ---------------------------------------------------------------
    p_info = subparsers.add_parser("info", help="Get skill details")
    p_info.add_argument("skill", help="Skill reference (e.g. @alice/my-skill)")

    # -- list ---------------------------------------------------------------
    p_list = subparsers.add_parser("list", help="List locally installed skills")
    p_list.add_argument("--skills-dir", action="append", help="Additional skills directory to scan (can be repeated)")

    # -- backup -------------------------------------------------------------
    p_backup = subparsers.add_parser("backup", help="Back up a skill directory to the registry (private, auto-versioned)")
    p_backup.add_argument("path", help="Path to the skill directory to back up")
    p_backup.add_argument("--name", help="Skill name (default: directory name)")
    p_backup.add_argument("--version", help="Explicit version (default: auto-increment from latest)")

    # -- restore ------------------------------------------------------------
    p_restore = subparsers.add_parser("restore", help="Restore a skill from the registry")
    p_restore.add_argument("name", help="Skill name or @namespace/name")
    restore_target = p_restore.add_mutually_exclusive_group()
    restore_target.add_argument("--skills-dir", help="Restore into a custom skills directory")
    restore_target.add_argument("--tool", choices=list(TOOL_SKILLS_DIRS.keys()),
        help="Restore into a known tool's skills dir (claude, cursor, windsurf)")
    p_restore.add_argument("-o", "--output", help="Restore to a specific directory")

    # -- whoami -------------------------------------------------------------
    p_whoami = subparsers.add_parser("whoami", help="Show current authentication status and account info")

    args = parser.parse_args(argv)

    # Merge --api-base from top-level into subcommand namespace
    if args.api_base:
        setattr(args, "api_base", args.api_base)
    elif not hasattr(args, "api_base"):
        setattr(args, "api_base", DEFAULT_API_BASE)

    # Validate --api-base scheme early (allow http only for localhost/127.0.0.1)
    api_base_val = getattr(args, "api_base", DEFAULT_API_BASE) or DEFAULT_API_BASE
    if api_base_val and not api_base_val.startswith("https://"):
        parsed_base = urllib.parse.urlparse(api_base_val)
        if parsed_base.hostname not in ("localhost", "127.0.0.1"):
            print(f"Error: Refusing to use insecure HTTP API base: {api_base_val}. Use HTTPS.", file=sys.stderr)
            sys.exit(1)

    if args.command == "auth":
        cmd_auth(args)
    elif args.command == "scan":
        cmd_scan(args)
    elif args.command == "save":
        cmd_save(args)
    elif args.command == "share":
        cmd_share(args)
    elif args.command == "install":
        cmd_install(args)
    elif args.command == "search":
        cmd_search(args)
    elif args.command == "info":
        cmd_info(args)
    elif args.command == "list":
        cmd_list(args)
    elif args.command == "backup":
        cmd_backup(args)
    elif args.command == "restore":
        cmd_restore(args)
    elif args.command == "whoami":
        cmd_whoami(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
