"""Scan files, staged changes or full git history."""

from __future__ import annotations

import fnmatch
import hashlib
import os
import re
import subprocess
from collections.abc import Iterable, Iterator
from dataclasses import asdict, dataclass
from pathlib import Path

from .rules import RULES, Rule, looks_like_placeholder, shannon_entropy

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".next", ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache"}
SKIP_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".gz", ".whl", ".so", ".dll", ".exe", ".woff", ".woff2", ".lock"}
MAX_BYTES = 1_000_000
IGNORE_MARK = "leakhound:ignore"


@dataclass
class Finding:
    rule: str
    name: str
    severity: str
    path: str
    line: int
    secret: str
    commit: str | None = None
    author: str | None = None

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(f"{self.rule}:{self.secret}".encode()).hexdigest()[:16]

    @property
    def redacted(self) -> str:
        s = self.secret
        return s[:4] + "*" * min(max(len(s) - 4, 4), 16) if len(s) > 8 else "*" * len(s)

    def as_dict(self, show_secret: bool = False) -> dict:
        d = asdict(self)
        d["secret"] = self.secret if show_secret else self.redacted
        d["fingerprint"] = self.fingerprint
        return d


def scan_text(text: str, path: str, rules: Iterable[Rule] = RULES, line_offset: int = 0) -> Iterator[Finding]:
    for n, line in enumerate(text.splitlines(), 1):
        if IGNORE_MARK in line or len(line) > 5000:
            continue
        taken: list[tuple[int, int]] = []
        for rule in rules:
            for m in rule.pattern.finditer(line):
                span = m.span(rule.group)
                if any(span[0] < e and s < span[1] for s, e in taken):
                    continue  # a more specific rule already matched this text
                secret = m.group(rule.group)
                if rule.min_entropy and (shannon_entropy(secret) < rule.min_entropy or looks_like_placeholder(secret)):
                    continue
                taken.append(span)
                yield Finding(rule.id, rule.name, rule.severity, path, n + line_offset, secret)


def load_ignores(root: Path) -> list[str]:
    f = root / ".leakhoundignore"
    if not f.exists():
        return []
    return [ln.strip() for ln in f.read_text().splitlines() if ln.strip() and not ln.startswith("#")]


def _ignored(rel: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(rel, p) or fnmatch.fnmatch(Path(rel).name, p) for p in patterns)


def iter_files(root: Path, ignores: list[str]) -> Iterator[Path]:
    if root.is_file():
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            p = Path(dirpath) / name
            rel = p.relative_to(root).as_posix()
            if p.suffix.lower() in SKIP_SUFFIXES or _ignored(rel, ignores):
                continue
            yield p


def _is_binary(data: bytes) -> bool:
    return b"\x00" in data[:8192]


def scan_path(root: Path) -> list[Finding]:
    ignores = load_ignores(root if root.is_dir() else root.parent)
    findings: list[Finding] = []
    for p in iter_files(root, ignores):
        try:
            if p.stat().st_size > MAX_BYTES:
                continue
            data = p.read_bytes()
        except OSError:
            continue
        if _is_binary(data):
            continue
        rel = p.relative_to(root).as_posix() if root.is_dir() else p.name
        findings.extend(scan_text(data.decode("utf-8", "replace"), rel))
    return findings


HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def scan_diff(diff: str) -> list[Finding]:
    """Scan only added lines of a unified diff (git log -p / git diff --cached)."""
    findings: list[Finding] = []
    commit = author = path = None
    lineno = 0
    for raw in diff.splitlines():
        if raw.startswith("commit "):
            commit = raw.split()[1][:12]
        elif raw.startswith("Author: "):
            author = raw[8:].split(" <")[0]
        elif raw.startswith("+++ "):
            path = raw[6:] if raw.startswith("+++ b/") else None
        elif (m := HUNK.match(raw)) is not None:
            lineno = int(m.group(1))
        elif path and raw.startswith("+") and not raw.startswith("+++"):
            for f in scan_text(raw[1:], path, line_offset=lineno - 1):
                f.commit, f.author = commit, author
                findings.append(f)
            lineno += 1
        elif path and not raw.startswith("-"):
            lineno += 1
    return findings


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, check=True, errors="replace").stdout  # noqa: S603,S607


def scan_history(repo: Path) -> list[Finding]:
    diff = _git(repo, "log", "-p", "--all", "--no-color", "--no-ext-diff", "-U0", "--format=commit %H%nAuthor: %an <%ae>")
    seen: dict[tuple[str, str], Finding] = {}
    for f in scan_diff(diff):  # newest first; keep the oldest commit that introduced each secret
        seen[(f.fingerprint, f.path)] = f
    return list(seen.values())


def scan_staged(repo: Path) -> list[Finding]:
    return scan_diff(_git(repo, "diff", "--cached", "--no-color", "--no-ext-diff", "-U0"))
