"""leakhound command line."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from . import __version__, report
from .scanner import scan_history, scan_path, scan_staged


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="leakhound", description="Find leaked credentials in files and git history.")
    p.add_argument("path", nargs="?", default=".", help="file, directory or git repo (default: .)")
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--history", action="store_true", help="scan every commit on every branch, not just current files")
    mode.add_argument("--staged", action="store_true", help="scan staged changes only (pre-commit hook)")
    p.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    p.add_argument("-o", "--output", help="write the report to a file instead of stdout")
    p.add_argument("--baseline", help="JSON file of accepted fingerprints; matching findings are ignored")
    p.add_argument("--update-baseline", action="store_true", help="write current findings to --baseline and exit 0")
    p.add_argument("--show-secrets", action="store_true", help="print full secrets in JSON output (careful)")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = Path(args.path)
    if not root.exists():
        print(f"leakhound: {root} does not exist", file=sys.stderr)
        return 2
    try:
        findings = scan_history(root) if args.history else scan_staged(root) if args.staged else scan_path(root)
    except subprocess.CalledProcessError as e:
        print(f"leakhound: git failed: {e.stderr.strip()}", file=sys.stderr)
        return 2

    if args.baseline and args.update_baseline:
        Path(args.baseline).write_text(json.dumps(sorted({f.fingerprint for f in findings}), indent=2) + "\n")
        print(f"Baseline of {len(findings)} finding(s) written to {args.baseline}")
        return 0
    if args.baseline and Path(args.baseline).exists():
        accepted = set(json.loads(Path(args.baseline).read_text()))
        findings = [f for f in findings if f.fingerprint not in accepted]

    out = {"text": report.text, "sarif": report.sarif}.get(args.format, lambda fs: report.as_json(fs, args.show_secrets))(findings)
    if args.output:
        Path(args.output).write_text(out + "\n")
    else:
        print(out)
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
