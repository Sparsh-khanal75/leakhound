"""Text, JSON and SARIF output."""

from __future__ import annotations

import json

from . import __version__
from .rules import RULES
from .scanner import Finding

SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def text(findings: list[Finding]) -> str:
    if not findings:
        return "No secrets found."
    out = []
    for f in sorted(findings, key=lambda f: (SEVERITY_ORDER[f.severity], f.path, f.line)):
        where = f"{f.path}:{f.line}" + (f"  (commit {f.commit} by {f.author})" if f.commit else "")
        out.append(f"{f.severity.upper():<9}{f.name:<28}{where}\n{'':9}{f.redacted}   fingerprint {f.fingerprint}")
    crit = sum(f.severity == "critical" for f in findings)
    out.append(f"\n{len(findings)} secret(s) found, {crit} critical. Rotate them first; deleting the line does not remove it from git history.")
    return "\n".join(out)


def as_json(findings: list[Finding], show_secrets: bool = False) -> str:
    return json.dumps([f.as_dict(show_secrets) for f in findings], indent=2)


def sarif(findings: list[Finding]) -> str:
    """SARIF 2.1.0, uploadable to GitHub code scanning."""
    used = {f.rule for f in findings}
    rules = [
        {
            "id": r.id,
            "name": r.name.title().replace(" ", ""),
            "shortDescription": {"text": r.name},
            "defaultConfiguration": {"level": SARIF_LEVEL[r.severity]},
            "properties": {"tags": ["security", "secrets"], "security-severity": {"critical": "9.5", "high": "8.0", "medium": "5.5"}.get(r.severity, "3.0")},
        }
        for r in RULES
        if r.id in used
    ]
    results = [
        {
            "ruleId": f.rule,
            "level": SARIF_LEVEL[f.severity],
            "message": {"text": f"{f.name} found ({f.redacted})" + (f" in commit {f.commit}" if f.commit else "")},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.path}, "region": {"startLine": f.line}}}],
            "partialFingerprints": {"leakhound/v1": f.fingerprint},
        }
        for f in findings
    ]
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "leakhound", "version": __version__, "rules": rules}}, "results": results}],
    }
    return json.dumps(doc, indent=2)
