"""Detection rules: provider-specific patterns first, then entropy-checked generic assignments."""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    pattern: re.Pattern[str]
    severity: str = "high"
    min_entropy: float = 0.0  # applied to the captured secret
    group: int = 0  # which regex group holds the secret


def _r(p: str, flags: int = 0) -> re.Pattern[str]:
    return re.compile(p, flags)


RULES: list[Rule] = [
    Rule("private-key", "Private key", _r(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY( BLOCK)?-----"), "critical"),
    Rule("aws-access-key-id", "AWS access key ID", _r(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b"), "critical", group=1),
    Rule(
        "aws-secret-access-key",
        "AWS secret access key",
        _r(r"aws_?secret_?access_?key\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})\b", re.I),
        "critical",
        4.0,
        group=1,
    ),
    Rule("github-token", "GitHub token", _r(r"\b(gh[pousr]_[A-Za-z0-9]{36,255})\b"), "critical", group=1),
    Rule("github-fine-grained-pat", "GitHub fine-grained token", _r(r"\b(github_pat_[A-Za-z0-9_]{60,255})\b"), "critical", group=1),
    Rule("gitlab-token", "GitLab token", _r(r"\b(glpat-[A-Za-z0-9_\-]{20})\b"), "critical", group=1),
    Rule("slack-token", "Slack token", _r(r"\b(xox[abposr]-[A-Za-z0-9-]{10,})\b"), "high", group=1),
    Rule("slack-webhook", "Slack webhook", _r(r"(https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+)"), "high", group=1),
    Rule("stripe-live-key", "Stripe live secret key", _r(r"\b((?:sk|rk)_live_[A-Za-z0-9]{24,})\b"), "critical", group=1),
    Rule("google-api-key", "Google API key", _r(r"\b(AIza[0-9A-Za-z\-_]{35})\b"), "high", group=1),
    Rule("openai-key", "OpenAI API key", _r(r"\b(sk-(?:proj-)?[A-Za-z0-9_\-]{20,}T3BlbkFJ[A-Za-z0-9_\-]{20,})\b"), "critical", group=1),
    Rule("jwt", "JSON Web Token", _r(r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b"), "medium", group=1),
    Rule(
        "db-connection-string",
        "Database URL with password",
        _r(r"\b((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:/@\"']+:([^\s@/\"']{4,})@[^\s\"']+)"),
        "high",
        2.5,
        group=2,
    ),
    Rule(
        "generic-secret",
        "Hard-coded secret",
        _r(
            r"(?:password|passwd|pwd|secret|token|api_?key|access_?key|client_?secret|auth_?token)[\w.-]{0,20}\s*[:=]{1,2}\s*[\"']([^\"'\s]{8,})[\"']",
            re.I,
        ),
        "medium",
        3.5,
        group=1,
    ),
]

PLACEHOLDERS = re.compile(
    r"^(?:\$?\{.*\}|<.*>|%\(.*\)s|.*(?:example|changeme|change_me|placeholder|your[_-]?|dummy|redacted|xxxx|\*\*\*|test|sample).*)$",
    re.I,
)


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    return -sum(c / len(s) * math.log2(c / len(s)) for c in counts.values())


def looks_like_placeholder(secret: str) -> bool:
    return bool(PLACEHOLDERS.match(secret)) or len(set(secret)) <= 3
