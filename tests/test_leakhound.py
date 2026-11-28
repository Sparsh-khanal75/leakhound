"""Secrets are assembled at runtime so this file never contains a real-looking credential itself."""

import json
import random
import string
import subprocess
from pathlib import Path

import pytest

from leakhound.cli import main
from leakhound.rules import shannon_entropy
from leakhound.scanner import scan_diff, scan_path, scan_text

rng = random.Random(42)


def rand(n: int, alphabet: str = string.ascii_letters + string.digits) -> str:
    return "".join(rng.choice(alphabet) for _ in range(n))


AWS_ID = "AK" + "IA" + rand(16, string.ascii_uppercase + string.digits)
GH_TOKEN = "gh" + "p_" + rand(36)
STRIPE = "sk_" + "live_" + rand(28)
PEM = "-----BEGIN " + "RSA PRIVATE KEY-----"
HIGH_ENTROPY = rand(24)
PW = "pass" + "word"


def rules_in(text: str) -> list[str]:
    return [f.rule for f in scan_text(text, "x")]


@pytest.mark.parametrize(
    ("line", "rule"),
    [
        (f'aws_key = "{AWS_ID}"', "aws-access-key-id"),
        (f"token: {GH_TOKEN}", "github-token"),
        (f"STRIPE={STRIPE}", "stripe-live-key"),
        (PEM, "private-key"),
        (f"DATABASE_URL=postgres://app:{HIGH_ENTROPY}@db.internal:5432/prod", "db-connection-string"),
        (f'db_{PW} = "{HIGH_ENTROPY}"', "generic-secret"),
    ],
    ids=["aws", "github", "stripe", "pem", "db-url", "generic"],
)
def test_detects_real_looking_secrets(line, rule):
    assert rules_in(line) == [rule]


@pytest.mark.parametrize(
    "line",
    [
        f'{PW} = "changeme123"',
        f'{PW} = "${{DB_{PW.upper()}}}"',
        'api_key = "<your-api-key-here>"',
        f'{PW} = "aaaaaaaaaaaa"',
        f'{PW} = "Summer2026"',  # too little entropy for the generic rule
        f'{PW} = os.environ["DB_{PW.upper()}"]',
        f'aws_key = "{AWS_ID}"  # leakhound:ignore',
        f'url = "postgres://app:{{{PW.upper()}}}@db:5432/x"',  # template placeholder
        'authlog-hunter = "authlog_hunter.cli:main"',  # "auth" in a name is not a secret
    ],
    ids=["changeme", "env-template", "angle", "repeated", "low-entropy", "environ", "ignore-mark", "brace-template", "auth-word"],
)
def test_ignores_placeholders_env_lookups_and_marked_lines(line):
    assert rules_in(line) == []


def test_specific_rule_wins_over_generic():
    assert rules_in(f'github_token = "{GH_TOKEN}"') == ["github-token"]


def test_entropy():
    assert shannon_entropy("aaaa") == 0
    assert shannon_entropy(HIGH_ENTROPY) > 4


def test_redaction_never_shows_the_whole_secret():
    f = next(scan_text(f"x={STRIPE}", "a.env"))
    assert f.redacted.startswith(STRIPE[:4]) and STRIPE not in f.redacted
    assert STRIPE not in json.dumps(f.as_dict())


def test_scan_path_skips_binary_ignored_and_vendored(tmp_path: Path):
    (tmp_path / "app.py").write_text(f'KEY = "{AWS_ID}"\n')
    (tmp_path / "image.bin").write_bytes(b"\x00\x01" + AWS_ID.encode())
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "lib.js").write_text(f'k="{AWS_ID}"')
    (tmp_path / "fixtures").mkdir()
    (tmp_path / "fixtures" / "fake.txt").write_text(AWS_ID)
    (tmp_path / ".leakhoundignore").write_text("# test data\nfixtures/*\n")
    found = scan_path(tmp_path)
    assert [(f.path, f.line) for f in found] == [("app.py", 1)]


def test_diff_scanning_reports_added_lines_with_commit_and_line_numbers():
    diff = f"""commit 0123456789abcdef
Author: Dev One <dev@example.com>

diff --git a/config.py b/config.py
--- a/config.py
+++ b/config.py
@@ -10,0 +11,2 @@
+DEBUG = False
+STRIPE_KEY = "{STRIPE}"
@@ -40 +41 @@
-OLD = "{GH_TOKEN}"
+NEW = 1
"""
    [f] = scan_diff(diff)
    assert (f.rule, f.path, f.line, f.commit, f.author) == ("stripe-live-key", "config.py", 12, "0123456789ab", "Dev One")


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t", *args], check=True, capture_output=True)


def test_history_finds_a_secret_that_was_deleted(tmp_path: Path):
    _git(tmp_path, "init", "-q")
    (tmp_path / "settings.py").write_text(f'TOKEN = "{GH_TOKEN}"\n')
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "add config")
    (tmp_path / "settings.py").write_text('TOKEN = os.environ["TOKEN"]\n')
    _git(tmp_path, "commit", "-qam", "remove token")

    assert main([str(tmp_path)]) == 0  # working tree is clean now
    out = tmp_path / "r.json"
    assert main([str(tmp_path), "--history", "--format", "json", "-o", str(out)]) == 1
    [f] = json.loads(out.read_text())
    assert f["rule"] == "github-token" and f["path"] == "settings.py" and f["commit"]


def test_staged_mode_for_pre_commit(tmp_path: Path):
    _git(tmp_path, "init", "-q")
    (tmp_path / "a.txt").write_text(PEM + "\n")
    _git(tmp_path, "add", ".")
    assert main([str(tmp_path), "--staged"]) == 1


def test_baseline_and_sarif(tmp_path: Path, capsys):
    (tmp_path / "old.py").write_text(f'K = "{AWS_ID}"\n')
    baseline = tmp_path / "baseline.json"
    assert main([str(tmp_path), "--baseline", str(baseline), "--update-baseline"]) == 0
    assert main([str(tmp_path), "--baseline", str(baseline)]) == 0
    (tmp_path / "new.py").write_text(PEM + "\n")
    capsys.readouterr()
    assert main([str(tmp_path), "--baseline", str(baseline), "--format", "sarif"]) == 1
    sarif = json.loads(capsys.readouterr().out)
    results = sarif["runs"][0]["results"]
    assert sarif["version"] == "2.1.0"
    assert [r["ruleId"] for r in results] == ["private-key"]
    assert results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "new.py"


def test_html_report_is_redacted(tmp_path):
    (tmp_path / "settings.py").write_text(f'AWS_ACCESS_KEY_ID = "{AWS_ID}"\nSTRIPE = "{STRIPE}"\n')
    out = tmp_path / "report.html"
    assert main([str(tmp_path), "--format", "html", "-o", str(out)]) == 1
    page = out.read_text(encoding="utf-8")
    assert "Secret scan report" in page
    assert "AWS access key ID" in page
    assert AWS_ID not in page and STRIPE not in page  # never leak the secret itself
    assert AWS_ID[:4] + "*" in page
