"""Build a throwaway git repo with planted, fake credentials to try leakhound on.

    python examples/make_demo_repo.py /tmp/leakhound-demo
    leakhound /tmp/leakhound-demo --history

Every "secret" is random and generated at runtime (and split in this source file),
so nothing here is a real credential and GitHub push protection is not triggered.
"""

from __future__ import annotations

import random
import shutil
import string
import subprocess
import sys
from pathlib import Path

rng = random.Random(7)  # deterministic demo output


def rand(n: int, alphabet: str = string.ascii_letters + string.digits) -> str:
    return "".join(rng.choice(alphabet) for _ in range(n))


def git(repo: Path, *args: str, author: str = "Dev One <dev1@example.com>") -> None:
    name, email = author[:-1].split(" <")
    env = {"GIT_AUTHOR_NAME": name, "GIT_AUTHOR_EMAIL": email, "GIT_COMMITTER_NAME": name, "GIT_COMMITTER_EMAIL": email}
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, env={**env, "PATH": "/usr/bin:/bin:/usr/local/bin"})


def write(repo: Path, rel: str, text: str) -> None:
    path = repo / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def main(dest: str) -> None:
    repo = Path(dest)
    shutil.rmtree(repo, ignore_errors=True)
    repo.mkdir(parents=True)
    git(repo, "init", "-q", "-b", "main")

    aws_id = "AK" + "IA" + rand(16, string.ascii_uppercase + string.digits)
    aws_secret = rand(40, string.ascii_letters + string.digits + "/+")
    write(repo, "README.md", "# billing-service\n")
    write(repo, "config/settings.py", f'AWS_ACCESS_KEY_ID = "{aws_id}"\naws_secret_access_key = "{aws_secret}"\nREGION = "eu-west-1"\n')
    git(repo, "add", ".")
    git(repo, "commit", "-q", "-m", "initial billing service")

    # A key committed by mistake, then "removed" - it is still in history.
    write(repo, ".env", "STRIPE_KEY=" + "sk_" + "live_" + rand(28) + "\nDEBUG=false\n")
    git(repo, "add", ".")
    git(repo, "commit", "-q", "-m", "add env", author="Dev Two <dev2@example.com>")
    (repo / ".env").unlink()
    git(repo, "commit", "-q", "-am", "remove .env (oops)", author="Dev Two <dev2@example.com>")

    write(
        repo,
        "deploy/notify.sh",
        "curl -X POST "
        + "https://hooks.slack"
        + ".com/services/T"
        + rand(9, string.ascii_uppercase + string.digits)
        + "/B"
        + rand(9, string.ascii_uppercase + string.digits)
        + "/"
        + rand(24)
        + " -d @msg.json\n",
    )
    write(repo, "deploy/ci.yml", "env:\n  GH_TOKEN: " + "gh" + "p_" + rand(36) + "\n")
    write(repo, "app/db.py", 'DATABASE_URL = "postgres://billing:' + "Pr0d" + rand(10) + '@db.internal:5432/billing"\n')
    write(repo, "app/client.py", 'api_key = "' + rand(32) + '"\n')
    write(repo, "keys/deploy_rsa", "-----BEGIN " + "RSA PRIVATE KEY-----\n" + rand(64) + "\n-----END " + "RSA PRIVATE KEY-----\n")
    git(repo, "add", ".")
    git(repo, "commit", "-q", "-m", "deployment scripts", author="Dev One <dev1@example.com>")
    print(f"Demo repo with planted fake secrets created at {repo}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "/tmp/leakhound-demo")
