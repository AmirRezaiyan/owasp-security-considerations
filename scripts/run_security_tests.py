"""Run the repository's security test suite with the active Python interpreter."""

import subprocess
import sys
from pathlib import Path


def main() -> int:
    project_root = Path(__file__).resolve().parents[1]
    command = [sys.executable, "-m", "pytest", "-q", "tests/security"]
    print("Running OWASP API security tests...", flush=True)
    result = subprocess.run(command, cwd=project_root, check=False)
    print(f"Security test command exited with status {result.returncode}.")
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
