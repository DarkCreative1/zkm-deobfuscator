#!/usr/bin/env python3
"""Runs every tests/test_*.py module and reports a summary."""
import glob
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TMP = os.path.join(ROOT, "build", "test-tmp")


def main():
    os.makedirs(TMP, exist_ok=True)
    modules = sorted(glob.glob(os.path.join(ROOT, "tests", "test_*.py")))
    if not modules:
        print("no python tests found")
        return 1
    failed = []
    for m in modules:
        name = os.path.basename(m)
        r = subprocess.run([sys.executable, m], cwd=ROOT, capture_output=True,
                           text=True, errors="replace")
        ok = r.returncode == 0
        if not ok:
            failed.append(name)
            print("FAILED: %s" % name)
            tail = (r.stderr or "").strip().splitlines()
            for line in tail[-5:]:
                print("    " + line)
    print("python tests: %d/%d passed" % (len(modules) - len(failed), len(modules)))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
