#!/usr/bin/env python
"""Compatibility launcher for the Python 3 scanner implementation.

This file intentionally uses old Python syntax so that commands like
`python basic_scan.py ...` can recover on hosts where `python` points to an
obsolete interpreter.  The real implementation lives in basic_scan_core.py.
"""

from __future__ import print_function

import os
import subprocess
import sys


MIN_VERSION = (3, 8)
CORE_FILE = "basic_scan_core.py"


def _candidate_interpreters():
    current = sys.executable
    names = []
    if current:
        names.append(current)
    names.extend(["python3.12", "python3.11", "python3.10", "python3.9", "python3.8", "python3"])
    seen = set()
    for name in names:
        if name and name not in seen:
            seen.add(name)
            yield name


def _version_for(interpreter):
    code = (
        "import sys; "
        "raise SystemExit(0 if sys.version_info[:2] >= %r else 1)"
    ) % (MIN_VERSION,)
    try:
        return subprocess.call(
            [interpreter, "-c", code],
            stdout=open(os.devnull, "w"),
            stderr=open(os.devnull, "w"),
        ) == 0
    except OSError:
        return False


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    core_path = os.path.join(script_dir, CORE_FILE)
    if not os.path.exists(core_path):
        print("Cannot find %s next to %s" % (CORE_FILE, __file__), file=sys.stderr)
        return 2

    for interpreter in _candidate_interpreters():
        if _version_for(interpreter):
            os.execvp(interpreter, [interpreter, core_path] + sys.argv[1:])

    print(
        "basic_scan requires Python %s.%s or newer. "
        "Install Python 3.12 or run with an explicit modern interpreter, for example:\n"
        "  python3.12 basic_scan.py --settings Settings.json"
        % MIN_VERSION,
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    sys.exit(main())
