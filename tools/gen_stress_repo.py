#!/usr/bin/env python
"""Deterministic stress-fixture generator for C35 resource-limit measurements.

Generates a repository of N small, analyzable Python files into a TEMP/output
directory chosen at run time. Fixtures are never committed to this repository.
Content is fully deterministic (a fixed template parameterised by file index),
so file count, byte sizes, and analysis load are declared exactly on stdout.

Usage:
    python tools/gen_stress_repo.py --count 10000 --output <dir> [--files-per-dir 500]

Prints one JSON line: {"files": N, "bytes": B, "output": "..."}.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_TEMPLATE = '''"""Stress fixture module {index}: deterministic content (C35). Do not edit by hand."""
import json
import os
import subprocess
from flask import Flask, request, jsonify

app = Flask(__name__)
MODULE_ID = {index}


@app.route("/api/v1/items/{index}", methods=["GET", "POST"])
def get_item_{index}():
    token = request.headers.get("Authorization")
    payload = json.loads(request.get_data() or b"{{}}")
    record = {{"id": {index}, "token": token, "payload": payload}}
    return jsonify(record)


def run_task_{index}(command_arg):
    env_key = "STRESS_SECRET_{index}"
    secret = os.environ.get(env_key)
    completed = subprocess.run(["echo", command_arg], capture_output=True)
    return (secret, completed.returncode)
'''


def generate_fixture(output: Path, count: int, *, files_per_dir: int = 500) -> dict:
    """Write ``count`` deterministic fixture files; return the declared totals."""
    if count < 1:
        raise SystemExit("--count must be >= 1")
    if files_per_dir < 1:
        raise SystemExit("--files-per-dir must be >= 1")
    output.mkdir(parents=True, exist_ok=True)
    total_bytes = 0
    for index in range(count):
        shard = output / f"pkg_{index // files_per_dir:04d}"
        if index % files_per_dir == 0:
            shard.mkdir(exist_ok=True)
        text = _TEMPLATE.format(index=index)
        total_bytes += len(text.encode("utf-8"))
        (shard / f"mod_{index:07d}.py").write_text(text, encoding="utf-8", newline="\n")
    return {"files": count, "bytes": total_bytes, "output": str(output)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, required=True,
                        help="number of fixture files to generate (e.g. 10000, 50000, 100000)")
    parser.add_argument("--output", type=Path, required=True,
                        help="directory to generate into (create a temp dir at run time; do not commit fixtures)")
    parser.add_argument("--files-per-dir", type=int, default=500,
                        help="shard size: files per subdirectory (default 500)")
    args = parser.parse_args(argv)
    summary = generate_fixture(args.output, args.count, files_per_dir=args.files_per_dir)
    json.dump(summary, sys.stdout)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
