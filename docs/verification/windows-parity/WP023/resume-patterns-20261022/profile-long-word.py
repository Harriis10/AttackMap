"""Bounded diagnosis only; unchanged production scanner and 200KB test payload."""
import cProfile
import hashlib
import io
import json
from pathlib import Path
import pstats
import tempfile
import time
from attackmap.scanner import scan_repo

proof = Path(__file__).resolve().parent
with tempfile.TemporaryDirectory(prefix="attackmap-wp023-patterns-") as raw:
    repo = Path(raw)
    (repo / "app.py").write_text("from flask import Flask\napp = Flask(__name__)\n\n@app.route('/ok')\ndef ok():\n    return 'ok'\n", encoding="utf-8")
    payload = "x = " + "a" * 200_000 + "\n"
    for name in ("big.py", "schema.graphql"):
        (repo / name).write_text(payload, encoding="utf-8")
    profile = cProfile.Profile()
    start = time.perf_counter()
    cpu = time.process_time()
    result = profile.runcall(scan_repo, repo)
    wall = time.perf_counter() - start
    cpu = time.process_time() - cpu
    profile.dump_stats(str(proof / "long-word.prof"))
    stream = io.StringIO()
    pstats.Stats(profile, stream=stream).strip_dirs().sort_stats("cumulative").print_stats(45)
    (proof / "long-word-profile.txt").write_text(stream.getvalue(), encoding="utf-8")
    summary = {"kind": "diagnostic_profile_not_threshold_test", "wall_seconds": wall, "cpu_seconds": cpu, "routes": len(result.routes), "payload_bytes": len(payload.encode()), "source_sha256": hashlib.sha256(Path("src/attackmap/scanner.py").read_bytes()).hexdigest()}
    (proof / "long-word-summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary))
