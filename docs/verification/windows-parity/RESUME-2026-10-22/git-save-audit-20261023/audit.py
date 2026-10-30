"""Read-only Git and filename/size audit; never stage, commit, or read secrets."""
import collections
import json
from pathlib import Path
import re
import subprocess

ROOT = Path.cwd().resolve()
OUT = Path(__file__).resolve().parent


def git(*args):
    result = subprocess.run(["git", "-c", "core.quotePath=false", *args], cwd=ROOT, capture_output=True)
    return result.stdout, result.stderr.decode("utf-8", errors="replace"), result.returncode


tracked_raw, tracked_errors, tracked_exit = git("diff", "--name-only", "-z")
staged_raw, staged_errors, staged_exit = git("diff", "--cached", "--name-only", "-z")
untracked_raw, errors, untracked_exit = git("ls-files", "--others", "--exclude-standard", "-z")
tracked = [name.decode("utf-8") for name in tracked_raw.split(b"\0") if name]
staged = [name.decode("utf-8") for name in staged_raw.split(b"\0") if name]
untracked = [name.decode("utf-8") for name in untracked_raw.split(b"\0") if name]
generated = re.compile(r"(^|/)(?:artifacts|bin|obj|build|dist|package-stages|installed|installation|test-temp[^/]*|pytest[^/]*|temp|profile|profile-data|\.tmp[^/]*|native-publish[^/]*|publish[^/]*)(/|$)|\.(?:exe|dll|pdb|zip|7z|nupkg|msix|msixbundle|msi|pyc|mui|winmd|lib|exp|obj|pri)$", re.I)
sensitive = re.compile(r"(^|/)(?:\.env(?:\.[^/]*)?|credentials?(?:\.[^/]*)?|secrets?(?:\.[^/]*)?|id_rsa|id_ed25519|settings\.json|local-settings\.json|token(?:\.[^/]*)?|.*\.(?:pem|key|pfx|p12|kdbx))$", re.I)
evidence_capture = re.compile(r"\.(?:png|jpg|jpeg|webp|mp4|webm)$", re.I)
rows = []
for name in tracked + untracked:
    path = ROOT / name
    try:
        size = path.stat().st_size
    except OSError:
        size = None
    if sensitive.search(name):
        category = "sensitive-name-review-only"
    elif generated.search(name):
        category = "generated-exclude"
    elif size is not None and size >= 10 * 1024 * 1024:
        category = "large-file-review-exclude-default"
    elif name.startswith("docs/verification/"):
        category = "evidence-image-review" if evidence_capture.search(name) else "evidence-curation-required"
    elif name.startswith(("src/", "tests/", "tools/", "schemas/", "installer/")) or name.startswith("desktop/") and path.suffix in {".cs", ".csproj", ".xaml", ".props", ".targets"}:
        category = "code-test-schema"
    else:
        category = "other-document-or-prior-work-review"
    rows.append(dict(path=name, status="tracked-modified" if name in tracked else "untracked",
                     size_bytes=size, category=category))

code = [row["path"] for row in rows if row["category"] == "code-test-schema"]
assert set(code) == set(tracked) - {"docs/roadmap-windows-parity-2026-10-20.md",
    "docs/verification/windows-parity/RESUME-2026-10-22/README.md", "docs/windows-parity-backlog.json",
    "docs/windows-parity-todo.md"} | {"tests/test_fleet_schema_contract.py", "tests/test_local_provider_timeouts.py",
    "desktop/windows/AttackMap.NativeSpike/ParitySmokeTimeouts.cs"}, code
with (OUT / "code-path-allowlist.txt").open("x", encoding="utf-8", newline="\n") as stream:
    stream.write("\n".join(sorted(code)) + "\n")
with (OUT / "inventory.json").open("x", encoding="utf-8") as stream:
    json.dump(rows, stream, indent=2)
with (OUT / "enumeration-warnings.txt").open("x", encoding="utf-8") as stream:
    stream.write(errors + tracked_errors + staged_errors)
summary = dict(scope="Read-only Git names/status/metadata only; no sensitive values inspected", staged_paths=staged,
    tracked_modified_count=len(tracked), untracked_visible_count=len(untracked), tracked_modified_paths=tracked,
    code_allowlist_count=len(code), categories=dict(collections.Counter(row["category"] for row in rows)),
    category_bytes={key: sum(row["size_bytes"] or 0 for row in rows if row["category"] == key)
                    for key in sorted({row["category"] for row in rows})},
    largest_visible_files=sorted((row for row in rows if row["size_bytes"] is not None),
                                key=lambda row: row["size_bytes"], reverse=True)[:15],
    sensitive_name_candidates=[row for row in rows if row["category"] == "sensitive-name-review-only"],
    enumeration_exit_codes=dict(tracked=tracked_exit, staged=staged_exit, untracked=untracked_exit),
    warning_lines=len(errors.splitlines()), inventory_is_complete=not bool(errors),
    note="Permission/long-path warnings limit untracked enumeration. No ACL changes or cleanup attempted.")
with (OUT / "summary.json").open("x", encoding="utf-8") as stream:
    json.dump(summary, stream, indent=2)
print(json.dumps({key: value for key, value in summary.items() if key not in {"sensitive_name_candidates", "largest_visible_files", "tracked_modified_paths"}}, indent=2))
