"""Save a new local checkpoint ref with a private index; leave shared HEAD/index intact."""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[5]
WORK = ROOT / ".tmp/wp043-fleet16-20261023"
EVIDENCE = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "tools"))
import generate_release_lock as locks


def main():
    proof_path = EVIDENCE / "candidate/git-checkpoint.json"
    if proof_path.exists(): raise RuntimeError("Existing checkpoint proof preserved")
    env = dict(os.environ)
    private_index = WORK / "git-checkpoint-04.index"
    if private_index.exists(): raise RuntimeError("Existing private index preserved")
    def git(*arguments):
        result = subprocess.run(["git", "-c", "core.longpaths=true", *arguments], cwd=ROOT, env=env,
            capture_output=True, text=True, encoding="utf-8", timeout=180)
        if result.returncode:
            error = EVIDENCE / "candidate/git-checkpoint04-error.txt"
            with error.open("x", encoding="utf-8") as stream: stream.write(result.stderr)
            raise RuntimeError("\n".join(line for line in result.stderr.splitlines() if not line.startswith("warning:"))[-3000:])
        return result.stdout.strip()
    head = git("rev-parse", "HEAD")
    index = Path(git("rev-parse", "--git-path", "index"))
    if not index.is_absolute(): index = ROOT / index
    index_before = locks.sha256_file(index) if index.exists() else None
    inputs = locks.release_inputs(ROOT)
    capture = json.loads((EVIDENCE / "candidate/source-capture-02.json").read_text())
    if inputs != capture["inputs"]: raise RuntimeError("Shared shipping sources changed after capture02")
    with (EVIDENCE / "candidate/git-checkpoint04-start.json").open("x", encoding="utf-8") as stream:
        json.dump(dict(head=head, shared_index_sha256=index_before, private_index=str(private_index)), stream, indent=2)
    ref = "refs/heads/codex/fleet16-checkpoint-20261023"
    existing = subprocess.run(["git", "show-ref", "--verify", "--quiet", ref], cwd=ROOT)
    if existing.returncode != 1: raise RuntimeError("Checkpoint ref exists or cannot be checked")
    env["GIT_INDEX_FILE"] = str(private_index)
    git("read-tree", head)
    git("add", "-u", "--")
    scope = "docs/verification/windows-parity/WP043/fleet16-20261023"
    paths = ["src", "installer", "tests", "schemas", "tools",
        "desktop/windows/AttackMap.NativeSpike", "desktop/windows/GraphExplorer.Core",
        "desktop/windows/GraphExplorer.Core.Tests", "desktop/windows/GraphExplorer.NativeView",
        "desktop/windows/GraphExplorer.Web", "desktop/windows/FleetGraphBinding.Tests",
        "docs/ecosystem", "docs/architecture", "docs/fleet-architecture.md", scope,
        "docs/verification/windows-parity/WP039/sol-ultra-20261023-python/BUILD-HANDOFF.md"]
    candidates = [name for name in git("ls-files", "--others", "--exclude-standard", "-z", "--", *paths).split("\0") if name]
    candidates = [name for name in candidates if not (name.startswith(scope + "/") and
        ("/profile/" in name or "/temp/" in name or name.startswith(scope + "/candidate/frozen-runtime-01/reports/") or
         name.startswith(scope + "/candidate/frozen-runtime-01/action-result/")))]
    pathspec = WORK / "git-checkpoint04-paths.nul"
    with pathspec.open("xb") as stream:
        stream.write(b"\0".join((":(literal)" + name).encode("utf-8") for name in candidates) + b"\0")
    if candidates: git("add", "--pathspec-from-file=" + str(pathspec), "--pathspec-file-nul")
    changed = git("diff", "--cached", "--name-only", head).splitlines()
    if not changed or len(changed) > 1500: raise RuntimeError("Unexpected checkpoint size; inspect private index")
    tree = git("write-tree")
    message = WORK / "git-checkpoint-02-message.txt"
    message.write_text("Checkpoint verified analyzer and fleet graph integration\n\n"
        "Combined immutable source02: native/frozen Fleet16 workflow and Juice Shop checks passed.\n"
        "Preserve open non-HTTP, hosted appearance, accessibility, clean-host and macOS gates.\n"
        "Local checkpoint ref only; shared checkout HEAD and index are preserved.\n", encoding="utf-8")
    commit = git("commit-tree", tree, "-p", head, "-F", str(message))
    if git("rev-parse", "HEAD") != head or (locks.sha256_file(index) if index.exists() else None) != index_before:
        raise RuntimeError("Shared HEAD/index changed; do not publish checkpoint ref")
    if locks.release_inputs(ROOT) != inputs: raise RuntimeError("Shipping sources changed during checkpoint")
    git("update-ref", ref, commit, "0" * 40)
    proof = dict(passed=True, commit=commit, ref=ref, parent=head, tree=tree, changed_files=changed,
        shared_head_preserved=git("rev-parse", "HEAD") == head,
        shared_index_preserved=(locks.sha256_file(index) if index.exists() else None) == index_before,
        source_checksums_sha256=inputs["source_checksums_sha256"], release_inputs_sha256=inputs["release_inputs_sha256"],
        scope="Local Git checkpoint of tracked worktree changes and explicit source/test/documentation scope. Runtime profiles, caches and full generated report trees excluded; no remote publication.")
    with proof_path.open("x", encoding="utf-8") as stream: json.dump(proof, stream, indent=2); stream.write("\n")
    print(json.dumps({key: proof[key] for key in ("passed", "commit", "ref", "shared_head_preserved", "shared_index_preserved")}))


if __name__ == "__main__": main()
