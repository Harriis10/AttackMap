"""Fetch immutable public upstream sources without changing installed packages."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import urllib.error
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[5]
OUT = Path(__file__).resolve().parent
WORK = ROOT / ".tmp/wp039-sol-ultra-20261023-python/upstream-qualification"
REPOSITORY = "mlaify/attackmap-analyzer-python"
PIN = "1bcce0dd5d639cb83ada65cc3f5024bb5a1d9782"
CANDIDATE = "478208fd33b7fa30e2acbb08f184b2e289f7bb0a"


def save(path, value):
    with path.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(value, indent=2) + "\n")


def fetch(url, destination, limit, timeout=45):
    request = urllib.request.Request(url, headers={"User-Agent": "AttackMap-upstream-qualification", "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        value = response.read(limit + 1)
        if len(value) > limit:
            raise ValueError("Upstream payload exceeds qualification bound")
        with destination.open("xb") as stream:
            stream.write(value)
        return {"url": url, "resolved_url": response.url, "status": response.status,
                "headers": {key: response.headers.get(key) for key in ("Date", "ETag", "Last-Modified", "Content-Type")},
                "path": str(destination), "bytes": len(value), "sha256": hashlib.sha256(value).hexdigest()}


def archive(label, commit):
    destination = WORK / f"{label}-{commit}.zip"
    result = fetch(f"https://codeload.github.com/{REPOSITORY}/zip/{commit}", destination, 10 * 1024 * 1024, 90)
    extracted = WORK / f"{label}-{commit}"
    extracted.mkdir()
    with zipfile.ZipFile(destination) as archive:
        members = archive.infolist()
        if len(members) > 2000 or sum(member.file_size for member in members) > 20 * 1024 * 1024:
            raise ValueError("Archive extraction exceeds qualification bound")
        for member in members:
            target = (extracted / member.filename).resolve()
            if not target.is_relative_to(extracted.resolve()) or (member.external_attr >> 16) & 0o170000 == 0o120000:
                raise ValueError("Archive path or symlink is outside qualification scope")
        archive.extractall(extracted)
    roots = [path for path in extracted.iterdir() if path.is_dir()]
    assert len(roots) == 1 and roots[0].name.endswith(commit)
    result["source_root"] = str(roots[0])
    result["requested_commit"] = commit
    return result


if __name__ == "__main__":
    WORK.mkdir(parents=True, exist_ok=False)
    manifest = {"repository": REPOSITORY, "scope": "Immutable upstream source qualification only; no installation/pin change", "api": {}, "archives": {}}
    for label, ref in (("pinned", PIN), ("candidate", CANDIDATE), ("main_observed", "main")):
        url = f"https://api.github.com/repos/{REPOSITORY}/commits/{ref}"
        try:
            result = fetch(url, WORK / f"{label}-commit.json", 1024 * 1024)
            payload = json.loads(Path(result["path"]).read_text(encoding="utf-8"))
            result["commit"] = payload["sha"]
            result["message"] = payload["commit"]["message"]
            result["committed_at"] = payload["commit"]["committer"]["date"]
            manifest["api"][label] = result
        except (urllib.error.URLError, OSError, ValueError, KeyError) as exc:
            manifest["api"][label] = {"url": url, "error_type": type(exc).__name__}
    for label, commit in (("pinned", PIN), ("candidate", CANDIDATE)):
        manifest["archives"][label] = archive(label, commit)
    main = manifest["api"]["main_observed"].get("commit")
    if main and main not in {PIN, CANDIDATE}:
        manifest["archives"]["main_observed"] = archive("main-observed", main)
    save(OUT / "upstream-fetch.json", manifest)
    print(json.dumps({"archives": {key: value["source_root"] for key, value in manifest["archives"].items()}, "main_observed": main}))
