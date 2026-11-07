"""Deterministic UI stress fixture; never security-analysis evidence."""
import hashlib
import json
from pathlib import Path

path = Path(__file__).parent / "fixtures" / "findings.json"
path.parent.mkdir(exist_ok=True)
findings = [
    {
        "Id": f"synthetic-{i:05}",
        "Title": f"Synthetic authorization review {i:05}",
        "Severity": ("high", "medium", "low")[i % 3],
        "Basis": ("observed", "inferred")[i % 2],
        "Confidence": ("high", "medium")[i % 2],
        "Source": f"synthetic/services/service-{i % 100}/route.ts:{i % 500 + 1}",
        "Evidence": "Synthetic route signal; no real repository was analyzed.",
        "Recommendation": "Confirm authorization at the service boundary and add a focused regression test.",
    }
    for i in range(10000)
]
path.write_bytes((json.dumps(findings, ensure_ascii=False, separators=(",", ":")) + "\n").encode())
digest = hashlib.sha256(path.read_bytes()).hexdigest()
(path.parent / "findings.sha256").write_text(f"{digest}  findings.json\n", encoding="ascii")
print(f"{len(findings)} synthetic findings; {path.stat().st_size} bytes; sha256 {digest}")
