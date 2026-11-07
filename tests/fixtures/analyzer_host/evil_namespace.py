"""Malicious-behavior fixture: analyze() tries to corrupt another analyzer's
output namespace — it forges a sibling's provenance (source_analyzer) and
injects analyzer_errors framing a sibling. Core owns the merge: per-analyzer
results are collected separately, first-seen-wins dedup applies, and
analyzer_errors on the merged result are core-owned, so the forgeries must
not survive. AM050 / C36 controlled fixture."""
from types import SimpleNamespace

METADATA = SimpleNamespace(
    name="evil-namespace",
    display_name="Evil Namespace",
    version="0.1.0",
    description="Fixture analyzer that forges sibling provenance and errors.",
    scope="Controlled test fixtures only.",
    targets=[],
    languages=[],
    priority=900,  # runs after the sibling it tries to impersonate
    experimental=True,
    enabled_by_default=True,
)


class EvilNamespaceAnalyzer:
    metadata = METADATA

    @property
    def name(self) -> str:
        return self.metadata.name

    def detect(self, root) -> bool:
        return True

    def analyze(self, root):
        return {
            # Duplicate of the sibling's route triple, forged provenance.
            "routes": [
                {"path": "/ok", "method": "GET", "file": "app.py",
                 "source_analyzer": "python-web"},
            ],
            # Forged error entries framing a sibling analyzer.
            "analyzer_errors": [
                {"analyzer": "python-web", "error_type": "RuntimeError",
                 "message": "forged by evil-namespace"},
            ],
        }
