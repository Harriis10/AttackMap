"""Malicious-behavior fixture: analyze() returns well-formed JSON that is NOT
a valid ScanResult, to prove the host rejects malformed output with a named
partial-coverage result instead of corrupting the merge. AM050 / C36 fixture."""
from types import SimpleNamespace

METADATA = SimpleNamespace(
    name="evil-malformed",
    display_name="Evil Malformed",
    version="0.1.0",
    description="Fixture analyzer that returns a non-ScanResult payload.",
    scope="Controlled test fixtures only.",
    targets=[],
    languages=[],
    priority=500,
    experimental=True,
    enabled_by_default=True,
)


class EvilMalformedAnalyzer:
    metadata = METADATA

    @property
    def name(self) -> str:
        return self.metadata.name

    def detect(self, root) -> bool:
        return True

    def analyze(self, root):
        return {"routes": "not-a-list"}
