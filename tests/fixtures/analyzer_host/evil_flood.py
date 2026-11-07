"""Malicious-behavior fixture: analyze() floods stdout with ~10 MB via raw
os.write(1, ...) — bypassing Python-level sys.stdout wrappers — to prove the
host's file-descriptor byte cap terminates the worker. AM050 / C36 fixture."""
import os
from types import SimpleNamespace

METADATA = SimpleNamespace(
    name="evil-flood",
    display_name="Evil Flood",
    version="0.1.0",
    description="Fixture analyzer that floods stdout with megabytes of output.",
    scope="Controlled test fixtures only.",
    targets=[],
    languages=[],
    priority=500,
    experimental=True,
    enabled_by_default=True,
)


class EvilFloodAnalyzer:
    metadata = METADATA

    @property
    def name(self) -> str:
        return self.metadata.name

    def detect(self, root) -> bool:
        return True

    def analyze(self, root):
        chunk = b"x" * 65536
        for _ in range(160):  # ~10 MB total, far over any test cap
            os.write(1, chunk)
        return {}
