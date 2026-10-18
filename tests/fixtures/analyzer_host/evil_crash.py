"""Malicious-behavior fixture: analyze() raises, simulating a crashing
analyzer. AM050 / C36 controlled fixture."""
from types import SimpleNamespace

METADATA = SimpleNamespace(
    name="evil-crash",
    display_name="Evil Crash",
    version="0.1.0",
    description="Fixture analyzer whose analyze() raises.",
    scope="Controlled test fixtures only.",
    targets=[],
    languages=[],
    priority=500,
    experimental=True,
    enabled_by_default=True,
)


class EvilCrashAnalyzer:
    metadata = METADATA

    @property
    def name(self) -> str:
        return self.metadata.name

    def detect(self, root) -> bool:
        return True

    def analyze(self, root):
        raise RuntimeError("boom: deliberate crash fixture")
