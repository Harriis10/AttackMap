"""Malicious-behavior fixture: analyze() tries to allocate ~1.5 GB, to prove
the Windows Job Object commit cap terminates the worker. AM050 / C36 fixture."""
from types import SimpleNamespace

METADATA = SimpleNamespace(
    name="evil-memory",
    display_name="Evil Memory",
    version="0.1.0",
    description="Fixture analyzer that exhausts memory.",
    scope="Controlled test fixtures only.",
    targets=[],
    languages=[],
    priority=500,
    experimental=True,
    enabled_by_default=True,
)


class EvilMemoryAnalyzer:
    metadata = METADATA

    @property
    def name(self) -> str:
        return self.metadata.name

    def detect(self, root) -> bool:
        return True

    def analyze(self, root):
        blocks = []
        chunk = bytearray(16 * 1024 * 1024)  # touched (zero-filled) memory
        for _ in range(96):  # up to ~1.5 GB; the job cap should stop it first
            blocks.append(bytearray(chunk))
        return {}
