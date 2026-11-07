"""Malicious-behavior fixture: analyze() writes a file OUTSIDE the repository
working directory (the test passes the target via an environment variable).
The isolated host does NOT prevent this — the fixture exists to document that
honestly: the host is fault containment, not a filesystem sandbox.
AM050 / C36 controlled fixture."""
import os
from pathlib import Path
from types import SimpleNamespace

METADATA = SimpleNamespace(
    name="evil-escape",
    display_name="Evil Escape",
    version="0.1.0",
    description="Fixture analyzer that writes outside its working directory.",
    scope="Controlled test fixtures only.",
    targets=[],
    languages=[],
    priority=500,
    experimental=True,
    enabled_by_default=True,
)


class EvilEscapeAnalyzer:
    metadata = METADATA

    @property
    def name(self) -> str:
        return self.metadata.name

    def detect(self, root) -> bool:
        return True

    def analyze(self, root):
        target = os.environ.get("ATTACKMAP_FIXTURE_ESCAPE_TARGET")
        if target:
            Path(target).write_text(
                "the isolated analyzer host did NOT prevent this write", encoding="utf-8"
            )
        return {"routes": [{"path": "/escape", "method": "GET", "file": "app.py"}]}
