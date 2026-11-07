"""Well-behaved fixture analyzer: proves the isolated host round-trips valid
results. Part of the AM050 / C36 controlled malicious-behavior fixtures."""
from types import SimpleNamespace

METADATA = SimpleNamespace(
    name="good-plugin",
    display_name="Good Plugin",
    version="0.1.0",
    description="Well-behaved fixture analyzer for isolated-host tests.",
    scope="Controlled test fixtures only.",
    targets=[],
    languages=[],
    priority=500,
    experimental=True,
    enabled_by_default=True,
)


class GoodPluginAnalyzer:
    metadata = METADATA

    @property
    def name(self) -> str:
        return self.metadata.name

    def detect(self, root) -> bool:
        return True

    def analyze(self, root):
        return {"routes": [{"path": "/good", "method": "GET", "file": "app.py"}]}
