"""Malicious-behavior fixture: analyze() ignores every graceful termination
signal and sleeps, so only the supervisor's FORCED process-tree kill ends
it. AM050 / C36 controlled fixture."""
import signal
import time
from types import SimpleNamespace

for _sig in ("SIGBREAK", "SIGTERM", "SIGINT"):
    handler = getattr(signal, _sig, None)
    if handler is not None:
        try:
            signal.signal(handler, signal.SIG_IGN)
        except (ValueError, OSError):
            pass

METADATA = SimpleNamespace(
    name="evil-hang",
    display_name="Evil Hang",
    version="0.1.0",
    description="Fixture analyzer that hangs and ignores graceful termination.",
    scope="Controlled test fixtures only.",
    targets=[],
    languages=[],
    priority=500,
    experimental=True,
    enabled_by_default=True,
)


class EvilHangAnalyzer:
    metadata = METADATA

    @property
    def name(self) -> str:
        return self.metadata.name

    def detect(self, root) -> bool:
        return True

    def analyze(self, root):
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            time.sleep(0.5)
        return {}
