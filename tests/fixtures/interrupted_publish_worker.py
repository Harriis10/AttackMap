"""Real-OS interrupted-write harness for the artifact publisher.

Run only from tests/test_artifact_publisher.py. Stages a complete
generation into ``BASE/RUN_ID``, performs a real publication, and holds
at a controlled point so the parent test can terminate this process and
inspect what a killed run leaves on the actual filesystem.

usage: python interrupted_publish_worker.py BASE RUN_ID MODE TARGET MARKER

modes:
    midwrite   hold with TARGET half-written on disk: the flushed bytes
               are the genuine first half of the publication write. TARGET
               is a file name, or "pointer" for the ``.current-*.tmp``
               commit file.
    precommit  hold at the publisher's before_commit boundary, after the
               pointer tmp is written and fsynced but before the swap.
"""
import sys
import time
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TESTS_DIR))

from artifact_fixture import write_generation  # noqa: E402
from attackmap import artifact_publisher  # noqa: E402


def hold(marker: Path) -> None:
    marker.write_text("hold", encoding="utf-8")
    while True:
        time.sleep(1)


def main() -> int:
    base = Path(sys.argv[1])
    run_id, mode, target = sys.argv[2], sys.argv[3], sys.argv[4]
    marker = Path(sys.argv[5])
    write_generation(base / run_id)
    if mode == "midwrite":
        real = artifact_publisher.safe_write_text

        def torn(out, path, text):
            if path.name == target or (target == "pointer" and path.name.startswith(".current-")):
                real(out, path, text[: len(text) // 2])
                hold(marker)
            else:
                real(out, path, text)

        artifact_publisher.safe_write_text = torn
        artifact_publisher.publish_generation(base, run_id)
    elif mode == "precommit":
        def boundary(name):
            if name == "before_commit":
                hold(marker)

        artifact_publisher.publish_generation(base, run_id, boundary=boundary)
    else:
        raise SystemExit(f"unknown mode: {mode}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
