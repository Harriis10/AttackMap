"""PyInstaller entry point: run attackmap.cli as a top-level script."""

import sys


def configure_redirected_stdio() -> None:
    """Pipes use the engine's UTF-8 wire format; real consoles keep OS behavior."""
    for stream in (sys.stdin, sys.stdout, sys.stderr):
        if stream is None:
            continue
        try:
            if not stream.isatty() and callable(getattr(stream, "reconfigure", None)):
                stream.reconfigure(encoding="utf-8")
        except (OSError, ValueError):
            # Closed or non-reconfigurable host streams cannot carry this wire format.
            continue


def main() -> None:
    configure_redirected_stdio()
    # The isolated analyzer supervisor uses this fixed Python-style worker
    # invocation. A frozen executable has no interpreter -m dispatcher.
    if getattr(sys, "frozen", False) and sys.argv[1:4] == [
        "-m", "attackmap.analyzer_host", "--worker",
    ]:
        from attackmap.analyzer_host import _main

        raise SystemExit(_main(sys.argv[3:]))
    from attackmap.cli import app

    app()


if __name__ == "__main__":
    main()
