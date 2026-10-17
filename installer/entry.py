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
    from attackmap.cli import app

    app()


if __name__ == "__main__":
    main()
