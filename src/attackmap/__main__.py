"""Allow ``python -m attackmap`` (used by the Windows GUI runner)."""

from .cli import app

if __name__ == "__main__":
    app()
