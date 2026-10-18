"""Admin CLI (synthetic fixture)."""
from __future__ import annotations

import argparse


def main() -> None:
    parser = argparse.ArgumentParser(prog="orders-admin")
    parser.add_argument("--tenant", default="public")
    args = parser.parse_args()
    print(f"tenant={args.tenant}")


if __name__ == "__main__":
    main()
