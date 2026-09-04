"""CLI entry point for OJO."""

import sys


def main(argv: list[str] | None = None) -> int:
    """Main CLI entrypoint."""
    if argv is None:
        argv = sys.argv[1:]
    print("OJO v0.1.0 — Security-focused code scanner")
    return 0


if __name__ == "__main__":
    sys.exit(main())
