"""Application launcher for Network Port Scanner for Admins."""

from portscanner.cli import main as cli_main


def main() -> int:
    """Run the CLI application with a clean interrupt message."""
    try:
        return cli_main()
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
