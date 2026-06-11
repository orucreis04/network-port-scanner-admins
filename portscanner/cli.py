"""Command-line interface entry point for the port scanner."""

import argparse
import time

from rich.console import Console

from portscanner.models import PortResult, ScanSummary
from portscanner.reporters import print_table, save_csv_report, save_json_report
from portscanner.scanner import normalize_workers, scan_targets
from portscanner.validators import parse_ports, parse_targets


console = Console()
VERSION = "0.1.0"


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="network-port-scanner-admins",
        description="Safe TCP port scanner CLI for authorized local/admin use.",
    )
    parser.add_argument(
        "--target",
        "-t",
        required=True,
        help="Authorized IP address, CIDR range, or domain to scan.",
    )
    parser.add_argument(
        "--ports",
        "-p",
        required=True,
        help="Comma-separated TCP ports or ranges, for example: 22,80,8000-8010.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="Socket timeout per TCP connection attempt in seconds. Default: 1.0.",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=100,
        help="Maximum worker threads per host, clamped to 1-500. Default: 100.",
    )
    parser.add_argument("--json", help="Optional JSON report output path.")
    parser.add_argument("--csv", help="Optional CSV report output path.")
    parser.add_argument(
        "--show-closed",
        action="store_true",
        help="Show closed ports in the terminal table.",
    )
    parser.add_argument(
        "--only-open",
        action="store_true",
        help="Only process open ports in terminal and file reports.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {VERSION}",
    )
    return parser


def main() -> int:
    """Run the CLI."""
    parser = build_parser()
    args = parser.parse_args()

    try:
        _validate_runtime_options(args.timeout)
        console.print(
            "[yellow]Notice:[/yellow] "
            "Use only on systems you own or have explicit permission to test."
        )

        hosts = parse_targets(args.target)
        ports = parse_ports(args.ports)
        effective_workers = normalize_workers(args.workers)

        console.print(
            f"[bold]Scan[/bold]: hosts={len(hosts)}, ports={len(ports)}, "
            f"timeout={args.timeout}s, workers={effective_workers}"
        )

        start_time = time.perf_counter()
        results = scan_targets(
            hosts,
            ports,
            timeout=args.timeout,
            workers=effective_workers,
        )
        duration_seconds = time.perf_counter() - start_time

        report_results = _filter_results(results, only_open=args.only_open)
        show_closed = args.show_closed and not args.only_open
        displayed_results = _filter_visible_results(
            report_results,
            show_closed=show_closed,
        )
        print_table(report_results, show_closed=show_closed)

        if args.json:
            save_json_report(report_results, args.json)
            console.print(f"JSON report saved: {args.json}")

        if args.csv:
            save_csv_report(report_results, args.csv)
            console.print(f"CSV report saved: {args.csv}")

        summary = _build_summary(hosts, ports, results, duration_seconds)
        _print_summary(summary, displayed_count=len(displayed_results))
        return 0
    except ValueError as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        return 2
    except OSError as exc:
        console.print(f"[bold red]File error:[/bold red] {exc}")
        return 3
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user.[/yellow]")
        return 130
    except Exception as exc:  # pragma: no cover - final CLI safety net
        console.print(
            f"[bold red]Unexpected error:[/bold red] {exc.__class__.__name__}"
        )
        return 1


def _validate_runtime_options(timeout: float) -> None:
    """Validate CLI runtime options before scanning."""
    if timeout <= 0:
        raise ValueError("Timeout must be greater than 0 seconds.")


def _filter_results(results: list[PortResult], only_open: bool) -> list[PortResult]:
    """Filter report results according to CLI output options."""
    if only_open:
        return [result for result in results if result.is_open]
    return results


def _filter_visible_results(
    results: list[PortResult],
    show_closed: bool,
) -> list[PortResult]:
    """Filter results that are visible in the terminal table."""
    if show_closed:
        return results
    return [result for result in results if result.is_open]


def _build_summary(
    hosts: list[str],
    ports: list[int],
    results: list[PortResult],
    duration_seconds: float,
) -> ScanSummary:
    """Build a summary for a completed CLI scan."""
    open_ports = sum(1 for result in results if result.is_open)
    return ScanSummary(
        total_hosts=len(hosts),
        total_ports_scanned=len(hosts) * len(ports),
        open_ports=open_ports,
        closed_ports=len(results) - open_ports,
        duration_seconds=round(duration_seconds, 3),
    )


def _print_summary(summary: ScanSummary, displayed_count: int) -> None:
    """Print a concise scan summary."""
    console.print(
        "[bold]Done[/bold]: "
        f"open={summary.open_ports}, "
        f"closed={summary.closed_ports}, "
        f"total={summary.total_ports_scanned}, "
        f"displayed={displayed_count}, "
        f"duration={summary.duration_seconds:.3f}s"
    )
