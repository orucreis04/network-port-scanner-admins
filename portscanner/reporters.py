"""Report generation helpers for scanner output."""

import csv
import json
from pathlib import Path

from rich.console import Console
from rich.table import Table

from portscanner.models import PortResult


REPORT_FIELDS = ["host", "port", "is_open", "service", "error", "response_time_ms"]


def results_to_dict(results: list[PortResult]) -> list[dict[str, object]]:
    """Convert scan results to JSON/CSV friendly dictionaries."""
    return [result.to_dict() for result in results]


def save_json_report(results: list[PortResult], output_path: str) -> None:
    """Write scan results to a JSON file."""
    path = Path(output_path)
    path.write_text(json.dumps(results_to_dict(results), indent=2), encoding="utf-8")


def save_csv_report(results: list[PortResult], output_path: str) -> None:
    """Write scan results to a CSV file."""
    rows = results_to_dict(results)
    path = Path(output_path)
    with path.open("w", newline="", encoding="utf-8") as report_file:
        writer = csv.DictWriter(report_file, fieldnames=REPORT_FIELDS)
        writer.writeheader()
        writer.writerows(rows)


def print_table(results: list[PortResult], show_closed: bool = False) -> None:
    """Print scan results in a rich terminal table."""
    visible_results = (
        results
        if show_closed
        else [result for result in results if result.is_open]
    )

    table = Table(title="Network Port Scan Results")
    table.add_column("Host", style="cyan", no_wrap=True)
    table.add_column("Port", justify="right")
    table.add_column("Status", justify="center")
    table.add_column("Service")
    table.add_column("Error")
    table.add_column("Response (ms)", justify="right")

    for result in visible_results:
        status = (
            "[bold green]OPEN[/bold green]"
            if result.is_open
            else "[dim]closed[/dim]"
        )
        table.add_row(
            result.host,
            str(result.port),
            status,
            result.service or "Unknown",
            result.error or "",
            "" if result.response_time_ms is None else f"{result.response_time_ms:.3f}",
        )

    Console().print(table)
