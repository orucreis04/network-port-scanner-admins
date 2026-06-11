"""Tests for report generation helpers."""

import csv
import json
from pathlib import Path

from portscanner.models import PortResult
from portscanner.reporters import results_to_dict, save_csv_report, save_json_report


def sample_results() -> list[PortResult]:
    """Return sample scanner results."""
    return [
        PortResult(
            host="127.0.0.1",
            port=22,
            is_open=True,
            service="SSH",
            error=None,
            response_time_ms=1.5,
        ),
        PortResult(
            host="127.0.0.1",
            port=80,
            is_open=False,
            service="HTTP",
            error="Connection refused",
            response_time_ms=2.25,
        ),
    ]


def test_results_to_dict() -> None:
    """Convert scan results to serializable dictionaries."""
    assert results_to_dict(sample_results()) == [
        {
            "host": "127.0.0.1",
            "port": 22,
            "is_open": True,
            "service": "SSH",
            "error": None,
            "response_time_ms": 1.5,
        },
        {
            "host": "127.0.0.1",
            "port": 80,
            "is_open": False,
            "service": "HTTP",
            "error": "Connection refused",
            "response_time_ms": 2.25,
        },
    ]


def test_save_json_report(tmp_path: Path) -> None:
    """Write scan results as UTF-8 JSON."""
    output_path = tmp_path / "report.json"

    save_json_report(sample_results(), str(output_path))

    saved_data = json.loads(output_path.read_text(encoding="utf-8"))

    assert saved_data == results_to_dict(sample_results())
    assert output_path.read_text(encoding="utf-8").startswith("[\n  {")


def test_save_csv_report(tmp_path: Path) -> None:
    """Write scan results as CSV with expected fields."""
    output_path = tmp_path / "report.csv"

    save_csv_report(sample_results(), str(output_path))

    with output_path.open(encoding="utf-8", newline="") as csv_file:
        rows = list(csv.DictReader(csv_file))

    assert rows == [
        {
            "host": "127.0.0.1",
            "port": "22",
            "is_open": "True",
            "service": "SSH",
            "error": "",
            "response_time_ms": "1.5",
        },
        {
            "host": "127.0.0.1",
            "port": "80",
            "is_open": "False",
            "service": "HTTP",
            "error": "Connection refused",
            "response_time_ms": "2.25",
        },
    ]
