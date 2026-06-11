"""Tests for TCP scanner helpers."""

import socket
from types import TracebackType
from typing import Any

import pytest

from portscanner.models import PortResult
from portscanner.scanner import scan_host, scan_port, scan_targets


class DummyConnection:
    """Context manager used to fake successful socket connections."""

    def __enter__(self) -> "DummyConnection":
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        return None


def test_scan_port_returns_open_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Return an open result when TCP connection succeeds."""

    def fake_create_connection(
        address: tuple[str, int],
        timeout: float,
    ) -> DummyConnection:
        assert address == ("127.0.0.1", 80)
        assert timeout == 1.0
        return DummyConnection()

    monkeypatch.setattr(socket, "create_connection", fake_create_connection)

    result = scan_port("127.0.0.1", 80)

    assert result.host == "127.0.0.1"
    assert result.port == 80
    assert result.is_open is True
    assert result.service == "HTTP"
    assert result.error is None
    assert result.response_time_ms is not None


def test_scan_port_returns_closed_result_on_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Return a closed result when TCP connection times out."""

    def fake_create_connection(
        address: tuple[str, int],
        timeout: float,
    ) -> DummyConnection:
        raise socket.timeout

    monkeypatch.setattr(socket, "create_connection", fake_create_connection)

    result = scan_port("127.0.0.1", 443)

    assert result.is_open is False
    assert result.service == "HTTPS"
    assert result.error == "Connection timed out"
    assert result.response_time_ms is not None


def test_scan_port_returns_closed_result_on_connection_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Return a closed result when TCP connection is refused."""

    def fake_create_connection(
        address: tuple[str, int],
        timeout: float,
    ) -> DummyConnection:
        raise ConnectionRefusedError

    monkeypatch.setattr(socket, "create_connection", fake_create_connection)

    result = scan_port("127.0.0.1", 22)

    assert result.host == "127.0.0.1"
    assert result.port == 22
    assert result.is_open is False
    assert result.service == "SSH"
    assert result.error == "Connection refused"
    assert result.response_time_ms is not None


def test_scan_host_scans_ports_with_bounded_workers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Scan multiple ports and clamp aggressive worker values."""
    calls: list[int] = []

    def fake_scan_port(host: str, port: int, timeout: float = 1.0) -> PortResult:
        calls.append(port)
        return PortResult(
            host=host,
            port=port,
            is_open=port == 22,
            service="SSH" if port == 22 else "HTTP",
            error=None,
            response_time_ms=1.0,
        )

    monkeypatch.setattr("portscanner.scanner.scan_port", fake_scan_port)

    results = scan_host("127.0.0.1", [80, 22], workers=999)

    assert sorted(calls) == [22, 80]
    assert [result.port for result in results] == [22, 80]
    assert [result.is_open for result in results] == [True, False]


def test_scan_targets_uses_scan_host_for_each_host(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Scan each host through the host-level scanner."""

    def fake_scan_host(
        host: str,
        ports: list[int],
        timeout: float = 1.0,
        workers: int = 100,
    ) -> list[PortResult]:
        return [
            PortResult(
                host=host,
                port=ports[0],
                is_open=True,
                service="SSH",
                error=None,
                response_time_ms=1.0,
            )
        ]

    monkeypatch.setattr("portscanner.scanner.scan_host", fake_scan_host)

    results = scan_targets(["127.0.0.1", "::1"], [22])

    assert [result.host for result in results] == ["127.0.0.1", "::1"]


def test_scan_targets_converts_host_level_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Convert unexpected host-level errors into PortResult entries."""

    def fake_scan_host(*args: Any, **kwargs: Any) -> list[PortResult]:
        raise RuntimeError("boom")

    monkeypatch.setattr("portscanner.scanner.scan_host", fake_scan_host)

    results = scan_targets(["127.0.0.1"], [22, 80])

    assert [result.port for result in results] == [22, 80]
    assert all(result.is_open is False for result in results)
    assert all(result.error == "Scanner error: RuntimeError" for result in results)
