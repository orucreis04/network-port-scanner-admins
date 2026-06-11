"""TCP scanner orchestration primitives."""

import concurrent.futures
import socket
import time
from collections.abc import Iterable

from portscanner.models import PortResult, ScanTarget
from portscanner.services import get_service_name


MIN_WORKERS = 1
MAX_WORKERS = 500


def scan_port(host: str, port: int, timeout: float = 1.0) -> PortResult:
    """Run a TCP connect scan for one host and port."""
    start_time = time.perf_counter()
    service = get_service_name(port)

    try:
        with socket.create_connection((host, port), timeout=timeout):
            response_time_ms = _elapsed_ms(start_time)
            return PortResult(
                host=host,
                port=port,
                is_open=True,
                service=service,
                error=None,
                response_time_ms=response_time_ms,
            )
    except (socket.timeout, TimeoutError):
        error = "Connection timed out"
    except ConnectionRefusedError:
        error = "Connection refused"
    except OSError as exc:
        error = _format_socket_error(exc)

    return PortResult(
        host=host,
        port=port,
        is_open=False,
        service=service,
        error=error,
        response_time_ms=_elapsed_ms(start_time),
    )


def scan_host(
    host: str,
    ports: list[int],
    timeout: float = 1.0,
    workers: int = 100,
) -> list[PortResult]:
    """Scan multiple TCP ports for one host using a bounded thread pool."""
    safe_workers = normalize_workers(workers)
    if not ports:
        return []

    worker_count = min(safe_workers, len(ports))
    results: list[PortResult] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = {
            executor.submit(scan_port, host, port, timeout): port
            for port in ports
        }
        for future in concurrent.futures.as_completed(futures):
            port = futures[future]
            try:
                results.append(future.result())
            except Exception as exc:  # pragma: no cover - defensive guard
                results.append(_error_result(host, port, exc))

    return sorted(results, key=lambda result: result.port)


def scan_targets(
    hosts: list[str],
    ports: list[int],
    timeout: float = 1.0,
    workers: int = 100,
) -> list[PortResult]:
    """Scan multiple hosts by reusing the host-level scanner."""
    results: list[PortResult] = []
    for host in hosts:
        try:
            results.extend(scan_host(host, ports, timeout=timeout, workers=workers))
        except Exception as exc:  # pragma: no cover - defensive guard
            results.extend(_error_results(host, ports, exc))
    return results


def scan_target(target: ScanTarget) -> list[PortResult]:
    """Scan a ScanTarget instance and return port results."""
    return scan_host(target.host, target.ports)


def normalize_workers(workers: int) -> int:
    """Clamp worker count to a conservative supported range."""
    return max(MIN_WORKERS, min(workers, MAX_WORKERS))


def _elapsed_ms(start_time: float) -> float:
    """Return elapsed monotonic time in milliseconds."""
    return round((time.perf_counter() - start_time) * 1000, 3)


def _format_socket_error(exc: OSError) -> str:
    """Convert socket errors into controlled user-facing text."""
    if exc.strerror:
        return exc.strerror
    return exc.__class__.__name__


def _error_result(host: str, port: int, exc: Exception) -> PortResult:
    """Build a closed-port result for an unexpected scanner error."""
    return PortResult(
        host=host,
        port=port,
        is_open=False,
        service=get_service_name(port),
        error=f"Scanner error: {exc.__class__.__name__}",
        response_time_ms=None,
    )


def _error_results(host: str, ports: Iterable[int], exc: Exception) -> list[PortResult]:
    """Build closed-port results for a host-level scanner failure."""
    return [_error_result(host, port, exc) for port in ports]
