"""Data models used by the port scanner."""

from dataclasses import asdict, dataclass


@dataclass(slots=True)
class ScanTarget:
    """Authorized scan target and TCP ports."""

    host: str
    ports: list[int]

    def to_dict(self) -> dict[str, object]:
        """Return a serializable dictionary representation."""
        return asdict(self)


@dataclass(slots=True)
class PortResult:
    """Single TCP port scan result."""

    host: str
    port: int
    is_open: bool
    service: str | None
    error: str | None
    response_time_ms: float | None

    def to_dict(self) -> dict[str, object]:
        """Return a serializable dictionary representation."""
        return asdict(self)


@dataclass(slots=True)
class ScanSummary:
    """Aggregate metrics for a completed scan."""

    total_hosts: int
    total_ports_scanned: int
    open_ports: int
    closed_ports: int
    duration_seconds: float

    def to_dict(self) -> dict[str, object]:
        """Return a serializable dictionary representation."""
        return asdict(self)
