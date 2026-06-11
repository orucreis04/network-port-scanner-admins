"""Tests for service lookup helpers."""

from portscanner.services import get_service_name


def test_get_service_name_returns_known_services() -> None:
    """Resolve common TCP service names."""
    assert get_service_name(22) == "SSH"
    assert get_service_name(80) == "HTTP"
    assert get_service_name(443) == "HTTPS"
    assert get_service_name(5432) == "PostgreSQL"
    assert get_service_name(27017) == "MongoDB"


def test_get_service_name_returns_unknown_for_unmapped_port() -> None:
    """Return Unknown for ports outside the common map."""
    assert get_service_name(65000) == "Unknown"
