"""Tests for validator helpers."""

import pytest

from portscanner.validators import parse_ports, parse_targets, validate_host


def test_validate_host_accepts_ipv4() -> None:
    """Accept valid IP address strings."""
    assert validate_host("127.0.0.1") == "127.0.0.1"


def test_validate_host_accepts_ipv6() -> None:
    """Accept valid IPv6 address strings."""
    assert validate_host("::1") == "::1"


def test_validate_host_accepts_domain() -> None:
    """Accept valid domain strings."""
    assert validate_host("Example.COM") == "example.com"


def test_validate_host_rejects_empty_value() -> None:
    """Reject empty host values."""
    with pytest.raises(ValueError, match="cannot be empty"):
        validate_host(" ")


def test_parse_targets_accepts_single_ip() -> None:
    """Parse a single IP target."""
    assert parse_targets("192.168.1.10") == ["192.168.1.10"]


def test_parse_targets_accepts_domain() -> None:
    """Parse a domain target."""
    assert parse_targets("admin.example.com") == ["admin.example.com"]


def test_parse_targets_expands_cidr() -> None:
    """Expand CIDR targets into usable hosts."""
    assert parse_targets("192.168.1.0/30") == ["192.168.1.1", "192.168.1.2"]


def test_parse_targets_rejects_large_networks() -> None:
    """Reject CIDR ranges above the safety limit."""
    with pytest.raises(ValueError, match="1024 host safety limit"):
        parse_targets("10.0.0.0/20")


def test_parse_ports_accepts_single_port() -> None:
    """Parse a single port."""
    assert parse_ports("80") == [80]


def test_parse_ports_accepts_comma_separated_ports() -> None:
    """Parse comma-separated ports."""
    assert parse_ports("22,80,443") == [22, 80, 443]


def test_parse_ports_accepts_range() -> None:
    """Parse a port range."""
    assert parse_ports("1-3") == [1, 2, 3]


def test_parse_ports_accepts_mixed_input_and_deduplicates() -> None:
    """Parse mixed ports and ranges with duplicates removed."""
    assert parse_ports("22,80,80,8000-8002") == [22, 80, 8000, 8001, 8002]


def test_parse_ports_rejects_out_of_range_values() -> None:
    """Reject invalid TCP port values."""
    with pytest.raises(ValueError, match="between 1 and 65535"):
        parse_ports("70000")


def test_parse_ports_rejects_invalid_ranges() -> None:
    """Reject malformed or reversed ranges."""
    with pytest.raises(ValueError, match="start cannot be greater"):
        parse_ports("100-1")
