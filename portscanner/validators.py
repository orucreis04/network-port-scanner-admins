"""Input validation helpers for safe scanner usage."""

import ipaddress
import re
from itertools import islice


MAX_TARGET_HOSTS = 1024
MIN_PORT = 1
MAX_PORT = 65535
DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$"
)


def validate_host(host: str) -> str:
    """Validate and normalize an IPv4, IPv6, or domain target."""
    normalized_host = host.strip()
    if not normalized_host:
        raise ValueError(
            "Host cannot be empty. Provide an IP address, CIDR, or domain."
        )

    try:
        return str(ipaddress.ip_address(normalized_host))
    except ValueError:
        pass

    if DOMAIN_PATTERN.fullmatch(normalized_host):
        return normalized_host.rstrip(".").lower()

    raise ValueError("Host must be a valid IPv4 address, IPv6 address, or domain name.")


def parse_targets(target: str) -> list[str]:
    """Parse a single IP, CIDR network, or domain target."""
    normalized_target = target.strip()
    if not normalized_target:
        raise ValueError(
            "Target cannot be empty. Example: 127.0.0.1 or 192.168.1.0/24."
        )

    if "/" not in normalized_target:
        return [validate_host(normalized_target)]

    try:
        network = ipaddress.ip_network(normalized_target, strict=False)
    except ValueError as exc:
        raise ValueError(
            "Target CIDR notation is invalid. Example: 192.168.1.0/24."
        ) from exc

    hosts = list(islice(network.hosts(), MAX_TARGET_HOSTS + 1))
    if len(hosts) > MAX_TARGET_HOSTS:
        raise ValueError(
            f"Target network exceeds the {MAX_TARGET_HOSTS} host safety limit."
        )

    if not hosts:
        raise ValueError("Target network does not contain any usable hosts.")

    return [str(host) for host in hosts]


def parse_ports(port_input: str) -> list[int]:
    """Parse comma-separated ports and ranges into a sorted unique list."""
    normalized_input = port_input.strip()
    if not normalized_input:
        raise ValueError("Port input cannot be empty. Example: 22,80,443 or 1-100.")

    ports: set[int] = set()
    for raw_part in normalized_input.split(","):
        part = raw_part.strip()
        if not part:
            raise ValueError("Port input contains an empty item. Remove extra commas.")

        if "-" in part:
            ports.update(_parse_port_range(part))
        else:
            ports.add(_parse_single_port(part))

    return sorted(ports)


def _parse_port_range(value: str) -> range:
    """Parse one port range expression."""
    pieces = value.split("-")
    if len(pieces) != 2 or not pieces[0].strip() or not pieces[1].strip():
        raise ValueError(f"Invalid port range: {value}. Example: 8000-8010.")

    start = _parse_single_port(pieces[0].strip())
    end = _parse_single_port(pieces[1].strip())
    if start > end:
        raise ValueError(f"Port range start cannot be greater than end: {value}.")

    return range(start, end + 1)


def _parse_single_port(value: str) -> int:
    """Parse one TCP port value."""
    try:
        port = int(value)
    except ValueError as exc:
        raise ValueError(
            f"Invalid port value: {value}. Ports must be numeric."
        ) from exc

    if not MIN_PORT <= port <= MAX_PORT:
        raise ValueError(f"Port must be between {MIN_PORT} and {MAX_PORT}: {port}.")

    return port


def is_valid_ip_address(value: str) -> bool:
    """Return True when value is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def is_valid_port(port: int) -> bool:
    """Return True when port is in the valid TCP port range."""
    return MIN_PORT <= port <= MAX_PORT
