"""
IPv4 and IPv6 addresses and CIDR ranges (port of packages/verify/src/ip.js), shared by
``where.networks`` and the ``net`` constraint (spec/evaluation.md §3.4, §3.10). Address families
never match each other.
"""
from __future__ import annotations

import re


def parse_ip(ip):
    """
    Parse an IPv4 or IPv6 address to (bits, value), or None.

    This is the JS parser, not ``ipaddress``: the two disagree on inputs a client controls
    (``ipaddress`` rejects IPv4 octets with leading zeros and accepts IPv6 ``%zone`` suffixes),
    and a CIDR check must give the same answer in every implementation.
    """
    if not isinstance(ip, str):
        return None
    if re.fullmatch(r"[0-9]{1,3}(?:\.[0-9]{1,3}){3}", ip, re.ASCII):
        parts = [int(p) for p in ip.split(".")]
        if any(p > 255 for p in parts):
            return None
        value = 0
        for p in parts:
            value = (value << 8) + p
        return 32, value
    if not re.fullmatch(r"[0-9a-fA-F:.]+", ip, re.ASCII) or ":" not in ip:
        return None
    address = ip
    v4 = re.search(r"([0-9]{1,3}(?:\.[0-9]{1,3}){3})\Z", address, re.ASCII)
    if v4:
        parsed = parse_ip(v4.group(1))
        if not parsed:
            return None
        address = address[: -len(v4.group(1))] + format(parsed[1] >> 16, "x") + ":" + format(parsed[1] & 0xFFFF, "x")
    halves = address.split("::")
    if len(halves) > 2:
        return None
    head = halves[0].split(":") if halves[0] else []
    tail = halves[1].split(":") if len(halves) == 2 and halves[1] else []
    missing = 8 - len(head) - len(tail)
    if (len(halves) == 1 and missing != 0) or missing < 0:
        return None
    groups = head + ["0"] * (missing if len(halves) == 2 else 0) + tail
    if len(groups) != 8 or any(not re.fullmatch(r"[0-9a-fA-F]{1,4}", g, re.ASCII) for g in groups):
        return None
    value = 0
    for g in groups:
        value = (value << 16) + int(g, 16)
    return 128, value


def parse_cidr(cidr):
    """Parse a CIDR range to (bits, value, prefix), or None when invalid. Host bits may be set."""
    if not isinstance(cidr, str):
        return None
    parts = cidr.split("/")
    if len(parts) != 2 or not re.fullmatch(r"[0-9]{1,3}", parts[1], re.ASCII):
        return None
    parsed = parse_ip(parts[0])
    prefix = int(parts[1])
    if not parsed or prefix > parsed[0]:
        return None
    return parsed[0], parsed[1], prefix


def ip_in_cidr(ip, cidr) -> bool:
    """True when ip is inside the CIDR range. Address families never match each other."""
    address = parse_ip(ip)
    network = parse_cidr(cidr)
    if not address or not network or address[0] != network[0]:
        return False
    shift = network[0] - network[2]
    return (address[1] >> shift) == (network[1] >> shift)


def same_ip(a, b) -> bool:
    """True when two strings are the same address, however each is written ("2001:db8::1", "2001:DB8:0::1")."""
    x = parse_ip(a)
    y = parse_ip(b)
    return bool(x and y) and x[0] == y[0] and x[1] == y[1]
