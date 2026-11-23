"""
The ``net`` grant constraint (port of packages/verify/src/net.js; spec/evaluation.md §3.10): rules
about the connection a request arrives on, rather than the place it comes from.

Everything that needs I/O (address lists, DNS answers, relay hops, a timed round trip, a customer
webhook) is resolved by the verifier first and handed in through the context, so this stays pure
and the conformance vectors stay plain JSON. ``net.server`` is validated here but not evaluated by
verifiers: it binds the device's own SDK or CLI.
"""
from __future__ import annotations

import re

from . import _js
from ._js import MISSING, get, includes, is_finite, is_object, is_safe_integer, present, truthy
from .ip import ip_in_cidr, parse_cidr, same_ip

NET_KEYS = {"client", "server"}
_DIRECTION_KEYS = {"addresses", "route", "latency"}
_ADDRESS_KEYS = {"of", "cidrs", "lists", "dns", "webhook"}
_LIST_KEYS = {"id", "uri"}
_DNS_KEYS = {"names", "dnssec"}
_ROUTE_KEYS = {"relays", "min_hops", "max_hops", "require_attested"}
_LATENCY_KEYS = {"max_rtt_ms", "samples", "reuse_s"}

NET_LIMITS = {"cidrs": 64, "lists": 8, "names": 16, "relays": 16, "maxHops": 4, "maxRttMs": 5000, "samples": 5, "maxReuse": 300, "uriLength": 512}
# fullmatch with re.ASCII: JS \d is ASCII-only and JS $ does not match before a trailing newline.
ADDRESS_LIST_ID = re.compile(r"adl_[A-Za-z0-9]{8,64}", re.ASCII)
_DEVICE_ID = re.compile(r"dev_[A-Za-z0-9]{8,64}", re.ASCII)
_GATE_ID = re.compile(r"gate_[A-Za-z0-9]{8,64}", re.ASCII)
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", re.ASCII)
_NUMERIC = re.compile(r"[0-9]+", re.ASCII)
_ROUTE_ERROR = re.compile(r"[a-z0-9_]{1,64}", re.ASCII)
# JS \s (WhiteSpace and LineTerminator), which differs from Python's Unicode \s.
_WS = "\t\n\v\f\r    -     　﻿"
# An https URL, or http on this machine's loopback for local development (a local issuer's lists).
_LIST_URI = re.compile(f"(?:https://[^{_WS}/]+|http://(?:localhost|127\\.0\\.0\\.1|\\[::1\\])(?::[0-9]{{1,5}})?)/[^{_WS}]*")


def _is_int(value, low, high) -> bool:
    return is_safe_integer(value) and low <= value <= high


def _nullish(value, default):
    """``value ?? default``."""
    return default if value is MISSING or value is None else value


def _set_size(values) -> int:
    """``new Set(values).size``: SameValueZero for JSON scalars, identity for objects and arrays."""
    seen = set()
    for v in values:
        if v is MISSING:
            seen.add(("undefined",))
        elif v is None:
            seen.add(("null",))
        elif isinstance(v, bool):
            seen.add(("bool", v))
        elif _js.is_number(v):
            seen.add(("number", 0 if v == 0 else v))
        elif isinstance(v, str):
            seen.add(("string", v))
        else:
            seen.add(("object", id(v)))
    return len(seen)


def valid_host_name(name) -> bool:
    """A lower-case DNS host name with at least two labels and a non-numeric last label."""
    if not isinstance(name, str) or _js.js_len(name) > 253:
        return False
    labels = name.split(".")
    return len(labels) >= 2 and all(_LABEL.fullmatch(label) for label in labels) and not _NUMERIC.fullmatch(labels[-1])


def _unknown_in(value, allowed, path) -> list:
    return [f"{path}.{k}" for k in _js.keys(value) if k not in allowed] if is_object(value) else []


def net_unknown_keys(net) -> list:
    """Paths of members ``net`` does not know (each becomes ``unknown_constraint:<path>``)."""
    if not is_object(net):
        return []
    paths = _unknown_in(net, NET_KEYS, "net")
    for side in ("client", "server"):
        d = get(net, side)
        p = f"net.{side}"
        paths += _unknown_in(d, _DIRECTION_KEYS, p)
        if not is_object(d):
            continue
        addresses = get(d, "addresses")
        paths += _unknown_in(addresses, _ADDRESS_KEYS, f"{p}.addresses")
        paths += _unknown_in(get(d, "route"), _ROUTE_KEYS, f"{p}.route")
        paths += _unknown_in(get(d, "latency"), _LATENCY_KEYS, f"{p}.latency")
        if is_object(addresses):
            paths += _unknown_in(get(addresses, "dns"), _DNS_KEYS, f"{p}.addresses.dns")
            lists = get(addresses, "lists")
            if isinstance(lists, list):
                for i, entry in enumerate(lists):
                    paths += _unknown_in(entry, _LIST_KEYS, f"{p}.addresses.lists[{i}]")
    return paths


def _check_list(value, path, errors, maximum, test, message) -> None:
    if not isinstance(value, list) or len(value) == 0 or len(value) > maximum:
        errors.append(f"{path} must be a list of 1–{maximum} entries")
        return
    if _set_size(value) != len(value):
        errors.append(f"{path} has duplicates")
    for i, v in enumerate(value):
        if not test(v):
            errors.append(f"{path}[{i}] {message}")


def _list_ok(entry) -> bool:
    list_id, uri = get(entry, "id"), get(entry, "uri")
    return (is_object(entry) and isinstance(list_id, str) and bool(ADDRESS_LIST_ID.fullmatch(list_id))
            and isinstance(uri, str) and _js.js_len(uri) <= NET_LIMITS["uriLength"] and bool(_LIST_URI.fullmatch(uri)))


def _validate_addresses(a, side, has_route, path, errors) -> None:
    if not is_object(a):
        errors.append(f"{path} must be an object")
        return
    of = get(a, "of")
    if of is not MISSING and not _js.strict_eq(of, "peer") and not _js.strict_eq(of, "origin"):
        errors.append(f'{path}.of must be "peer" or "origin"')
    if _js.strict_eq(of, "origin") and side == "server":
        errors.append(f"{path}.of \"origin\" is only for net.client (a device sees the server's address directly)")
    if _js.strict_eq(of, "origin") and not has_route:
        errors.append(f"{path}.of \"origin\" needs a route: the first relay records the device's address")
    if present(a, "cidrs"):
        _check_list(a["cidrs"], f"{path}.cidrs", errors, NET_LIMITS["cidrs"], lambda c: parse_cidr(c) is not None,
                    'must be a CIDR range like "203.0.113.0/24"')
    lists = get(a, "lists")
    if lists is not MISSING:
        _check_list(lists, f"{path}.lists", errors, NET_LIMITS["lists"], _list_ok, 'must be { id: "adl_…", uri: "https://…" }')
        if isinstance(lists, list) and _set_size([get(entry, "id") for entry in lists]) != len(lists):
            errors.append(f"{path}.lists names a list twice")
    dns = get(a, "dns")
    if dns is not MISSING:
        if not is_object(dns):
            errors.append(f"{path}.dns must be an object")
        else:
            _check_list(get(dns, "names"), f"{path}.dns.names", errors, NET_LIMITS["names"], valid_host_name,
                        'must be a lower-case host name like "vpn.example.com"')
            dnssec = get(dns, "dnssec")
            if dnssec is not MISSING and not isinstance(dnssec, bool):
                errors.append(f"{path}.dns.dnssec must be true or false")
    webhook = get(a, "webhook")
    if webhook is not MISSING:
        if side == "server":
            errors.append(f"{path}.webhook is only for net.client (devicebasedauth.org asks the webhook during online authorization)")
        elif not isinstance(webhook, str) or not _GATE_ID.fullmatch(webhook):
            errors.append(f'{path}.webhook must be a webhook gate id like "gate_…"')
    if not any(present(a, k) for k in ("cidrs", "lists", "dns", "webhook")):
        errors.append(f"{path} needs at least one of cidrs, lists, dns or webhook")


def _validate_route(r, path, errors) -> None:
    if not is_object(r):
        errors.append(f"{path} must be an object")
        return
    _check_list(get(r, "relays"), f"{path}.relays", errors, NET_LIMITS["relays"],
                lambda i: isinstance(i, str) and bool(_DEVICE_ID.fullmatch(i)), 'must be a relay device id like "dev_…"')
    top = NET_LIMITS["maxHops"]
    low, high = _nullish(get(r, "min_hops"), 1), _nullish(get(r, "max_hops"), top)
    if not _is_int(low, 1, top):
        errors.append(f"{path}.min_hops must be an integer 1–{top}")
    if not _is_int(high, 1, top):
        errors.append(f"{path}.max_hops must be an integer 1–{top}")
    elif _is_int(low, 1, top) and low > high:
        errors.append(f"{path}.min_hops must not exceed max_hops")
    attested = get(r, "require_attested")
    if attested is not MISSING and not isinstance(attested, bool):
        errors.append(f"{path}.require_attested must be true or false")


def _validate_latency(l, path, errors) -> None:  # noqa: E741 - mirrors the JS
    if not is_object(l):
        errors.append(f"{path} must be an object")
        return
    if not _is_int(get(l, "max_rtt_ms"), 1, NET_LIMITS["maxRttMs"]):
        errors.append(f"{path}.max_rtt_ms must be an integer 1–{NET_LIMITS['maxRttMs']}")
    samples, reuse = get(l, "samples"), get(l, "reuse_s")
    if samples is not MISSING and not _is_int(samples, 1, NET_LIMITS["samples"]):
        errors.append(f"{path}.samples must be an integer 1–{NET_LIMITS['samples']}")
    if reuse is not MISSING and not _is_int(reuse, 0, NET_LIMITS["maxReuse"]):
        errors.append(f"{path}.reuse_s must be an integer 0–{NET_LIMITS['maxReuse']}")


def validate_net(net, path: str = "grant.net") -> list:
    """Validation errors for a grant's ``net`` member (unknown members are reported by net_unknown_keys)."""
    if not is_object(net):
        return [f"{path} must be an object"]
    errors: list = []
    if not present(net, "client") and not present(net, "server"):
        errors.append(f"{path} needs client or server")
    for side in ("client", "server"):
        d = get(net, side)
        p = f"{path}.{side}"
        if d is MISSING:
            continue
        if not is_object(d):
            errors.append(f"{p} must be an object")
            continue
        if not any(present(d, k) for k in ("addresses", "route", "latency")):
            errors.append(f"{p} needs at least one of addresses, route or latency")
        if present(d, "addresses"):
            _validate_addresses(d["addresses"], side, present(d, "route"), f"{p}.addresses", errors)
        if present(d, "route"):
            _validate_route(d["route"], f"{p}.route", errors)
        if present(d, "latency"):
            _validate_latency(d["latency"], f"{p}.latency", errors)
    return errors


def check_net_client(client, context, reasons: list, online: dict) -> None:
    """
    Check ``net.client`` of a valid grant, appending reasons in the order of spec/evaluation.md §3.10.
    Sets ``online["address_webhook"]`` when only the webhook could still allow the address.
    """
    if not truthy(client):
        return
    network = get(get(context, "location"), "network")
    network = network if is_object(network) else {}
    route = get(context, "route")
    route = route if is_object(route) and isinstance(get(route, "relays"), list) else None
    addresses = get(client, "addresses")
    if truthy(addresses):
        origin = _js.strict_eq(get(addresses, "of"), "origin")
        _check_addresses(addresses, get(route, "origin") if origin else get(network, "ip"), context, reasons, online)
    r = get(client, "route")
    if truthy(r):
        route_error = get(context, "route_error")
        if route_error is not MISSING and route_error is not None:
            ok = isinstance(route_error, str) and _ROUTE_ERROR.fullmatch(route_error)
            reasons.append(f"route_invalid:{route_error if ok else 'malformed'}")
        elif route is None:
            reasons.append("route_required")
        else:
            hops = len(route["relays"])
            if hops < _nullish(get(r, "min_hops"), 1) or hops > _nullish(get(r, "max_hops"), NET_LIMITS["maxHops"]):
                reasons.append("route_invalid:hop_count")
            attested = get(route, "attested")
            if truthy(get(r, "require_attested")) and not (
                isinstance(attested, list) and len(attested) == hops and all(a is True for a in attested)
            ):
                reasons.append("route_invalid:relay_not_attested")
            if not all(includes(r["relays"], relay) for relay in route["relays"]):
                reasons.append("route_relay_not_allowed")
    latency = get(client, "latency")
    if truthy(latency):
        rtt = get(network, "rtt_ms")
        if not is_finite(rtt) or rtt < 0:
            reasons.append("rtt_required")
        elif rtt > latency["max_rtt_ms"]:
            reasons.append("rtt_exceeded")


def _check_addresses(a, address, context, reasons, online) -> None:
    if not isinstance(address, str) or address == "":
        reasons.append("address_unavailable")
        return
    lists = get(context, "address_lists")
    lists = lists if is_object(lists) else {}
    answers_dns = get(context, "dns")
    answers_dns = answers_dns if is_object(answers_dns) else {}
    dns = get(a, "dns")

    def list_of(list_id):
        entry = lists.get(list_id, MISSING)
        return entry if is_object(entry) and isinstance(get(entry, "cidrs"), list) else None

    def answer_of(name):
        entry = answers_dns.get(name, MISSING)
        return entry if is_object(entry) and isinstance(get(entry, "addrs"), list) else None

    def dns_ok(answer):
        return answer is not None and (not _js.strict_eq(get(dns, "dnssec"), True) or _js.strict_eq(get(answer, "dnssec"), True))

    def by_name(name):
        answer = answer_of(name)
        return dns_ok(answer) and any(same_ip(address, x) for x in answer["addrs"])

    def by_list(entry):
        found = list_of(entry["id"])
        return found is not None and any(ip_in_cidr(address, c) for c in found["cidrs"])

    names = _or_empty(get(dns, "names"))
    allowed = (any(ip_in_cidr(address, c) for c in _or_empty(get(a, "cidrs")))
               or any(by_list(entry) for entry in _or_empty(get(a, "lists")))
               or any(by_name(name) for name in names))
    if allowed:
        return
    webhook = get(a, "webhook")
    if truthy(webhook):
        # Only devicebasedauth.org can ask the webhook, so offline the grant becomes online-only.
        if not truthy(get(context, "online")):
            online["address_webhook"] = webhook
            return
        answers = get(context, "address_webhook")
        if is_object(answers) and answers.get(webhook, MISSING) is True:
            return
    reasons.append("address_not_allowed")
    for entry in _or_empty(get(a, "lists")):
        if list_of(entry["id"]) is None:
            reasons.append(f"address_list_unavailable:{entry['id']}")
    for name in names:
        answer = answer_of(name)
        if answer is None:
            reasons.append(f"dns_unresolved:{name}")
        elif not dns_ok(answer):
            reasons.append(f"dns_unvalidated:{name}")


def _or_empty(value):
    """``value || []`` for a member a valid grant holds as a list or not at all."""
    return value if truthy(value) else []


def _join_or(items) -> str:
    items = [_js.to_string(i) for i in items]
    return "".join(items) if len(items) <= 1 else f"{', '.join(items[:-1])} or {items[-1]}"


def _describe_addresses(a) -> str:
    sources = list(_or_empty(get(a, "cidrs")))
    for entry in _or_empty(get(a, "lists")):
        sources.append(f"the addresses in list {_js.to_string(get(entry, 'id'))}")
    dns = get(a, "dns")
    for name in _or_empty(get(dns, "names")):
        sources.append(f"the addresses of {_js.to_string(name)}{' (DNSSEC-validated)' if truthy(get(dns, 'dnssec')) else ''}")
    if truthy(get(a, "webhook")):
        sources.append(f"addresses webhook {_js.to_string(a['webhook'])} allows")
    return _join_or(sources)


def _describe_route(r) -> str:
    low, high = _nullish(get(r, "min_hops"), 1), _nullish(get(r, "max_hops"), NET_LIMITS["maxHops"])
    if _js.strict_eq(low, high):
        hops = f"{_js.to_string(low)} hop{'' if _js.strict_eq(low, 1) else 's'}"
    else:
        hops = f"{_js.to_string(low)}–{_js.to_string(high)} hops"
    relays = _or_empty(get(r, "relays"))
    attested = ", attested relays only" if truthy(get(r, "require_attested")) else ""
    return f"through relay{'s' if len(relays) > 1 else ''} {_join_or(relays)} ({hops}{attested})"


def describe_net(net) -> list:
    """Plain-English phrases for a grant's ``net`` (the parts describeGrant adds in the JS)."""
    parts: list = []
    for side in ("client", "server"):
        d = get(net, side)
        addresses, route, latency = get(d, "addresses"), get(d, "route"), get(d, "latency")
        rtt = _js.to_string(get(latency, "max_rtt_ms"))
        if side == "client":
            if truthy(addresses):
                at = "devices at " if _js.strict_eq(get(addresses, "of"), "origin") else ""
                parts.append(f"only from {at}{_describe_addresses(addresses)}")
            if truthy(route):
                parts.append(f"only {_describe_route(route)}")
            if truthy(latency):
                parts.append(f"only from a device answering within {rtt} ms")
        else:
            if truthy(addresses):
                parts.append(f"sending only to servers at {_describe_addresses(addresses)}")
            if truthy(route):
                parts.append(f"sending only {_describe_route(route)}")
            if truthy(latency):
                parts.append(f"sending only to a server answering within {rtt} ms")
    return parts

