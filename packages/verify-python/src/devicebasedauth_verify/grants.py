"""
Grant vocabulary v1: validation and evaluation (port of packages/verify/src/grants.js).

The normative description is spec/evaluation.md and every case in spec/vectors/evaluation.json
must pass. The evaluator is deliberately deny-by-default: a grant with a member this version does
not understand fails as a whole, because ignoring an unknown restriction would widen access.
"""
from __future__ import annotations

import functools
import math
import os
import re
from datetime import datetime, timedelta, timezone

import zoneinfo

from . import _js
from ._js import MISSING, get, includes, is_finite, is_object, is_safe_integer, present, truthy

VOCABULARY_VERSION = 1
DAYS = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"]
USE_PERIODS = ["minute", "hour", "day", "month", "total"]
PERIOD_SECONDS = {"minute": 60, "hour": 3600, "day": 86400, "month": 2592000}
GRANT_KEYS = {"actions", "resources", "when", "where", "limits", "require"}
WHEN_KEYS = {"tz", "windows", "not_before", "not_after"}
WINDOW_KEYS = {"days", "from", "to"}
WHERE_KEYS = {"source", "countries", "regions", "areas", "networks"}
AREA_KEYS = {"lat", "lon", "radius_m"}
LIMIT_KEYS = {"uses", "spend_usd_per_month"}
USES_KEYS = {"count", "per"}
REQUIRE_KEYS = {"online", "step_up"}
LIMITS = {"grants": 32, "actions": 64, "resources": 64, "windows": 16, "places": 64, "networks": 64, "resourceLength": 256}
DEVICE_LOCATION_MAX_AGE = 300

# re.ASCII and fullmatch: JS \d is ASCII-only and JS $ does not match before a trailing newline.
ACTION = re.compile(r"[a-z0-9-]{1,32}(?::[a-z0-9_.-]{1,64})*:(?:[a-z0-9_.-]{1,64}|\*)", re.ASCII)
TIME = re.compile(r"(?:[01][0-9]|2[0-3]):[0-5][0-9]|24:00", re.ASCII)
COUNTRY = re.compile(r"[A-Z]{2}", re.ASCII)
REGION = re.compile(r"[A-Z]{2}-[A-Z0-9]{1,3}", re.ASCII)
# ECMA-402 accepts UTC offsets as time zones ("+05:30", "-08", "+0530"; U+2212 too).
OFFSET_ZONE = re.compile("([+\\-−])([01][0-9]|2[0-3])(?::?([0-5][0-9]))?", re.ASCII)


# Files in a tz database directory that are not zones, and that ICU (hence JS Intl) rejects.
_NOT_ZONES = {"factory", "localtime", "posixrules"}


def _zone_links():
    """(alias, target) pairs from tzdata.zi, which also lists the "backward" links (US/Pacific,
    Asia/Calcutta, …). Some distributions ship those links only there, not as files, while ICU
    always accepts them."""
    sources = [os.path.join(path, "tzdata.zi") for path in zoneinfo.TZPATH]
    try:
        import importlib.resources
        sources.append(importlib.resources.files("tzdata").joinpath("zoneinfo", "tzdata.zi"))
    except Exception:
        pass
    for source in sources:
        try:
            with open(source, encoding="utf-8") as handle:
                for line in handle:
                    if line.startswith("L "):
                        parts = line.split()
                        if len(parts) >= 3:
                            yield parts[2], parts[1]
        except Exception:
            continue


@functools.lru_cache(maxsize=1)
def _zone_names() -> dict:
    """Lower-case name → loadable zone key. Intl matches IANA names case-insensitively."""
    names: dict = {}
    try:
        names.update((name.lower(), name) for name in zoneinfo.available_timezones())
    except Exception:  # pragma: no cover - no tz database at all
        pass
    for alias, target in _zone_links():
        names.setdefault(alias.lower(), target)
    for name in _NOT_ZONES:
        names.pop(name, None)
    return names


@functools.lru_cache(maxsize=512)
def _zone(tz: str):
    offset = OFFSET_ZONE.fullmatch(tz)
    if offset:
        sign = 1 if offset.group(1) == "+" else -1
        return timezone(sign * timedelta(hours=int(offset.group(2)), minutes=int(offset.group(3) or 0)))
    key = _zone_names().get(tz.lower())
    if key is None:
        raise ValueError(f"unknown time zone {tz!r}")
    return zoneinfo.ZoneInfo(key)


def valid_time_zone(tz) -> bool:
    """True when the IANA zone (or UTC offset) is known to this runtime."""
    if not isinstance(tz, str) or tz == "":
        return False
    try:
        _zone(tz)
        return True
    except Exception:
        return False


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


def distance_meters(a, b) -> float:
    """Great-circle (haversine) distance in meters on the mean Earth radius."""
    rad = math.radians
    r = 6371008.8
    d_lat = rad(b["lat"] - a["lat"])
    d_lon = rad(b["lon"] - a["lon"])
    h = math.sin(d_lat / 2) ** 2 + math.cos(rad(a["lat"])) * math.cos(rad(b["lat"])) * math.sin(d_lon / 2) ** 2
    return 2 * r * math.asin(min(1, math.sqrt(h)))


def action_matches(pattern, action) -> bool:
    """Does an action pattern (exact, or ending in ":*") match an action?"""
    if _js.strict_eq(pattern, action):
        return True
    return isinstance(pattern, str) and isinstance(action, str) and pattern.endswith(":*") and action.startswith(pattern[:-1])


def resource_matches(pattern, resource) -> bool:
    """Does a resource pattern ("*", "prefix*" or exact) match a resource? No resource matches only "*"."""
    if pattern == "*":
        return True
    if not isinstance(resource, str):
        return False
    if pattern.endswith("*"):
        return resource.startswith(pattern[:-1])
    return pattern == resource


def action_namespace(action: str) -> str:
    """The namespace of an action ("hashbin" for "hashbin:content:write")."""
    return action.split(":")[0]


def _check_keys(value, allowed, path, errors) -> bool:
    if not is_object(value):
        errors.append(f"{path} must be an object")
        return False
    for key in _js.keys(value):
        if key not in allowed:
            errors.append(f"{path}.{key} is not a known constraint")
    return True


def _check_string_list(value, path, errors, maximum, test, message):
    if not isinstance(value, list) or len(value) == 0 or len(value) > maximum:
        errors.append(f"{path} must be a list of 1–{maximum} entries")
        return
    for i, item in enumerate(value):
        if not isinstance(item, str) or not test(item):
            errors.append(f"{path}[{i}] {message}")


def _time_ok(value) -> bool:
    # Window times must be strings: ["08:00"] is invalid (as in the JS evaluator).
    return isinstance(value, str) and bool(TIME.fullmatch(value))


def validate_grant(grant, path: str = "grant") -> list:
    """
    Validate one grant. Returns a list of human-readable problems (empty when valid).
    Issuers reject anything invalid; verifiers deny grants with unknown constraints.
    """
    errors: list = []
    if not _check_keys(grant, GRANT_KEYS, path, errors):
        return errors
    _check_string_list(get(grant, "actions"), f"{path}.actions", errors, LIMITS["actions"], lambda a: bool(ACTION.fullmatch(a)),
                       'must look like "namespace:verb" or "namespace:*"')
    if present(grant, "resources"):
        n = LIMITS["resourceLength"]
        _check_string_list(grant["resources"], f"{path}.resources", errors, LIMITS["resources"], lambda r: 0 < _js.js_len(r) <= n,
                           f"must be 1–{n} characters")
    if present(grant, "when") and _check_keys(grant["when"], WHEN_KEYS, f"{path}.when", errors):
        when = grant["when"]
        tz, windows, nb, na = get(when, "tz"), get(when, "windows"), get(when, "not_before"), get(when, "not_after")
        if windows is not MISSING:
            if not valid_time_zone(tz):
                errors.append(f"{path}.when.tz must be an IANA time zone when windows are given")
            if not isinstance(windows, list) or len(windows) == 0 or len(windows) > LIMITS["windows"]:
                errors.append(f"{path}.when.windows must be a list of 1–{LIMITS['windows']} windows")
            else:
                for i, w in enumerate(windows):
                    wp = f"{path}.when.windows[{i}]"
                    if not _check_keys(w, WINDOW_KEYS, wp, errors):
                        continue
                    days = get(w, "days")
                    if days is not MISSING and (not isinstance(days, list) or len(days) == 0 or any(not includes(DAYS, d) for d in days)):
                        errors.append(f"{wp}.days must list days from {', '.join(DAYS)}")
                    if not _time_ok(get(w, "from")) or _js.strict_eq(get(w, "from"), "24:00"):
                        errors.append(f"{wp}.from must be HH:MM (00:00–23:59)")
                    if not _time_ok(get(w, "to")):
                        errors.append(f"{wp}.to must be HH:MM (00:00–24:00)")
                    if _js.strict_eq(get(w, "from"), get(w, "to")):
                        errors.append(f"{wp} from and to must differ")
        elif tz is not MISSING and not valid_time_zone(tz):
            errors.append(f"{path}.when.tz must be an IANA time zone")
        for key, value in (("not_before", nb), ("not_after", na)):
            if value is not MISSING and not is_safe_integer(value):
                errors.append(f"{path}.when.{key} must be a NumericDate (seconds)")
        if is_safe_integer(nb) and is_safe_integer(na) and nb >= na:
            errors.append(f"{path}.when.not_before must be earlier than not_after")
    if present(grant, "where") and _check_keys(grant["where"], WHERE_KEYS, f"{path}.where", errors):
        w = grant["where"]
        if not includes(["network", "device", "both"], get(w, "source")):
            errors.append(f'{path}.where.source must be "network", "device" or "both"')
        if present(w, "countries"):
            _check_string_list(w["countries"], f"{path}.where.countries", errors, LIMITS["places"], lambda c: bool(COUNTRY.fullmatch(c)),
                               'must be an ISO 3166-1 alpha-2 code like "US"')
        if present(w, "regions"):
            _check_string_list(w["regions"], f"{path}.where.regions", errors, LIMITS["places"], lambda r: bool(REGION.fullmatch(r)),
                               'must be an ISO 3166-2 code like "US-MO"')
        if present(w, "areas"):
            areas = w["areas"]
            if not isinstance(areas, list) or len(areas) == 0 or len(areas) > LIMITS["places"]:
                errors.append(f"{path}.where.areas must be a list of 1–{LIMITS['places']} areas")
            else:
                for i, a in enumerate(areas):
                    ap = f"{path}.where.areas[{i}]"
                    if not _check_keys(a, AREA_KEYS, ap, errors):
                        continue
                    lat, lon, radius = get(a, "lat"), get(a, "lon"), get(a, "radius_m")
                    if not (is_finite(lat) and -90 <= lat <= 90):
                        errors.append(f"{ap}.lat must be between -90 and 90")
                    if not (is_finite(lon) and -180 <= lon <= 180):
                        errors.append(f"{ap}.lon must be between -180 and 180")
                    if not (is_finite(radius) and 10 <= radius <= 20037508):
                        errors.append(f"{ap}.radius_m must be between 10 and 20,037,508")
        if present(w, "networks"):
            _check_string_list(w["networks"], f"{path}.where.networks", errors, LIMITS["networks"], lambda n: parse_cidr(n) is not None,
                               'must be a CIDR range like "203.0.113.0/24"')
        if not any(present(w, k) for k in ("countries", "regions", "areas", "networks")):
            errors.append(f"{path}.where needs at least one of countries, regions, areas or networks")
        if _js.strict_eq(get(w, "source"), "device") and (truthy(get(w, "countries")) or truthy(get(w, "regions")) or truthy(get(w, "networks"))):
            errors.append(f'{path}.where with source "device" can only use areas (a device reports coordinates, not countries or networks)')
    if present(grant, "limits") and _check_keys(grant["limits"], LIMIT_KEYS, f"{path}.limits", errors):
        uses, spend = get(grant["limits"], "uses"), get(grant["limits"], "spend_usd_per_month")
        if uses is not MISSING and _check_keys(uses, USES_KEYS, f"{path}.limits.uses", errors):
            count = get(uses, "count")
            if not is_safe_integer(count) or count < 1 or count > 1e9:
                errors.append(f"{path}.limits.uses.count must be an integer from 1 to 1,000,000,000")
            if not includes(USE_PERIODS, get(uses, "per")):
                errors.append(f"{path}.limits.uses.per must be one of {', '.join(USE_PERIODS)}")
        if spend is not MISSING and not (is_finite(spend) and 0 <= spend <= 1e6):
            errors.append(f"{path}.limits.spend_usd_per_month must be a number from 0 to 1,000,000")
    if present(grant, "require") and _check_keys(grant["require"], REQUIRE_KEYS, f"{path}.require", errors):
        for key in ("online", "step_up"):
            value = get(grant["require"], key)
            if value is not MISSING and not isinstance(value, bool):
                errors.append(f"{path}.require.{key} must be true or false")
    return errors


def validate_grants(grants) -> list:
    """Validate a grant list (1–32 grants)."""
    if not isinstance(grants, list) or len(grants) == 0 or len(grants) > LIMITS["grants"]:
        return [f"grants must be a list of 1–{LIMITS['grants']} grants"]
    return [problem for i, grant in enumerate(grants) for problem in validate_grant(grant, f"grants[{i}]")]


def local_time(now_seconds, tz: str) -> dict:
    """Local weekday (0 = Sunday) and minutes since midnight at an instant in a zone."""
    local = datetime.fromtimestamp(math.floor(now_seconds * 1000) / 1000, _zone(tz))
    return {"day": (local.weekday() + 1) % 7, "minutes": local.hour * 60 + local.minute}


def _minutes(time) -> float:
    # A non-string "HH:MM" can only get here through JS String() coercion; JS then computes NaN.
    if not isinstance(time, str):
        return math.nan
    return int(time[:2]) * 60 + int(time[3:])


def in_window(window: dict, local: dict) -> bool:
    """Is an instant inside a window? Overnight windows (from > to) belong to the day they start on."""
    days = window.get("days") if truthy(window.get("days")) else DAYS
    start = _minutes(window["from"])
    end = 1440 if _js.strict_eq(window["to"], "24:00") else _minutes(window["to"])
    today = DAYS[local["day"]]
    yesterday = DAYS[(local["day"] + 6) % 7]
    if start < end:
        return today in days and start <= local["minutes"] < end
    return (today in days and local["minutes"] >= start) or (yesterday in days and local["minutes"] < end)


def _place_matches(where: dict, loc, kind: str) -> bool:
    if kind == "network":
        if present(where, "countries") and includes(where["countries"], get(loc, "country")):
            return True
        if present(where, "regions") and includes(where["regions"], get(loc, "region")):
            return True
    lat, lon = get(loc, "lat"), get(loc, "lon")
    if truthy(get(where, "areas")) and is_finite(lat) and is_finite(lon):
        acc = get(loc, "acc_m")
        # Device accuracy is held against the device: a fix that might be outside the area is.
        slack = (acc if is_finite(acc) else math.inf) if kind == "device" else 0
        return any(distance_meters(area, {"lat": lat, "lon": lon}) + slack <= area["radius_m"] for area in where["areas"])
    return False


def _check_source(where: dict, loc, kind: str, now, reasons: list) -> None:
    if not truthy(loc):
        reasons.append(f"location_unavailable:{kind}")
        return
    t = get(loc, "t")
    if kind == "device" and not (is_finite(t) and abs(now - t) <= DEVICE_LOCATION_MAX_AGE):
        reasons.append("location_stale:device")
        return
    places = truthy(get(where, "countries")) or truthy(get(where, "regions")) or truthy(get(where, "areas"))
    if places and not _place_matches(where, loc, kind):
        reasons.append(f"outside_location:{kind}")
    if kind == "network" and truthy(get(where, "networks")) and not any(ip_in_cidr(get(loc, "ip"), n) for n in where["networks"]):
        reasons.append("network_not_allowed")


def _unknown_members(grant) -> list:
    if not is_object(grant):
        return ["grant"]
    unknown = [k for k in _js.keys(grant) if k not in GRANT_KEYS]
    for member, allowed in (("when", WHEN_KEYS), ("where", WHERE_KEYS), ("limits", LIMIT_KEYS), ("require", REQUIRE_KEYS)):
        value = get(grant, member)
        if is_object(value):
            unknown += [f"{member}.{k}" for k in _js.keys(value) if k not in allowed]
    return unknown


def evaluate_grant(grant, context: dict) -> dict:
    """
    Evaluate one grant against a request context. Returns {ok, reasons, online}.
    ``online`` lists the checks only devicebasedauth.org can make (usage counters, step-up).
    """
    reasons: list = []
    online: dict = {}
    unknown = _unknown_members(grant)
    if unknown:
        return {"ok": False, "reasons": [f"unknown_constraint:{k}" for k in unknown], "online": online}
    if validate_grant(grant):
        return {"ok": False, "reasons": ["invalid_grant"], "online": online}
    now = get(context, "now")
    # JS compares undefined/null/strings numerically (undefined → NaN, so every comparison fails).
    now = math.nan if now is MISSING else _js.to_number(now)
    action, resource = get(context, "action"), get(context, "resource")
    if not any(action_matches(p, action) for p in grant["actions"]):
        reasons.append("action_not_granted")
    if not any(resource_matches(p, resource) for p in (grant.get("resources") or ["*"])):
        reasons.append("resource_not_granted")
    when = get(grant, "when")
    if truthy(when):
        if present(when, "not_before") and now < when["not_before"]:
            reasons.append("before_not_before")
        if present(when, "not_after") and now >= when["not_after"]:
            reasons.append("after_not_after")
        if truthy(get(when, "windows")):
            local = local_time(now, when["tz"])
            if not any(in_window(w, local) for w in when["windows"]):
                reasons.append("outside_time_window")
    where = get(grant, "where")
    if truthy(where):
        location = get(context, "location")
        location = location if truthy(location) else {}
        if where["source"] in ("network", "both"):
            _check_source(where, get(location, "network"), "network", now, reasons)
        if where["source"] in ("device", "both"):
            _check_source(where, get(location, "device"), "device", now, reasons)
    limits, require = get(grant, "limits"), get(grant, "require")
    if truthy(get(limits, "uses")):
        online["uses"] = limits["uses"]
    if truthy(get(require, "step_up")):
        online["step_up"] = True
    if truthy(get(require, "online")):
        online["required"] = True
    if not reasons and online and not truthy(get(context, "online")):
        reasons.append("online_required")
    return {"ok": not reasons, "reasons": reasons, "online": online}


def evaluate_grants(grants, context: dict) -> dict:
    """
    Evaluate every grant; allow when any grant passes (deny by default).

    context: {now (seconds, the verifier's clock), action, resource, location: {network, device},
    online}. Returns {allow, grant_index, grant, online, caveats, reasons, online_required,
    results}, where reasons has one list per grant.
    """
    if not isinstance(grants, list):
        return {"allow": False, "grant_index": None, "reasons": [["invalid_grants"]], "online_required": False}
    results = [evaluate_grant(g, context) for g in grants]
    index = next((i for i, r in enumerate(results) if r["ok"]), -1)
    online_required = index < 0 and any(r["reasons"] == ["online_required"] for r in results)
    spend = get(get(grants[index], "limits"), "spend_usd_per_month") if index >= 0 else MISSING
    return {
        "allow": index >= 0,
        "grant_index": index if index >= 0 else None,
        "grant": grants[index] if index >= 0 else None,
        "online": results[index]["online"] if index >= 0 else {},
        "caveats": {"spend_usd_per_month": spend} if spend is not MISSING else {},
        "reasons": [r["reasons"] for r in results],
        "online_required": online_required,
        "results": results,
    }


def period_seconds(per: str) -> float:
    """Length of a usage period in seconds (total = infinity)."""
    return PERIOD_SECONDS.get(per, math.inf)
