"""
JavaScript value semantics, in one place.

The reference implementation (packages/verify, JavaScript) decides on parsed JSON. Python's JSON
values behave differently in ways that matter for a security check: ``True == 1``, ``{}`` and
``[]`` are falsy, a present ``null`` and an absent member are both ``None``, ``re`` patterns
match Unicode digits and ``$`` matches before a trailing newline. Every conformance-relevant
decision goes through these helpers so that the Python port gives the same answer as the JS
for the same credential, including hostile ones.
"""
from __future__ import annotations

import math
import re

#: An absent object member (JS ``undefined``), distinct from JSON ``null`` (``None``).
MISSING = object()
MAX_SAFE_INTEGER = 2**53 - 1
_INDEX_KEY = re.compile(r"0|[1-9][0-9]*", re.ASCII)


def get(obj, key):
    """``obj.key`` (or ``obj?.key``): MISSING unless obj is a JSON object holding key."""
    return obj.get(key, MISSING) if isinstance(obj, dict) else MISSING


def present(obj, key) -> bool:
    """``obj.key !== undefined``."""
    return get(obj, key) is not MISSING


def is_object(value) -> bool:
    """Plain JSON object (not null, not an array)."""
    return isinstance(value, dict)


def is_number(value) -> bool:
    """``typeof value === 'number'`` (bool is not a number in JS)."""
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def is_finite(value) -> bool:
    """``Number.isFinite``."""
    return is_number(value) and math.isfinite(value)


def is_safe_integer(value) -> bool:
    """``Number.isSafeInteger``: 5 and 5.0 both qualify; 2**53 and true do not."""
    if not is_number(value):
        return False
    if isinstance(value, float) and not (math.isfinite(value) and value.is_integer()):
        return False
    return abs(value) <= MAX_SAFE_INTEGER


def truthy(value) -> bool:
    """JS truthiness: empty lists and objects are truthy, 0, NaN and '' are not."""
    if value is MISSING or value is None or value is False:
        return False
    if is_number(value):
        return value != 0 and not math.isnan(value)
    if isinstance(value, str):
        return value != ""
    return True


def strict_eq(a, b) -> bool:
    """``a === b`` for JSON values (objects and arrays compare by identity)."""
    if a is MISSING or b is MISSING or a is None or b is None:
        return a is b
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if is_number(a) or is_number(b):
        return is_number(a) and is_number(b) and a == b
    if isinstance(a, str) or isinstance(b, str):
        return isinstance(a, str) and isinstance(b, str) and a == b
    return a is b


def includes(items, value) -> bool:
    """``Array.prototype.includes`` (SameValueZero)."""
    if is_number(value) and math.isnan(value):
        return any(is_number(x) and math.isnan(x) for x in items)
    return any(strict_eq(x, value) for x in items)


def keys(obj: dict) -> list:
    """``Object.keys`` order: integer-like keys ascending first, then insertion order."""
    index = sorted((k for k in obj if _INDEX_KEY.fullmatch(k) and int(k) < 2**32 - 1), key=int)
    return index + [k for k in obj if not (_INDEX_KEY.fullmatch(k) and int(k) < 2**32 - 1)]


def js_len(text: str) -> int:
    """``string.length``, which counts UTF-16 code units."""
    return len(text.encode("utf-16-le", "surrogatepass")) // 2


def utf8(text: str) -> bytes:
    """``new TextEncoder().encode(text)``: lone surrogates become U+FFFD."""
    return text.encode("utf-16-le", "surrogatepass").decode("utf-16-le", "replace").encode("utf-8")


def to_string(value) -> str:
    """``String(value)`` for the JSON values a regex ``test`` may be handed."""
    if isinstance(value, str):
        return value
    if value is MISSING:
        return "undefined"
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, list):
        return ",".join("" if v is None or v is MISSING else to_string(v) for v in value)
    if isinstance(value, dict):
        return "[object Object]"
    if isinstance(value, float) and value.is_integer() and abs(value) < 1e21:
        return str(int(value))
    return str(value)


_DECIMAL = re.compile(r"[+-]?(?:[0-9]+\.?[0-9]*|\.[0-9]+)(?:[eE][+-]?[0-9]+)?", re.ASCII)
_RADIX = re.compile(r"0([xXoObB])([0-9a-fA-F]+)", re.ASCII)


def to_number(value) -> float:
    """``Number(value)`` for strings and JSON scalars (NaN when not numeric)."""
    if is_number(value):
        return value
    if value is None:
        return 0
    if isinstance(value, bool):
        return 1 if value else 0
    if isinstance(value, str):
        text = value.strip(" \t\n\r\v\f ﻿  ")
        if text == "":
            return 0
        if _DECIMAL.fullmatch(text):
            return float(text)
        if text in ("Infinity", "+Infinity", "-Infinity"):
            return -math.inf if text.startswith("-") else math.inf
        radix = _RADIX.fullmatch(text)
        if radix:
            try:
                return int(radix.group(2), {"x": 16, "o": 8, "b": 2}[radix.group(1).lower()])
            except ValueError:
                return math.nan
    return math.nan
