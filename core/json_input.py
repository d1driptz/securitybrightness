"""Strict JSON decoding shared by HTTP input and existing audit history."""

import json
import math


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _constant(value):
    raise ValueError("non-finite JSON number")


def _validate(value, depth, max_depth):
    if depth > max_depth:
        raise ValueError("JSON nesting is too deep")
    if isinstance(value, str):
        value.encode("utf-8")  # Reject lone surrogates before downstream output.
    elif isinstance(value, float) and not math.isfinite(value):
        raise ValueError("non-finite JSON number")
    elif isinstance(value, dict):
        for key, item in value.items():
            _validate(key, depth, max_depth)
            _validate(item, depth + 1, max_depth)
    elif isinstance(value, list):
        for item in value:
            _validate(item, depth + 1, max_depth)


def loads(text, *, max_depth=32):
    try:
        value = json.loads(text, object_pairs_hook=_object, parse_constant=_constant)
        _validate(value, 0, max_depth)
        return value
    except RecursionError as exc:
        raise ValueError("JSON nesting is too deep") from exc
