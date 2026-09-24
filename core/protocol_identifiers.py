"""Strict vocabulary for structured proposal operation and resource types.

These identifiers are protocol labels, not natural language. Restricting them
avoids Unicode/case ambiguity before cross-language or enforcement integration.
"""
import re

_IDENTIFIER = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")


def protocol_identifier(value, name):
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string")
    value = value.strip().lower()
    if not value:
        raise ValueError(f"{name} must be nonempty")
    if not value.isascii() or _IDENTIFIER.fullmatch(value) is None:
        raise ValueError(f"{name} must use lowercase-compatible ASCII protocol syntax")
    return value
