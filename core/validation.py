"""Validation shared by registry and authorization entry points."""
from .events import MAX_TEXT_LENGTH


def application_id(value):
    if not isinstance(value, str):
        raise TypeError("application_id must be a string")
    value = value.strip()
    if not value:
        raise ValueError("application_id is required")
    if len(value) > MAX_TEXT_LENGTH or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError("application_id contains invalid characters or is too long")
    return value


def boolean(value, name):
    if type(value) is not bool:
        raise TypeError(f"{name} must be a boolean")
    return value
