"""Shared validation for public Arena of Solare acquisition options."""

from __future__ import annotations


def validate_retain_raw_extensions(value: object) -> bool:
    """Return a validated raw-retention flag with one consistent contract."""

    if not isinstance(value, bool):
        raise TypeError("retain_raw_extensions must be a boolean")
    return value
