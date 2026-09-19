"""Validation shared by every Agris acquisition entry point."""

from __future__ import annotations


def validate_expected_maximum_points(value: object) -> int:
    """Require an explicit, positive uint32 cap; never infer a default."""

    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("expected_maximum_points must be an integer")
    if not 1 <= value <= 0xFFFFFFFF:
        raise ValueError("expected_maximum_points must be between 1 and 4294967295")
    return value
