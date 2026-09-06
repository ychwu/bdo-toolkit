"""Private calibration validation implementation."""

from __future__ import annotations

import inspect
import math
from dataclasses import replace
from typing import Optional
from .._protocol import MAX_PLAUSIBLE_ITEM_ID
from ._constants import CALIBRATION_ACTIONS


def _validate_live_options(stop_on_complete: object, on_update: object) -> None:
    if not isinstance(stop_on_complete, bool):
        raise TypeError("stop_on_complete must be a boolean")
    if on_update is not None and not callable(on_update):
        raise TypeError("on_update must be callable or None")
    if inspect.iscoroutinefunction(on_update) or inspect.iscoroutinefunction(
        getattr(on_update, "__call__", None)
    ):
        raise TypeError("on_update must be synchronous")


def _validate_calibration_options(
    *,
    item_id: int,
    quantity: Optional[int],
    action: str,
    context_frames: int,
    min_confidence: float,
) -> None:
    if isinstance(item_id, bool) or not isinstance(item_id, int):
        raise ValueError("item_id must be an integer")
    if not 1 <= item_id <= MAX_PLAUSIBLE_ITEM_ID:
        raise ValueError(
            f"item_id must be between 1 and {MAX_PLAUSIBLE_ITEM_ID}"
        )
    if quantity is not None and (
        isinstance(quantity, bool)
        or not isinstance(quantity, int)
        or not 1 <= quantity <= 0xFFFFFFFF
    ):
        raise ValueError("quantity must be None or a positive uint32")
    if action != "auto" and action not in CALIBRATION_ACTIONS:
        raise ValueError(
            f"unknown calibration action {action!r}; "
            f"expected one of {CALIBRATION_ACTIONS} or 'auto'"
        )
    if (
        isinstance(context_frames, bool)
        or not isinstance(context_frames, int)
        or context_frames <= 0
    ):
        raise ValueError("context_frames must be a positive integer")
    if (
        isinstance(min_confidence, bool)
        or not isinstance(min_confidence, (int, float))
        or not math.isfinite(min_confidence)
        or not 0 <= min_confidence <= 1
    ):
        raise ValueError("min_confidence must be a finite number from 0 to 1")


def _validate_calibration_retention_limits(
    *,
    max_retained_frames: int,
    max_retained_bytes: int,
    context_frames: int,
) -> None:
    for name, value in (
        ("max_retained_frames", max_retained_frames),
        ("max_retained_bytes", max_retained_bytes),
    ):
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise ValueError(f"{name} must be a positive integer")
    if max_retained_frames <= context_frames:
        raise ValueError(
            "max_retained_frames must be greater than context_frames so one "
            "candidate and its requested preceding context can be retained"
        )


def _validate_profile_replacement_options(
    replace: bool,
    replace_entire_action: bool,
) -> None:
    if not isinstance(replace, bool):
        raise TypeError("replace must be a boolean")
    if not isinstance(replace_entire_action, bool):
        raise TypeError("replace_entire_action must be a boolean")
    if replace_entire_action and not replace:
        raise ValueError(
            "replace_entire_action=True cannot be combined with replace=False"
        )
