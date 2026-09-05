"""Private calibration formatting implementation."""

from __future__ import annotations

import datetime as dt
from typing import Iterable
from ._constants import OPCODE_PROFILE_EVENTS
from ._records import _Options
from .models import MessageSpec


def _dedupe_message_specs(specs: Iterable[MessageSpec]) -> list[MessageSpec]:
    output: list[MessageSpec] = []
    seen: set[tuple[object, ...]] = set()
    for spec in specs:
        key = spec.dedupe_key()
        if key in seen:
            continue
        seen.add(key)
        output.append(spec)
    return output


def _confidence_label(score: float) -> str:
    level = "high" if score >= 0.90 else "medium"
    return f"calibrated-{level}"


def _calibration_source(options: _Options, action: str) -> str:
    parts = [f"calibrate {action}", f"item_id={options.item_id}"]
    if options.quantity is not None:
        parts.append(f"qty={options.quantity}")
    return " ".join(parts)


def _iso_timestamp(timestamp: float) -> str:
    return (
        dt.datetime.fromtimestamp(timestamp, tz=dt.UTC)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def _utc_now_text() -> str:
    return (
        dt.datetime.now(tz=dt.UTC)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def _events_for_action(action: str) -> tuple[str, ...]:
    if action == "loot-preview":
        return ("LOOT_PREVIEW",)
    if action == "storage-to-inventory":
        return ("INVENTORY_TRANSFER", "SOURCE_CONTAINER_DECREMENT")
    if action == "inventory-to-storage":
        return (
            "SOURCE_STACK_DECREMENT",
            "SOURCE_ITEM_REFERENCE",
            "STORAGE_ITEM_DELTA",
        )
    # ``auto`` observes both transfer directions but never owns the separate
    # loot-preview workflow.
    return tuple(event for event in OPCODE_PROFILE_EVENTS if event != "LOOT_PREVIEW")
