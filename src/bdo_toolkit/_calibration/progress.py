"""Immutable live assessments and shared readiness policy.

Progress is a view of one retained evidence window, never profile authority.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from .._profile_runtime import validate_runtime_profile
from ..profiles import OPCODE_PROFILE_SCHEMA_VERSION, OpcodeProfile, ProfileError
from .models import CalibrationResult, CalibrationRetention, MessageSpec


TRANSFER_REQUIRED = frozenset({
    "INVENTORY_TRANSFER", "STORAGE_ITEM_DELTA", "SOURCE_STACK_DECREMENT",
})


def required_events(action: str) -> frozenset[str]:
    return {
        "auto": TRANSFER_REQUIRED,
        "inventory-to-storage": frozenset({"STORAGE_ITEM_DELTA", "SOURCE_STACK_DECREMENT"}),
        "storage-to-inventory": frozenset({"INVENTORY_TRANSFER"}),
        "loot-preview": frozenset({"LOOT_PREVIEW"}),
    }[action]


def readiness_issues(result: CalibrationResult, action: str) -> tuple[str, ...]:
    missing = required_events(action) - result.events_found
    if missing:
        return tuple(f"missing {event}" for event in sorted(missing))
    # Validate only the newly inferred layouts. Existing files must not fill
    # gaps in a post-patch calibration or participate in readiness.
    profile = OpcodeProfile(
        path=Path("<live-calibration>"), active=True,
        version=OPCODE_PROFILE_SCHEMA_VERSION, updated_at=None,
        calibration_item_id=result.calibration_item_id,
        specs={event: tuple(spec.to_json_dict() for spec in specs)
               for event, specs in result.specs_by_event().items()},
    )
    try:
        validate_runtime_profile(profile)
    except ProfileError as exc:
        return (str(exc),)
    return ()


@dataclass(frozen=True)
class CalibrationProgress:
    """One replaceable live assessment, or the terminal session update.

    ``ready`` describes the assessed window only. ``kind='finished'`` with a
    non-None ``result`` is the authoritative final batch result. A manual or
    timed stop may return a partial result with ``ready=False``. Consumers
    replace their previous assessment; they must not union candidate layouts.
    No raw frames, instances, or flow identifiers are included.
    """

    kind: Literal["progress", "finalizing", "finished"]
    specs: tuple[MessageSpec, ...]
    detected_opcodes: tuple[int, ...]
    missing_events: frozenset[str]
    issues: tuple[str, ...]
    ready: bool
    retention: CalibrationRetention
    result: CalibrationResult | None = None

    def to_json_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "specs": [spec.to_json_dict() for spec in self.specs],
            "detected_opcodes": [f"0x{opcode:04X}" for opcode in self.detected_opcodes],
            "missing_events": sorted(self.missing_events),
            "issues": list(self.issues), "ready": self.ready,
            "retention": self.retention.to_json_dict(),
            "result": self.result.to_json_dict() if self.result is not None else None,
        }
