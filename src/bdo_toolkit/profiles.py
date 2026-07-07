"""Opcode profile helpers."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional


@dataclass(frozen=True)
class OpcodeProfile:
    """Versioned opcode profile metadata and raw specs."""

    path: Path
    active: bool
    version: Optional[int]
    updated_at: Optional[str]
    calibration_item_id: Optional[int]
    specs: dict[str, list[dict[str, Any]]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": str(self.path),
            "active": self.active,
            "version": self.version,
            "updated_at": self.updated_at,
            "calibration_item_id": self.calibration_item_id,
            "specs": self.specs,
        }


def default_profile_path() -> Path:
    return Path(__file__).resolve().parents[2] / "profiles" / "opcodes.json"


def load_opcode_profile(path: str | Path | None = None) -> OpcodeProfile:
    profile_path = Path(path) if path is not None else default_profile_path()
    data = json.loads(profile_path.read_text(encoding="utf-8-sig"))
    specs = data.get("specs", {})
    if not isinstance(specs, dict):
        specs = {}
    normalized_specs: dict[str, list[dict[str, Any]]] = {}
    for event_name, entries in specs.items():
        if isinstance(event_name, str) and isinstance(entries, list):
            normalized_specs[event_name] = [
                entry for entry in entries if isinstance(entry, dict)
            ]
    return OpcodeProfile(
        path=profile_path,
        active=bool(data.get("profile_active")),
        version=data.get("version") if isinstance(data.get("version"), int) else None,
        updated_at=(
            data.get("updated_at") if isinstance(data.get("updated_at"), str) else None
        ),
        calibration_item_id=(
            data.get("calibration_item_id")
            if isinstance(data.get("calibration_item_id"), int)
            else None
        ),
        specs=normalized_specs,
    )

