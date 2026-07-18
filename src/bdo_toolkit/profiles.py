"""Opcode profile helpers."""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional


class ProfileError(ValueError):
    """Raised when an opcode profile has an invalid JSON or schema shape."""


@dataclass(frozen=True)
class OriginCompanionFamily:
    """One explicitly promoted structural family trusted by the classifier."""

    delta_opcode: int
    companion_opcodes: tuple[int, int]
    companion_lengths: tuple[int, int]
    detection: str
    observations: int
    promoted_at: Optional[str]

    @property
    def family_key(self) -> tuple[int, int, int, int, int]:
        return (
            self.delta_opcode,
            self.companion_opcodes[0],
            self.companion_opcodes[1],
            self.companion_lengths[0],
            self.companion_lengths[1],
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "delta_opcode": f"0x{self.delta_opcode:04X}",
            "companion_opcodes": [
                f"0x{opcode:04X}" for opcode in self.companion_opcodes
            ],
            "companion_lengths": list(self.companion_lengths),
            "detection": self.detection,
            "observations": self.observations,
            "promoted_at": self.promoted_at,
        }


@dataclass(frozen=True)
class OpcodeProfile:
    """Versioned opcode profile metadata and raw specs."""

    path: Path
    active: bool
    version: Optional[int]
    updated_at: Optional[str]
    calibration_item_id: Optional[int]
    specs: dict[str, list[dict[str, Any]]]
    origin_companion_families: tuple[OriginCompanionFamily, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": str(self.path),
            "active": self.active,
            "version": self.version,
            "updated_at": self.updated_at,
            "calibration_item_id": self.calibration_item_id,
            "specs": self.specs,
            "origin_companion_families": [
                family.to_dict() for family in self.origin_companion_families
            ],
        }


def default_profile_path() -> Path:
    """Path to the opcode profile bundled with the package.

    The bundled profile reflects the last calibration performed by the toolkit
    maintainers and can go stale after a game patch. Pass an explicit path to
    ``load_opcode_profile``/``replay_pcap``/``capture_live`` to use a locally
    calibrated profile instead.
    """
    return Path(__file__).resolve().parent / "data" / "opcodes.json"


def load_opcode_profile(path: str | Path | None = None) -> OpcodeProfile:
    profile_path = Path(path) if path is not None else default_profile_path()
    if not profile_path.is_file():
        raise FileNotFoundError(f"Opcode profile does not exist: {profile_path}")
    try:
        data = json.loads(profile_path.read_text(encoding="utf-8-sig"))
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise ProfileError(f"Could not parse opcodes JSON {profile_path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ProfileError(f"Opcodes JSON {profile_path} must be a top-level object")

    active_value = data.get("profile_active", False)
    if not isinstance(active_value, bool):
        raise ProfileError(f"profile_active in {profile_path} must be a boolean")

    version_value = data.get("version")
    if version_value is not None and (
        isinstance(version_value, bool)
        or not isinstance(version_value, int)
        or version_value < 1
    ):
        raise ProfileError(f"version in {profile_path} must be a positive integer")

    updated_at_value = data.get("updated_at")
    if updated_at_value is not None and not isinstance(updated_at_value, str):
        raise ProfileError(f"updated_at in {profile_path} must be a string")

    calibration_item_value = data.get("calibration_item_id")
    if calibration_item_value is not None and (
        isinstance(calibration_item_value, bool)
        or not isinstance(calibration_item_value, int)
        or not 1 <= calibration_item_value <= 0xFFFFFFFF
    ):
        raise ProfileError(
            f"calibration_item_id in {profile_path} must be a positive uint32"
        )

    specs = data.get("specs", {})
    if not isinstance(specs, dict):
        raise ProfileError(f"specs in {profile_path} must be an object")
    normalized_specs: dict[str, list[dict[str, Any]]] = {}
    for event_name, entries in specs.items():
        if not isinstance(event_name, str):
            raise ProfileError(f"spec event names in {profile_path} must be strings")
        if not isinstance(entries, list):
            raise ProfileError(
                f"specs[{event_name!r}] in {profile_path} must be a list"
            )
        if any(not isinstance(entry, dict) for entry in entries):
            raise ProfileError(
                f"every specs[{event_name!r}] entry in {profile_path} must be an object"
            )
        normalized_entries: list[dict[str, Any]] = []
        for index, entry in enumerate(entries):
            normalized = dict(entry)
            _validate_profile_entry(profile_path, event_name, index, normalized)
            normalized_entries.append(normalized)
        normalized_specs[event_name] = normalized_entries

    raw_families = data.get("origin_companion_families", [])
    if not isinstance(raw_families, list):
        raise ProfileError(
            f"origin_companion_families in {profile_path} must be a list"
        )
    families = tuple(
        _origin_companion_family(profile_path, index, entry)
        for index, entry in enumerate(raw_families)
    )
    return OpcodeProfile(
        path=profile_path,
        active=active_value,
        version=version_value,
        updated_at=updated_at_value,
        calibration_item_id=calibration_item_value,
        specs=normalized_specs,
        origin_companion_families=families,
    )


def _profile_opcode(value: object, location: str) -> int:
    if isinstance(value, bool):
        raise ProfileError(f"{location} must be a uint16")
    if isinstance(value, int):
        opcode = value
    elif isinstance(value, str):
        try:
            opcode = int(value, 16 if value.lower().startswith("0x") else 10)
        except ValueError as exc:
            raise ProfileError(f"{location} must be a uint16") from exc
    else:
        raise ProfileError(f"{location} must be a uint16")
    if not 0 <= opcode <= 0xFFFF:
        raise ProfileError(f"{location} must be a uint16")
    return opcode


def _origin_companion_family(
    path: Path,
    index: int,
    value: object,
) -> OriginCompanionFamily:
    location = f"origin_companion_families[{index}] in {path}"
    if not isinstance(value, dict):
        raise ProfileError(f"{location} must be an object")
    raw_opcodes = value.get("companion_opcodes")
    raw_lengths = value.get("companion_lengths")
    if not isinstance(raw_opcodes, list) or len(raw_opcodes) != 2:
        raise ProfileError(f"companion_opcodes in {location} must contain two values")
    if not isinstance(raw_lengths, list) or len(raw_lengths) != 2:
        raise ProfileError(f"companion_lengths in {location} must contain two values")
    lengths: list[int] = []
    for raw_length in raw_lengths:
        if (
            isinstance(raw_length, bool)
            or not isinstance(raw_length, int)
            or not 5 <= raw_length <= 0xFFFF
        ):
            raise ProfileError(
                f"companion_lengths in {location} must contain values from 5 to 65535"
            )
        lengths.append(raw_length)
    detection = value.get("detection")
    if detection != "shared-token-chain-v1":
        raise ProfileError(
            f"detection in {location} must be 'shared-token-chain-v1'"
        )
    observations = value.get("observations")
    if (
        isinstance(observations, bool)
        or not isinstance(observations, int)
        or observations <= 0
    ):
        raise ProfileError(f"observations in {location} must be a positive integer")
    promoted_at = value.get("promoted_at")
    if promoted_at is not None and not isinstance(promoted_at, str):
        raise ProfileError(f"promoted_at in {location} must be a string or null")
    return OriginCompanionFamily(
        delta_opcode=_profile_opcode(value.get("delta_opcode"), f"delta_opcode in {location}"),
        companion_opcodes=(
            _profile_opcode(raw_opcodes[0], f"companion_opcodes in {location}"),
            _profile_opcode(raw_opcodes[1], f"companion_opcodes in {location}"),
        ),
        companion_lengths=(lengths[0], lengths[1]),
        detection=detection,
        observations=observations,
        promoted_at=promoted_at,
    )


def _validate_profile_entry(
    path: Path,
    event: str,
    index: int,
    entry: dict[str, Any],
) -> None:
    location = f"specs[{event!r}][{index}] in {path}"
    embedded_event = entry.get("event")
    if embedded_event is not None and embedded_event != event:
        raise ProfileError(
            f"event in {location} must match its containing {event!r} category"
        )
    opcode = entry.get("opcode")
    if isinstance(opcode, bool):
        raise ProfileError(f"opcode in {location} must be a uint16")
    if isinstance(opcode, str):
        try:
            opcode_number = int(opcode, 16 if opcode.lower().startswith("0x") else 10)
        except ValueError as exc:
            raise ProfileError(f"opcode in {location} must be a uint16") from exc
    elif isinstance(opcode, int):
        opcode_number = opcode
    else:
        raise ProfileError(f"opcode in {location} must be a uint16")
    if not 0 <= opcode_number <= 0xFFFF:
        raise ProfileError(f"opcode in {location} must be a uint16")

    length = entry.get("length")
    if length is not None and (
        isinstance(length, bool)
        or not isinstance(length, int)
        or not 5 <= length <= 0xFFFF
    ):
        raise ProfileError(f"length in {location} must be 5..65535 or null")

    offset_fields = (
        "item_id_offset",
        "quantity_offset",
        "item_instance_offset",
        "context_offset",
        "inventory_slot_offset",
        "source_instance_offset",
        "quantity_removed_offset",
        "quantity_added_offset",
        "destination_instance_offset",
    )
    for field_name in offset_fields:
        value = entry.get(field_name)
        if value is not None and (
            isinstance(value, bool) or not isinstance(value, int) or value < 0
        ):
            raise ProfileError(
                f"{field_name} in {location} must be a non-negative integer or null"
            )
    repeat_stride = entry.get("repeat_stride")
    if repeat_stride is not None and (
        isinstance(repeat_stride, bool)
        or not isinstance(repeat_stride, int)
        or repeat_stride <= 0
    ):
        raise ProfileError(
            f"repeat_stride in {location} must be a positive integer or null"
        )
    for field_name in ("confidence", "source", "observed_at"):
        value = entry.get(field_name)
        if value is not None and not isinstance(value, str):
            raise ProfileError(f"{field_name} in {location} must be a string or null")
    score = entry.get("score")
    if score is not None and (
        isinstance(score, bool)
        or not isinstance(score, (int, float))
        or not math.isfinite(score)
        or not 0 <= score <= 1
    ):
        raise ProfileError(f"score in {location} must be a finite number from 0 to 1")
