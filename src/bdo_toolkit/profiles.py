"""Opcode profile helpers."""

from __future__ import annotations

import json
import math
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from types import MappingProxyType
from typing import Any, Optional


OPCODE_PROFILE_SCHEMA_VERSION = 1


class ProfileError(ValueError):
    """Raised when an opcode profile has an invalid JSON or schema shape."""


@dataclass(frozen=True)
class AgrisProfileLayout:
    """Portable Agris geometry; no player balance or connection identity."""

    opcode: int
    message_length: int
    remaining_offset: int
    maximum_offset: int
    flag: int = 0
    encoding: str = "uint32_le"
    observed_date: str | None = None

    def __post_init__(self) -> None:
        for name, low, high in (("opcode", 0, 65535), ("message_length", 13, 65535),
                                ("remaining_offset", 5, 65531), ("maximum_offset", 5, 65531),
                                ("flag", 0, 0)):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
                raise ProfileError(f"agris.{name} must be an integer from {low} to {high}")
        if self.encoding != "uint32_le":
            raise ProfileError("agris.encoding must be uint32_le")
        if max(self.remaining_offset, self.maximum_offset) + 4 > self.message_length:
            raise ProfileError("agris offsets extend outside the message")
        if abs(self.remaining_offset - self.maximum_offset) < 4:
            raise ProfileError("agris remaining and maximum fields overlap")
        if self.observed_date is not None:
            try:
                if not isinstance(self.observed_date, str) or date.fromisoformat(self.observed_date).isoformat() != self.observed_date:
                    raise ValueError
            except ValueError as exc:
                raise ProfileError("agris.observed_date must be YYYY-MM-DD or null") from exc

    def to_dict(self) -> dict[str, Any]:
        return {"opcode": f"0x{self.opcode:04X}", "message_length": self.message_length,
                "remaining_offset": self.remaining_offset, "maximum_offset": self.maximum_offset,
                "flag": self.flag, "encoding": self.encoding, "observed_date": self.observed_date}


def _agris_layout(value: object) -> AgrisProfileLayout | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ProfileError("agris must be an object or null")
    required = {"opcode", "message_length", "remaining_offset", "maximum_offset", "flag", "encoding"}
    if not required <= value.keys() or value.keys() - required - {"observed_date"}:
        raise ProfileError("agris has missing or unsupported fields")
    return AgrisProfileLayout(opcode=_profile_opcode(value["opcode"], "agris.opcode"),
                              message_length=value["message_length"],
                              remaining_offset=value["remaining_offset"], maximum_offset=value["maximum_offset"],
                              flag=value["flag"], encoding=value["encoding"], observed_date=value.get("observed_date"))


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
    version: int
    updated_at: Optional[str]
    calibration_item_id: Optional[int]
    specs: Mapping[str, tuple[Mapping[str, Any], ...]]
    origin_companion_families: tuple[OriginCompanionFamily, ...] = ()
    agris: AgrisProfileLayout | None = field(default=None, kw_only=True)

    def __post_init__(self) -> None:
        if self.agris is not None:
            if not isinstance(self.agris, AgrisProfileLayout):
                raise ProfileError("agris must be an AgrisProfileLayout or None")
            self.agris.__post_init__()
        object.__setattr__(
            self,
            "specs",
            MappingProxyType(
                {
                    event: tuple(
                        _freeze_profile_mapping(entry) for entry in entries
                    )
                    for event, entries in self.specs.items()
                }
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": str(self.path),
            "active": self.active,
            "version": self.version,
            "updated_at": self.updated_at,
            "calibration_item_id": self.calibration_item_id,
            "specs": {
                event: [_thaw_profile_value(entry) for entry in entries]
                for event, entries in self.specs.items()
            },
            "origin_companion_families": [
                family.to_dict() for family in self.origin_companion_families
            ],
            **({"agris": self.agris.to_dict()} if self.agris is not None else {}),
        }


def load_opcode_profile(path: str | Path) -> OpcodeProfile:
    """Load and validate one explicit, app-owned opcode profile."""

    profile_path = Path(path)
    if not profile_path.is_file():
        raise FileNotFoundError(f"Opcode profile does not exist: {profile_path}")
    try:
        data = json.loads(profile_path.read_text(encoding="utf-8-sig"))
    except (json.JSONDecodeError, RecursionError, UnicodeError) as exc:
        raise ProfileError(f"Could not parse opcodes JSON {profile_path}: {exc}") from exc
    return _opcode_profile_from_data(data, profile_path)


def _opcode_profile_from_data(data: Any, profile_path: Path) -> OpcodeProfile:
    """Shared validation for loaded and proposed profile content."""
    if not isinstance(data, dict):
        raise ProfileError(f"Opcodes JSON {profile_path} must be a top-level object")

    active_value = data.get("profile_active", False)
    if not isinstance(active_value, bool):
        raise ProfileError(f"profile_active in {profile_path} must be a boolean")

    version_value = data.get("version")
    if (
        isinstance(version_value, bool)
        or not isinstance(version_value, int)
        or version_value != OPCODE_PROFILE_SCHEMA_VERSION
    ):
        raise ProfileError(
            f"version in {profile_path} must be "
            f"{OPCODE_PROFILE_SCHEMA_VERSION}"
        )

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
    immutable_specs = MappingProxyType(
        {
            event: tuple(_freeze_profile_mapping(entry) for entry in entries)
            for event, entries in normalized_specs.items()
        }
    )
    return OpcodeProfile(
        path=profile_path,
        active=active_value,
        version=version_value,
        updated_at=updated_at_value,
        calibration_item_id=calibration_item_value,
        specs=immutable_specs,
        origin_companion_families=families,
        agris=_agris_layout(data.get("agris")),
    )


def _freeze_profile_mapping(value: Mapping[str, Any]) -> Mapping[str, Any]:
    return MappingProxyType(
        {key: _freeze_profile_value(item) for key, item in value.items()}
    )


def _freeze_profile_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return _freeze_profile_mapping(value)
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_profile_value(item) for item in value)
    return value


def _thaw_profile_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            key: _thaw_profile_value(item) for key, item in value.items()
        }
    if isinstance(value, tuple):
        return [_thaw_profile_value(item) for item in value]
    return value


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
        "record_count_offset",
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
    if event == "STORAGE_ITEM_DELTA":
        item_offset = entry.get("item_id_offset")
        context_offset = entry.get("context_offset")
        count_offset = entry.get("record_count_offset")
        if isinstance(item_offset, int) and not isinstance(item_offset, bool):
            if context_offset is not None and context_offset + 4 > item_offset:
                raise ProfileError(
                    f"context_offset in {location} must end before item_id_offset"
                )
            if count_offset is not None and count_offset + 2 > item_offset:
                raise ProfileError(
                    f"record_count_offset in {location} must end before item_id_offset"
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
