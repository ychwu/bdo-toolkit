"""Validate every profile shape consumed by the runtime decoder."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Optional

from ._deposit_origin import DecrementSpec
from ._protocol import MAX_TARGET_MESSAGE_LENGTH
from ._specs import LoadedSpecProfile, _parse_opcode, event_specs_from_profile
from .profiles import (
    OPCODE_PROFILE_SCHEMA_VERSION,
    OpcodeProfile,
    OriginCompanionFamily,
    ProfileError,
)


@dataclass(frozen=True)
class RuntimeProfileValidation:
    """Validated event layouts and non-event companion layouts."""

    loaded_specs: LoadedSpecProfile
    decrement_specs: tuple[DecrementSpec, ...]


def validate_runtime_profile(profile: OpcodeProfile) -> RuntimeProfileValidation:
    """Validate one immutable profile as complete runtime authority."""

    if (
        isinstance(profile.version, bool)
        or not isinstance(profile.version, int)
        or profile.version != OPCODE_PROFILE_SCHEMA_VERSION
    ):
        raise ProfileError(
            f"Opcode profile version in {profile.path} must be "
            f"{OPCODE_PROFILE_SCHEMA_VERSION}"
        )
    if profile.active is not True:
        raise ProfileError(f"Opcode profile is inactive: {profile.path}")

    loaded_specs = event_specs_from_profile(profile)
    decrement_specs = tuple(
        _decrement_spec(profile, index, entry)
        for index, entry in enumerate(
            profile.specs.get("SOURCE_STACK_DECREMENT", ())
        )
    )
    for index, family in enumerate(profile.origin_companion_families):
        _validate_origin_companion_family(profile, index, family)
    return RuntimeProfileValidation(
        loaded_specs=loaded_specs,
        decrement_specs=decrement_specs,
    )


def _decrement_spec(
    profile: OpcodeProfile,
    index: int,
    entry: Mapping[str, object],
) -> DecrementSpec:
    location = f"SOURCE_STACK_DECREMENT[{index}] in {profile.path}"
    opcode = _parse_opcode(entry.get("opcode"))
    if opcode is None:
        raise ProfileError(f"Invalid {location}: opcode must be a uint16")
    length = _required_int(entry.get("length"), "length", location)
    if not 5 <= length <= MAX_TARGET_MESSAGE_LENGTH:
        raise ProfileError(
            f"Invalid {location}: length must be from 5 to "
            f"{MAX_TARGET_MESSAGE_LENGTH}"
        )
    quantity_offset = _required_int(
        entry.get("quantity_removed_offset"),
        "quantity_removed_offset",
        location,
    )
    source_instance_offset = _optional_int(
        entry.get("source_instance_offset"),
        "source_instance_offset",
        location,
    )
    repeat_stride = _optional_int(
        entry.get("repeat_stride"),
        "repeat_stride",
        location,
    )
    try:
        return DecrementSpec(
            opcode=opcode,
            min_message_length=length,
            quantity_offset=quantity_offset,
            source_instance_offset=source_instance_offset,
            repeat_stride=repeat_stride,
        )
    except ValueError as exc:
        raise ProfileError(f"Invalid {location}: {exc}") from exc


def _validate_origin_companion_family(
    profile: OpcodeProfile,
    index: int,
    family: OriginCompanionFamily,
) -> None:
    location = f"origin_companion_families[{index}] in {profile.path}"
    if not isinstance(family, OriginCompanionFamily):
        raise ProfileError(f"Invalid {location}: expected OriginCompanionFamily")
    if len(family.companion_opcodes) != 2:
        raise ProfileError(
            f"Invalid {location}: exactly two companion opcodes required"
        )
    opcodes = (family.delta_opcode, *family.companion_opcodes)
    if any(
        isinstance(opcode, bool)
        or not isinstance(opcode, int)
        or not 0 <= opcode <= 0xFFFF
        for opcode in opcodes
    ):
        raise ProfileError(f"Invalid {location}: opcodes must be uint16 values")
    if len(family.companion_lengths) != 2 or any(
        isinstance(length, bool)
        or not isinstance(length, int)
        or not 5 <= length <= 0xFFFF
        for length in family.companion_lengths
    ):
        raise ProfileError(
            f"Invalid {location}: exactly two companion lengths from 5 to 65535 required"
        )
    if family.detection != "shared-token-chain-v1":
        raise ProfileError(
            f"Invalid {location}: unsupported companion detection method"
        )
    if (
        isinstance(family.observations, bool)
        or not isinstance(family.observations, int)
        or family.observations <= 0
    ):
        raise ProfileError(f"Invalid {location}: observations must be positive")
    if family.promoted_at is not None and not isinstance(family.promoted_at, str):
        raise ProfileError(f"Invalid {location}: promoted_at must be a string or null")


def _required_int(value: object, field: str, location: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ProfileError(
            f"Invalid {location}: {field} must be a non-negative integer"
        )
    return value


def _optional_int(value: object, field: str, location: str) -> Optional[int]:
    if value is None:
        return None
    return _required_int(value, field, location)


__all__ = ["RuntimeProfileValidation", "validate_runtime_profile"]
