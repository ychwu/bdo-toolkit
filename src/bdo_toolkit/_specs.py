"""Turn opcode profile JSON entries into decodable event specs."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Iterable, Optional

from ._protocol import EventSpec
from .profiles import OpcodeProfile, ProfileError


@dataclass(frozen=True)
class LoadedSpecProfile:
    active: bool
    specs: tuple[EventSpec, ...]
    source: str


def event_specs_from_profile(profile: OpcodeProfile) -> LoadedSpecProfile:
    """Convert one validated profile object into decoder event specs."""
    if not profile.active:
        return LoadedSpecProfile(active=False, specs=(), source=str(profile.path))

    specs: list[EventSpec] = []
    decodable_events = {"LOOT_PREVIEW", "INVENTORY_TRANSFER", "STORAGE_ITEM_DELTA"}
    for event, entries in profile.specs.items():
        for entry in entries:
            try:
                spec = _event_spec_from_entry(event, entry)
            except ValueError as exc:
                raise ProfileError(
                    f"Invalid {event} spec in {profile.path}: {exc}"
                ) from exc
            if spec is not None:
                specs.append(spec)
            elif event in decodable_events:
                raise ProfileError(
                    f"Invalid {event} spec in {profile.path}: "
                    "missing or invalid required fields"
                )

    return LoadedSpecProfile(
        active=True,
        specs=tuple(_dedupe_event_specs(specs)),
        source=str(profile.path),
    )


def _event_spec_from_entry(
    event: str,
    entry: Mapping[str, object],
) -> Optional[EventSpec]:
    opcode = _parse_opcode(entry.get("opcode"))
    if opcode is None:
        return None

    length = _optional_int(entry.get("length"))
    item_id_offset = _optional_int(entry.get("item_id_offset"))
    quantity_offset = _optional_int(entry.get("quantity_offset"))

    if event == "LOOT_PREVIEW":
        if item_id_offset is None or quantity_offset is None:
            return None
        item_instance_offset = _optional_int(entry.get("item_instance_offset"))
        return EventSpec(
            label="LOOT_PREVIEW",
            opcode=opcode,
            item_offset=item_id_offset,
            quantity_offset=quantity_offset,
            min_message_length=_minimum_event_length(
                length,
                item_id_offset + 4,
                quantity_offset + 4,
                (
                    item_instance_offset + 8
                    if item_instance_offset is not None
                    else None
                ),
            ),
            item_instance_offset=item_instance_offset,
            single_record_message_length=length,
            default_context="Gathering",
        )

    if event == "INVENTORY_TRANSFER":
        if item_id_offset is None or quantity_offset is None:
            return None
        inventory_slot_offset = _optional_int(entry.get("inventory_slot_offset"))
        context_offset = _optional_int(entry.get("context_offset"))
        item_instance_offset = _optional_int(entry.get("item_instance_offset"))
        repeat_stride = _optional_int(entry.get("repeat_stride"))
        return EventSpec(
            label="INVENTORY_TRANSFER",
            opcode=opcode,
            item_offset=item_id_offset,
            quantity_offset=quantity_offset,
            min_message_length=_minimum_event_length(
                length,
                item_id_offset + 4,
                quantity_offset + 4,
                item_instance_offset + 8 if item_instance_offset is not None else None,
                context_offset + 4 if context_offset is not None else None,
                inventory_slot_offset + 1 if inventory_slot_offset is not None else None,
            ),
            inventory_slot_offset=inventory_slot_offset,
            source_context_offset=context_offset,
            item_instance_offset=item_instance_offset,
            repeat_stride=repeat_stride,
            # Preserve the calibrated base length even when a single-record
            # capture could not reveal a repeat stride. Runtime structural
            # discovery uses it to validate later multi-record messages.
            single_record_message_length=length,
        )

    if event == "STORAGE_ITEM_DELTA":
        quantity_added_offset = _optional_int(entry.get("quantity_added_offset"))
        destination_instance_offset = _optional_int(
            entry.get("destination_instance_offset")
        )
        if item_id_offset is None or quantity_added_offset is None:
            return None
        context_offset = _optional_int(entry.get("context_offset"))
        repeat_stride = _optional_int(entry.get("repeat_stride"))
        return EventSpec(
            label="INVENTORY_TO_STORAGE",
            opcode=opcode,
            item_offset=item_id_offset,
            quantity_offset=quantity_added_offset,
            min_message_length=_minimum_event_length(
                length,
                item_id_offset + 4,
                quantity_added_offset + 4,
                (
                    destination_instance_offset + 8
                    if destination_instance_offset is not None
                    else None
                ),
                context_offset + 4 if context_offset is not None else None,
            ),
            source_context_offset=context_offset,
            storage_instance_offset=destination_instance_offset,
            repeat_stride=repeat_stride,
            single_record_message_length=length,
            default_context="Storage",
        )

    return None


def _parse_opcode(value: object) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        opcode = value
    elif isinstance(value, str):
        try:
            opcode = int(value, 16 if value.lower().startswith("0x") else 10)
        except ValueError:
            return None
    else:
        return None

    if not 0 <= opcode <= 0xFFFF:
        return None
    return opcode


def _optional_int(value: object) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"expected a non-negative integer, got {value!r}")
    return value


def _minimum_event_length(length: Optional[int], *ends: Optional[int]) -> int:
    minimum = max((end for end in ends if end is not None), default=5)
    if length is not None and length > 0:
        minimum = max(minimum, length)
    return minimum


def _dedupe_event_specs(specs: Iterable[EventSpec]) -> list[EventSpec]:
    output: list[EventSpec] = []
    # EventSpec is a frozen value object whose fields are all decode-affecting.
    # Using the complete value as identity preserves same-opcode layouts that
    # differ in base length, instance offsets, repeat geometry, context width,
    # or fallback context while still removing literal duplicates.
    seen: set[EventSpec] = set()
    for spec in specs:
        if spec in seen:
            continue
        seen.add(spec)
        output.append(spec)
    return output
