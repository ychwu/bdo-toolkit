"""Turn opcode profile JSON entries into decodable event specs."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Iterable, Optional

from ._protocol import MAX_TARGET_MESSAGE_LENGTH, EventSpec
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

    normalized = tuple(_dedupe_event_specs(specs))
    _validate_unambiguous_loot_specs(normalized, source=profile.path)
    return LoadedSpecProfile(
        active=True,
        specs=normalized,
        source=str(profile.path),
    )


def _validate_loot_profile_entries(
    entries: Iterable[Mapping[str, object]],
    *,
    source: object,
) -> None:
    """Validate only the runtime ambiguity introduced by raw LOOT entries."""

    specs: list[EventSpec] = []
    for entry in entries:
        try:
            spec = _event_spec_from_entry("LOOT_PREVIEW", entry)
        except ValueError as exc:
            raise ProfileError(
                f"Invalid LOOT_PREVIEW spec in {source}: {exc}"
            ) from exc
        if spec is None:
            raise ProfileError(
                f"Invalid LOOT_PREVIEW spec in {source}: "
                "missing or invalid required fields"
            )
        specs.append(spec)

    _validate_unambiguous_loot_specs(
        _dedupe_event_specs(specs),
        source=source,
    )


def _validate_unambiguous_loot_specs(
    specs: Iterable[EventSpec],
    *,
    source: object,
) -> None:
    """Require one non-overlapping runtime length domain per LOOT opcode."""

    grouped: dict[int, list[EventSpec]] = {}
    for spec in specs:
        if spec.label != "LOOT_PREVIEW":
            continue
        grouped.setdefault(spec.opcode, []).append(spec)

    for opcode, candidates in grouped.items():
        for index, first in enumerate(candidates):
            first_low, first_high = _loot_message_length_domain(first)
            for second in candidates[index + 1 :]:
                second_low, second_high = _loot_message_length_domain(second)
                if max(first_low, second_low) > min(first_high, second_high):
                    continue
                raise ProfileError(
                    f"Ambiguous LOOT_PREVIEW specs in {source}: opcode "
                    f"0x{opcode:04X} has distinct layouts with overlapping "
                    "runtime message-length domains: "
                    f"{_loot_layout_description(first)} and "
                    f"{_loot_layout_description(second)}. Keep only the layout for "
                    "the captured game patch, or recalibrate and replace the "
                    "LOOT_PREVIEW family instead of merging it."
                )


def _loot_message_length_domain(spec: EventSpec) -> tuple[int, int]:
    exact_length = spec.single_record_message_length
    if exact_length is not None:
        return exact_length, exact_length
    return spec.min_message_length, MAX_TARGET_MESSAGE_LENGTH


def _loot_layout_description(spec: EventSpec) -> str:
    exact_length = spec.single_record_message_length
    length = (
        str(exact_length)
        if exact_length is not None
        else f"{spec.min_message_length}..{MAX_TARGET_MESSAGE_LENGTH}"
    )
    return (
        f"(length={length}, item_id_offset={spec.item_offset}, "
        f"quantity_offset={spec.quantity_offset}, "
        f"item_instance_offset={spec.item_instance_offset!r})"
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
