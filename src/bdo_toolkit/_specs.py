"""Turn opcode profile JSON entries into decodable event specs."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

from ._protocol import (
    CURRENT_EVENT_SPECS,
    CURRENT_INVENTORY_TRANSFER_RECORD_BASE_LENGTH,
    CURRENT_STORAGE_DELTA_RECORD_BASE_LENGTH,
    CURRENT_STORAGE_DELTA_RECORD_STRIDE,
    LEGACY_EVENT_SPECS,
    EventSpec,
)
from .profiles import ProfileError, load_opcode_profile


@dataclass(frozen=True)
class LoadedSpecProfile:
    active: bool
    specs: tuple[EventSpec, ...]
    source: str


def select_event_specs(
    *,
    opcodes_path: Path,
    include_legacy: bool = False,
    ignore_opcodes: bool = False,
    require_profile: bool = False,
) -> tuple[tuple[EventSpec, ...], str]:
    """Resolve the event specs to decode with and a human-readable source."""
    profile = (
        LoadedSpecProfile(active=False, specs=(), source="")
        if ignore_opcodes
        else load_spec_profile(opcodes_path, missing_ok=not require_profile)
    )
    if profile.active:
        specs = profile.specs
        source = f"{profile.source} active profile"
    else:
        specs = CURRENT_EVENT_SPECS
        source = "built-in current verified profile"

    if include_legacy:
        specs = tuple(dict.fromkeys(specs + LEGACY_EVENT_SPECS))
        source += " + legacy observed opcodes"
    return specs, source


def load_spec_profile(path: Path, *, missing_ok: bool = True) -> LoadedSpecProfile:
    if not path.exists():
        if missing_ok:
            return LoadedSpecProfile(active=False, specs=(), source=str(path))
        raise FileNotFoundError(f"Opcode profile does not exist: {path}")

    profile = load_opcode_profile(path)

    if not profile.active:
        return LoadedSpecProfile(active=False, specs=(), source=str(path))

    specs: list[EventSpec] = []
    decodable_events = {"LOOT_PREVIEW", "INVENTORY_TRANSFER", "STORAGE_ITEM_DELTA"}
    for event, entries in profile.specs.items():
        for entry in entries:
            try:
                spec = _event_spec_from_entry(event, entry)
            except ValueError as exc:
                raise ProfileError(
                    f"Invalid {event} spec in {path}: {exc}"
                ) from exc
            if spec is not None:
                specs.append(spec)
            elif event in decodable_events:
                raise ProfileError(
                    f"Invalid {event} spec in {path}: missing or invalid required fields"
                )

    return LoadedSpecProfile(
        active=True,
        specs=tuple(_dedupe_event_specs(specs)),
        source=str(path),
    )


def _event_spec_from_entry(
    event: str,
    entry: dict[str, object],
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
        return EventSpec(
            label="LOOT_PREVIEW",
            opcode=opcode,
            item_offset=item_id_offset,
            quantity_offset=quantity_offset,
            min_message_length=_minimum_event_length(
                length,
                item_id_offset + 4,
                quantity_offset + 4,
                _optional_int(entry.get("item_instance_offset"), width=8),
            ),
            default_context="Gathering",
        )

    if event == "INVENTORY_TRANSFER":
        if item_id_offset is None or quantity_offset is None:
            return None
        inventory_slot_offset = _optional_int(entry.get("inventory_slot_offset"))
        context_offset = _optional_int(entry.get("context_offset"))
        item_instance_offset = _optional_int(entry.get("item_instance_offset"))
        repeat_stride = _infer_repeat_stride(event, entry)
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
            single_record_message_length=(
                length if repeat_stride is not None else None
            ),
        )

    if event == "STORAGE_ITEM_DELTA":
        quantity_added_offset = _optional_int(entry.get("quantity_added_offset"))
        destination_instance_offset = _optional_int(
            entry.get("destination_instance_offset")
        )
        if item_id_offset is None or quantity_added_offset is None:
            return None
        context_offset = _optional_int(entry.get("context_offset"))
        repeat_stride = _infer_repeat_stride(event, entry)
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
            single_record_message_length=(
                length if repeat_stride is not None else None
            ),
            default_context="Storage",
        )

    return None


def _infer_repeat_stride(
    event: str,
    entry: dict[str, object],
) -> Optional[int]:
    configured = _optional_int(entry.get("repeat_stride"))
    if configured is not None:
        return configured
    item_id_offset = _optional_int(entry.get("item_id_offset"))
    quantity_offset = _optional_int(entry.get("quantity_offset"))
    item_instance_offset = _optional_int(entry.get("item_instance_offset"))
    length = _optional_int(entry.get("length"))
    if (
        event == "INVENTORY_TRANSFER"
        and item_id_offset == 33
        and quantity_offset == 37
        and item_instance_offset == 68
        and length is not None
        and length > CURRENT_INVENTORY_TRANSFER_RECORD_BASE_LENGTH
        and (
            length - CURRENT_INVENTORY_TRANSFER_RECORD_BASE_LENGTH
        )
        % 228
        == 0
    ):
        return 228
    quantity_added_offset = _optional_int(entry.get("quantity_added_offset"))
    destination_instance_offset = _optional_int(
        entry.get("destination_instance_offset")
    )
    if (
        event == "STORAGE_ITEM_DELTA"
        and item_id_offset == 37
        and quantity_added_offset == 41
        and destination_instance_offset == 72
        and length is not None
        and length > CURRENT_STORAGE_DELTA_RECORD_BASE_LENGTH
        and (length - CURRENT_STORAGE_DELTA_RECORD_BASE_LENGTH)
        % CURRENT_STORAGE_DELTA_RECORD_STRIDE
        == 0
    ):
        return CURRENT_STORAGE_DELTA_RECORD_STRIDE
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


def _optional_int(value: object, width: int = 0) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"expected a non-negative integer, got {value!r}")
    return value + width if width else value


def _minimum_event_length(length: Optional[int], *ends: Optional[int]) -> int:
    minimum = max((end for end in ends if end is not None), default=5)
    if length is not None and length > 0:
        minimum = max(minimum, length)
    return minimum


def _dedupe_event_specs(specs: Iterable[EventSpec]) -> list[EventSpec]:
    output: list[EventSpec] = []
    seen: set[tuple[object, ...]] = set()
    for spec in specs:
        key = (
            spec.label,
            spec.opcode,
            spec.item_offset,
            spec.quantity_offset,
            spec.inventory_slot_offset,
            spec.source_context_offset,
            spec.storage_instance_offset,
        )
        if key in seen:
            continue
        seen.add(key)
        output.append(spec)
    return output
