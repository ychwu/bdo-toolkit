"""Turn opcode profile JSON entries into decodable event specs."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

from ._protocol import (
    CURRENT_EVENT_SPECS,
    CURRENT_STORAGE_DELTA_CONTEXT_OFFSET,
    CURRENT_STORAGE_DELTA_RECORD_STRIDE,
    LEGACY_EVENT_SPECS,
    EventSpec,
)


class ProfileError(ValueError):
    """Raised when an opcode profile file cannot be parsed."""


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
) -> tuple[tuple[EventSpec, ...], str]:
    """Resolve the event specs to decode with and a human-readable source."""
    profile = (
        LoadedSpecProfile(active=False, specs=(), source="")
        if ignore_opcodes
        else load_spec_profile(opcodes_path)
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


def load_spec_profile(path: Path) -> LoadedSpecProfile:
    if not path.exists():
        return LoadedSpecProfile(active=False, specs=(), source=str(path))

    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError as exc:
        raise ProfileError(f"Could not parse opcodes JSON {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ProfileError(f"Opcodes JSON {path} must be a top-level object")

    if not bool(data.get("profile_active", False)):
        return LoadedSpecProfile(active=False, specs=(), source=str(path))

    specs: list[EventSpec] = []
    raw_specs = data.get("specs", {})
    if isinstance(raw_specs, dict):
        for event, entries in raw_specs.items():
            if not isinstance(event, str) or not isinstance(entries, list):
                continue
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                spec = _event_spec_from_entry(event, entry)
                if spec is not None:
                    specs.append(spec)

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
        return EventSpec(
            label="INVENTORY_TRANSFER",
            opcode=opcode,
            item_offset=item_id_offset,
            quantity_offset=quantity_offset,
            min_message_length=_minimum_event_length(
                length,
                item_id_offset + 4,
                quantity_offset + 4,
                _optional_int(entry.get("item_instance_offset"), width=8),
            ),
            inventory_slot_offset=_optional_int(entry.get("inventory_slot_offset")),
            source_context_offset=_optional_int(entry.get("context_offset")),
            item_instance_offset=_optional_int(entry.get("item_instance_offset")),
            repeat_stride=_infer_repeat_stride(event, opcode, entry),
        )

    if event == "STORAGE_ITEM_DELTA":
        quantity_added_offset = _optional_int(entry.get("quantity_added_offset"))
        destination_instance_offset = _optional_int(
            entry.get("destination_instance_offset")
        )
        if item_id_offset is None or quantity_added_offset is None:
            return None
        context_offset = _optional_int(entry.get("context_offset"))
        if (
            context_offset is None
            and opcode == 0x0E6A
            and item_id_offset == 37
            and quantity_added_offset == 41
            and destination_instance_offset == 72
        ):
            context_offset = CURRENT_STORAGE_DELTA_CONTEXT_OFFSET
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
            ),
            source_context_offset=context_offset,
            storage_instance_offset=destination_instance_offset,
            repeat_stride=_infer_repeat_stride(event, opcode, entry),
            default_context="Storage",
        )

    return None


def _infer_repeat_stride(
    event: str,
    opcode: int,
    entry: dict[str, object],
) -> Optional[int]:
    configured = _optional_int(entry.get("repeat_stride"))
    if configured is not None:
        return configured
    item_id_offset = _optional_int(entry.get("item_id_offset"))
    quantity_offset = _optional_int(entry.get("quantity_offset"))
    item_instance_offset = _optional_int(entry.get("item_instance_offset"))
    if (
        event == "INVENTORY_TRANSFER"
        and opcode == 0x0F16
        and item_id_offset == 33
        and quantity_offset == 37
        and item_instance_offset == 68
    ):
        return 228
    quantity_added_offset = _optional_int(entry.get("quantity_added_offset"))
    destination_instance_offset = _optional_int(
        entry.get("destination_instance_offset")
    )
    if (
        event == "STORAGE_ITEM_DELTA"
        and opcode == 0x0E6A
        and item_id_offset == 37
        and quantity_added_offset == 41
        and destination_instance_offset == 72
    ):
        return CURRENT_STORAGE_DELTA_RECORD_STRIDE
    return None


def _parse_opcode(value: object) -> Optional[int]:
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
    if not isinstance(value, int):
        return None
    if value < 0:
        return None
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
