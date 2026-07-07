"""Bridge from the current prototype parser into toolkit events.

This module is intentionally the only place that imports
``home_internet_analyzer``. Future work should migrate TCP reassembly, frame
parsing, and decoders into native toolkit modules behind the same public API.
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable, Optional

from .events import BDOEvent, Flow
from .filters import EventFilter
from .profiles import default_profile_path


def legacy_parser():
    try:
        import home_internet_analyzer as legacy  # type: ignore
    except ImportError as exc:
        raise RuntimeError(
            "The transitional toolkit bridge requires home_internet_analyzer.py "
            "on PYTHONPATH. Move the native parser modules into the package "
            "before publishing it as a standalone repo."
        ) from exc
    return legacy


def select_event_specs(
    *,
    opcode_profile: str | Path | None = None,
    include_legacy_opcodes: bool = False,
    ignore_opcode_profile: bool = False,
):
    legacy = legacy_parser()
    profile_path = Path(opcode_profile) if opcode_profile is not None else default_profile_path()
    return legacy.select_logging_event_specs(
        opcodes_path=profile_path,
        include_legacy=include_legacy_opcodes,
        ignore_opcodes=ignore_opcode_profile,
    )


def _event_type_for_label(label: str) -> str:
    return {
        "LOOT_PREVIEW": "loot_preview",
        "INVENTORY_TRANSFER": "item_received",
        "INVENTORY_TO_STORAGE": "storage_delta",
    }.get(label, label.lower())


def _source_label(legacy, event) -> Optional[str]:
    formatted = legacy.format_source_context(
        event.source_context_candidate,
        event.default_context,
    )
    if formatted == "UNKNOWN":
        return None
    if formatted.startswith('"') and formatted.endswith('"'):
        return formatted[1:-1]
    return formatted


def _hex(value: Optional[bytes]) -> Optional[str]:
    if value is None:
        return None
    return f"0x{value.hex()}"


def toolkit_event_from_legacy(event) -> BDOEvent:
    legacy = legacy_parser()
    base_item_id, enhancement_level, enhancement = legacy.split_item_id_enhancement(
        event.item_id
    )
    if enhancement_level is None:
        base_item_id = None

    extra = {}
    if event.stream_sequence is not None:
        extra["stream_sequence"] = event.stream_sequence
    if event.label == "INVENTORY_TO_STORAGE":
        extra["storage_delta"] = event.quantity

    return BDOEvent(
        event_type=_event_type_for_label(event.label),
        timestamp=event.context.timestamp,
        flow=Flow(
            source_ip=event.context.flow.source_ip,
            source_port=event.context.flow.source_port,
            destination_ip=event.context.flow.destination_ip,
            destination_port=event.context.flow.destination_port,
        ),
        item_id=event.item_id,
        quantity=event.quantity,
        source=_source_label(legacy, event),
        raw_context=_hex(event.source_context_candidate),
        opcode=event.opcode,
        message_length=event.message_length,
        legacy_label=event.label,
        base_item_id=base_item_id,
        enhancement_level=enhancement_level,
        enhancement=enhancement,
        inventory_slot=event.inventory_slot,
        item_instance=_hex(event.item_instance),
        storage_instance=_hex(event.storage_instance),
        record_index=event.record_index,
        record_count=event.record_count,
        record_offset=event.record_offset,
        confidence="observed",
        extra=extra,
    )


class ToolkitLootSniffer:
    """LootSniffer subclass that emits structured toolkit events."""

    def __init__(
        self,
        *,
        server_ports: tuple[int, ...],
        event_filter: Optional[EventFilter] = None,
        on_event: Optional[Callable[[BDOEvent], None]] = None,
        opcode_profile: str | Path | None = None,
        include_legacy_opcodes: bool = False,
        ignore_opcode_profile: bool = False,
    ) -> None:
        legacy = legacy_parser()
        event_specs, profile_source = select_event_specs(
            opcode_profile=opcode_profile,
            include_legacy_opcodes=include_legacy_opcodes,
            ignore_opcode_profile=ignore_opcode_profile,
        )

        class _Sniffer(legacy.LootSniffer):
            def __init__(self, outer: "ToolkitLootSniffer") -> None:
                self._outer = outer
                super().__init__(
                    server_ports=server_ports,
                    event_specs=event_specs,
                    opcode_profile_source=profile_source,
                )

            def _on_event(self, event, raw_message: bytes) -> None:
                if self._is_duplicate_event(event, raw_message):
                    return
                self.events_found += 1
                toolkit_event = toolkit_event_from_legacy(event)
                self._outer._emit(toolkit_event)

        self.events: list[BDOEvent] = []
        self.event_filter = event_filter
        self.on_event = on_event
        self.sniffer = _Sniffer(self)
        self.profile_source = profile_source

    def _emit(self, event: BDOEvent) -> None:
        if self.event_filter is not None and not self.event_filter.allows(event):
            return
        self.events.append(event)
        if self.on_event is not None:
            self.on_event(event)

