"""Stable event objects emitted by the toolkit.

The packet protocol is still moving, so these models intentionally keep an
``extra`` mapping for newly discovered fields that should not require a schema
break on day one.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Mapping, Optional


def _freeze_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType(
            {key: _freeze_value(item) for key, item in value.items()}
        )
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_value(item) for item in value)
    if isinstance(value, (set, frozenset)):
        return frozenset(_freeze_value(item) for item in value)
    return value


def _thaw_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw_value(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw_value(item) for item in value]
    if isinstance(value, frozenset):
        return [_thaw_value(item) for item in value]
    return value


def _hashable_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return frozenset(
            (key, _hashable_value(item)) for key, item in value.items()
        )
    if isinstance(value, (tuple, list)):
        return tuple(_hashable_value(item) for item in value)
    if isinstance(value, (set, frozenset)):
        return frozenset(_hashable_value(item) for item in value)
    return value


@dataclass(frozen=True)
class Flow:
    """Network flow for a server-to-client packet stream."""

    source_ip: str
    source_port: int
    destination_ip: str
    destination_port: int

    def __str__(self) -> str:
        return (
            f"{self.source_ip}:{self.source_port} -> "
            f"{self.destination_ip}:{self.destination_port}"
        )

    def to_dict(self) -> dict[str, object]:
        return dataclasses.asdict(self)


@dataclass(frozen=True)
class BDOEvent:
    """One decoded gameplay-relevant packet event.

    ``event_type`` is the stable app-facing category. ``legacy_label`` preserves
    the current prototype label so migrations can stay lossless while the event
    model matures.
    """

    event_type: str
    timestamp: float
    flow: Flow
    item_id: int
    quantity: int
    source: Optional[str] = None
    raw_context: Optional[str] = None
    opcode: Optional[int] = None
    message_length: Optional[int] = None
    legacy_label: Optional[str] = None
    base_item_id: Optional[int] = None
    enhancement_level: Optional[int] = None
    enhancement: Optional[str] = None
    inventory_slot: Optional[int] = None
    item_instance: Optional[str] = None
    storage_instance: Optional[str] = None
    record_index: Optional[int] = None
    record_count: Optional[int] = None
    record_offset: Optional[int] = None
    confidence: Optional[str] = None
    # "worker" | "manual" | "unknown" on storage_delta events, None elsewhere.
    # Classified from packet structure; the per-signal audit trail stays in
    # extra["deposit_origin_evidence"]. Graduated from extra 2026-07-08.
    deposit_origin: Optional[str] = None
    extra: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "extra", _freeze_value(self.extra))

    @property
    def timestamp_text(self) -> str:
        return dt.datetime.fromtimestamp(self.timestamp).strftime("%H:%M:%S.%f")[:-3]

    @property
    def timestamp_iso(self) -> str:
        """Deterministic UTC ISO-8601 timestamp for serialization."""
        return (
            dt.datetime.fromtimestamp(self.timestamp, tz=dt.timezone.utc)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z")
        )

    def to_dict(self) -> dict[str, Any]:
        output: dict[str, Any] = {
            "event_type": self.event_type,
            "timestamp": self.timestamp,
            "timestamp_iso": self.timestamp_iso,
            "flow": self.flow.to_dict(),
            "item_id": self.item_id,
            "quantity": self.quantity,
        }
        optional = {
            "source": self.source,
            "raw_context": self.raw_context,
            "opcode": f"0x{self.opcode:04X}" if self.opcode is not None else None,
            "message_length": self.message_length,
            "legacy_label": self.legacy_label,
            "base_item_id": self.base_item_id,
            "enhancement_level": self.enhancement_level,
            "enhancement": self.enhancement,
            "inventory_slot": (
                f"0x{self.inventory_slot:02x}"
                if self.inventory_slot is not None
                else None
            ),
            "item_instance": self.item_instance,
            "storage_instance": self.storage_instance,
            "record_index": self.record_index,
            "record_count": self.record_count,
            "record_offset": self.record_offset,
            "confidence": self.confidence,
            "deposit_origin": self.deposit_origin,
        }
        for key, value in optional.items():
            if value is not None:
                output[key] = value
        if self.extra:
            output["extra"] = _thaw_value(self.extra)
        return output

    def __hash__(self) -> int:
        values = tuple(
            getattr(self, field_info.name)
            for field_info in dataclasses.fields(self)
            if field_info.name != "extra"
        )
        return hash((values, _hashable_value(self.extra)))

    def format_human(self) -> str:
        parts = [
            f"[{self.timestamp_text}]",
            self.event_type.upper(),
            f"source={self.source!r}" if self.source else "source=None",
            f"item_id={self.item_id}",
            f"quantity={self.quantity}",
        ]
        if self.base_item_id is not None:
            parts.append(f"base_item_id={self.base_item_id}")
        if self.enhancement_level is not None:
            parts.append(f"enhancement_level={self.enhancement_level}")
        if self.enhancement is not None:
            parts.append(f"enhancement={self.enhancement}")
        if self.record_index is not None and self.record_count is not None:
            parts.append(f"record_index={self.record_index}/{self.record_count}")
        if self.item_instance is not None:
            parts.append(f"item_instance={self.item_instance}")
        if self.storage_instance is not None:
            parts.append(f"storage_instance={self.storage_instance}")
        if self.deposit_origin is not None:
            parts.append(f"deposit_origin={self.deposit_origin}")
        return " ".join(parts)

