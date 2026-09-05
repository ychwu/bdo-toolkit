"""Private calibration models implementation."""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from ._constants import OPCODE_PROFILE_EVENTS, _FAMILY_LABELS


@dataclass(frozen=True)
class MessageSpec:
    event: str
    opcode: int
    length: Optional[int]
    item_id_offset: Optional[int] = None
    quantity_offset: Optional[int] = None
    item_instance_offset: Optional[int] = None
    context_offset: Optional[int] = None
    record_count_offset: Optional[int] = field(default=None, kw_only=True)
    inventory_slot_offset: Optional[int] = None
    repeat_stride: Optional[int] = None
    source_instance_offset: Optional[int] = None
    quantity_removed_offset: Optional[int] = None
    quantity_added_offset: Optional[int] = None
    destination_instance_offset: Optional[int] = None
    confidence: str = "calibrated"
    source: str = "auto-calibration"
    observed_at: Optional[str] = None
    score: Optional[float] = None

    def __post_init__(self) -> None:
        if self.event not in OPCODE_PROFILE_EVENTS:
            raise ValueError(f"unknown profile event {self.event!r}")
        if isinstance(self.opcode, bool) or not isinstance(self.opcode, int):
            raise ValueError("opcode must be an integer")
        if not 0 <= self.opcode <= 0xFFFF:
            raise ValueError("opcode must be a uint16")
        if self.length is not None and (
            isinstance(self.length, bool)
            or not isinstance(self.length, int)
            or not 5 <= self.length <= 0xFFFF
        ):
            raise ValueError("length must be None or an integer from 5 to 65535")
        for name in (
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
        ):
            value = getattr(self, name)
            if value is not None and (
                isinstance(value, bool) or not isinstance(value, int) or value < 0
            ):
                raise ValueError(f"{name} must be None or a non-negative integer")
        if self.repeat_stride is not None and (
            isinstance(self.repeat_stride, bool)
            or not isinstance(self.repeat_stride, int)
            or self.repeat_stride <= 0
        ):
            raise ValueError("repeat_stride must be None or a positive integer")
        if self.score is not None and (
            isinstance(self.score, bool)
            or not isinstance(self.score, (int, float))
            or not math.isfinite(self.score)
            or not 0 <= self.score <= 1
        ):
            raise ValueError("score must be None or a finite number from 0 to 1")
        if self.length is not None:
            field_widths = {
                "item_id_offset": 4,
                "quantity_offset": 4,
                "item_instance_offset": 8,
                "context_offset": 4,
                "record_count_offset": 2,
                "inventory_slot_offset": 1,
                "source_instance_offset": 8,
                "quantity_removed_offset": 4,
                "quantity_added_offset": 4,
                "destination_instance_offset": 8,
            }
            for name, width in field_widths.items():
                value = getattr(self, name)
                if value is not None and value + width > self.length:
                    raise ValueError(f"{name} extends beyond the declared length")
        if self.event == "STORAGE_ITEM_DELTA" and self.item_id_offset is not None:
            if (
                self.context_offset is not None
                and self.context_offset + 4 > self.item_id_offset
            ):
                raise ValueError("context_offset must end before item_id_offset")
            if (
                self.record_count_offset is not None
                and self.record_count_offset + 2 > self.item_id_offset
            ):
                raise ValueError("record_count_offset must end before item_id_offset")

    def dedupe_key(self) -> tuple[object, ...]:
        return (
            self.event,
            self.opcode,
            self.length,
            self.item_id_offset,
            self.quantity_offset,
            self.item_instance_offset,
            self.context_offset,
            self.record_count_offset,
            self.inventory_slot_offset,
            self.source_instance_offset,
            self.quantity_removed_offset,
            self.quantity_added_offset,
            self.destination_instance_offset,
            self.repeat_stride,
        )

    def to_json_dict(self) -> dict[str, object]:
        output: dict[str, object] = {
            "event": self.event,
            "opcode": f"0x{self.opcode:04X}",
            "length": self.length,
            "confidence": self.confidence,
            "source": self.source,
        }
        optional_fields = {
            "item_id_offset": self.item_id_offset,
            "quantity_offset": self.quantity_offset,
            "item_instance_offset": self.item_instance_offset,
            "context_offset": self.context_offset,
            "record_count_offset": self.record_count_offset,
            "inventory_slot_offset": self.inventory_slot_offset,
            "repeat_stride": self.repeat_stride,
            "source_instance_offset": self.source_instance_offset,
            "quantity_removed_offset": self.quantity_removed_offset,
            "quantity_added_offset": self.quantity_added_offset,
            "destination_instance_offset": self.destination_instance_offset,
            "observed_at": self.observed_at,
            "score": round(self.score, 3) if self.score is not None else None,
        }
        for key, value in optional_fields.items():
            if value is not None:
                output[key] = value
        return output


class DirectionMismatchError(ValueError):
    """A capture's structure contradicts the explicitly declared action.

    Raised only in single-direction calibration (``action=`` set to a specific
    transfer). Auto calibration never raises this; it classifies each direction
    from structure and keeps whatever it can confirm.
    """


class CalibrationAuthorityError(ValueError):
    """A captured target exists but cannot yield a safe decoder profile."""


@dataclass(frozen=True)
class DirectionEvidence:
    """Why a candidate record was assigned (or not) to a transfer family.

    ``detected_family`` is ``"into_storage"``, ``"into_inventory"``, or ``None``
    when the two structural features disagree or neither fires. See
    :func:`detect_transfer_family`.
    """

    action: str
    opcode: int
    detected_family: Optional[str]
    reference_frame: bool
    context_label: bool
    storage_context: bool = False

    def to_json_dict(self) -> dict[str, object]:
        return {
            "action": self.action,
            "opcode": f"0x{self.opcode:04X}",
            "detected_family": self.detected_family,
            "reference_frame": self.reference_frame,
            "context_label": self.context_label,
            "storage_context": self.storage_context,
        }


@dataclass(frozen=True)
class CalibrationRetention:
    """Observed-versus-retained live calibration evidence.

    Live sessions keep the newest contiguous frame tail within both limits.
    ``truncated`` therefore means older evidence was intentionally evicted and
    the resulting calibration describes only the retained tail.
    """

    frames_observed: int
    frames_retained: int
    frames_discarded: int
    bytes_observed: Optional[int]
    bytes_retained: Optional[int]
    bytes_discarded: Optional[int]
    max_retained_frames: Optional[int] = None
    max_retained_bytes: Optional[int] = None

    def __post_init__(self) -> None:
        for name in (
            "frames_observed",
            "frames_retained",
            "frames_discarded",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"{name} must be a non-negative integer")
        if self.frames_retained + self.frames_discarded != self.frames_observed:
            raise ValueError(
                "retained and discarded frame counts must equal frames_observed"
            )

        byte_values = (
            self.bytes_observed,
            self.bytes_retained,
            self.bytes_discarded,
        )
        if any(value is None for value in byte_values):
            if not all(value is None for value in byte_values):
                raise ValueError("byte retention counters must be all set or all None")
        else:
            for name, value in zip(
                ("bytes_observed", "bytes_retained", "bytes_discarded"),
                byte_values,
            ):
                if (
                    isinstance(value, bool)
                    or not isinstance(value, int)
                    or value < 0
                ):
                    raise ValueError(f"{name} must be a non-negative integer")
            assert self.bytes_observed is not None
            assert self.bytes_retained is not None
            assert self.bytes_discarded is not None
            if self.bytes_retained + self.bytes_discarded != self.bytes_observed:
                raise ValueError(
                    "retained and discarded byte counts must equal bytes_observed"
                )

        for name in ("max_retained_frames", "max_retained_bytes"):
            value = getattr(self, name)
            if value is not None and (
                isinstance(value, bool)
                or not isinstance(value, int)
                or value <= 0
            ):
                raise ValueError(f"{name} must be None or a positive integer")
        if (
            self.max_retained_frames is not None
            and self.frames_retained > self.max_retained_frames
        ):
            raise ValueError("frames_retained exceeds max_retained_frames")
        if (
            self.max_retained_bytes is not None
            and self.bytes_retained is not None
            and self.bytes_retained > self.max_retained_bytes
        ):
            raise ValueError("bytes_retained exceeds max_retained_bytes")

    @property
    def truncated(self) -> bool:
        return self.frames_discarded > 0 or bool(self.bytes_discarded)

    @property
    def bounded(self) -> bool:
        return (
            self.max_retained_frames is not None
            or self.max_retained_bytes is not None
        )

    def to_json_dict(self) -> dict[str, object]:
        return {
            "frames_observed": self.frames_observed,
            "frames_retained": self.frames_retained,
            "frames_discarded": self.frames_discarded,
            "bytes_observed": self.bytes_observed,
            "bytes_retained": self.bytes_retained,
            "bytes_discarded": self.bytes_discarded,
            "max_retained_frames": self.max_retained_frames,
            "max_retained_bytes": self.max_retained_bytes,
            "truncated": self.truncated,
        }


@dataclass(frozen=True)
class CalibrationResult:
    """Promoted message specs plus diagnostics for rejected candidates.

    The fields are the raw record; ``events_found`` / ``specs_by_event()`` /
    ``summary()`` / ``to_json_dict()`` are pure, read-only views of them.
    There is deliberately no boolean ``ok``: success is per-event (a capture
    can promote STORAGE_ITEM_DELTA yet miss its companion specs), so check
    ``events_found`` against the events you need instead.
    """

    specs: tuple[MessageSpec, ...]
    ignored: tuple[str, ...]
    frames_scanned: int
    evidence: tuple[DirectionEvidence, ...] = ()
    calibration_item_id: Optional[int] = None
    retention: CalibrationRetention = field(kw_only=True)

    def __post_init__(self) -> None:
        if not isinstance(self.retention, CalibrationRetention):
            raise TypeError("retention must be a CalibrationRetention")
        if self.frames_scanned != self.retention.frames_retained:
            raise ValueError(
                "frames_scanned must equal retention.frames_retained"
            )

    @property
    def events_found(self) -> frozenset[str]:
        """Event names that got at least one promoted spec.

        Supports readable completeness checks::

            {"STORAGE_ITEM_DELTA", "SOURCE_STACK_DECREMENT"} <= result.events_found
        """
        return frozenset(spec.event for spec in self.specs)

    def specs_by_event(self) -> dict[str, tuple[MessageSpec, ...]]:
        """Promoted specs grouped by event name.

        Values are tuples because a capture can promote more than one
        candidate layout for the same event.
        """
        grouped: dict[str, list[MessageSpec]] = {}
        for spec in self.specs:
            grouped.setdefault(spec.event, []).append(spec)
        return {event: tuple(specs) for event, specs in grouped.items()}

    def detected_directions(self) -> frozenset[str]:
        """Transfer directions confirmed by structure, as human-readable labels
        (``"inventory->storage"`` / ``"storage->inventory"``)."""
        return frozenset(
            _FAMILY_LABELS[e.detected_family]
            for e in self.evidence
            if e.detected_family in _FAMILY_LABELS
        )

    def summary(self) -> str:
        """Human-readable multi-line report; print or log it as-is."""
        lines = [f"scanned {self.frames_scanned} frames"]
        retention = self.retention
        if retention.bounded:
            status = "truncated" if retention.truncated else "complete"
            lines.append(
                f"live retention {status}: observed {retention.frames_observed}, "
                f"retained {retention.frames_retained}, "
                f"discarded {retention.frames_discarded} frame(s)"
            )
        if self.specs:
            found = ", ".join(
                f"{spec.event} (0x{spec.opcode:04X})" for spec in self.specs
            )
            lines.append(f"promoted {len(self.specs)} spec(s): {found}")
        else:
            lines.append("no message specs promoted")
        directions = self.detected_directions()
        if directions:
            lines.append(f"detected direction(s): {', '.join(sorted(directions))}")
        if self.ignored:
            lines.append(
                f"ignored {len(self.ignored)} candidate(s) (see .ignored for reasons)"
            )
        return "\n".join(lines)

    def to_json_dict(self) -> dict[str, object]:
        """The whole result as JSON-ready data — the shape to attach to bug
        reports or logs. Mirrors ``MessageSpec.to_json_dict()`` for specs."""
        return {
            "frames_scanned": self.frames_scanned,
            "calibration_item_id": self.calibration_item_id,
            "retention": self.retention.to_json_dict(),
            "specs": [spec.to_json_dict() for spec in self.specs],
            "ignored": list(self.ignored),
            "evidence": [e.to_json_dict() for e in self.evidence],
        }


@dataclass(frozen=True)
class ProfileUpdate:
    """Outcome of persisting calibration specs into a profile file."""

    path: Path
    added: tuple[MessageSpec, ...]
    replaced_events: tuple[str, ...]
    backup_path: Optional[Path]
    written: bool = True

    def summary(self) -> str:
        """Human-readable multi-line report; print or log it as-is."""
        if not self.written:
            return (
                f"no new specs added; no profile changes; "
                f"{self.path} was not written"
            )
        lines = [f"wrote {self.path}"]
        if self.backup_path is not None:
            lines.append(f"backup at {self.backup_path}")
        if self.replaced_events:
            lines.append(f"replaced {', '.join(self.replaced_events)}")
        if self.added:
            for spec in self.added:
                lines.append(f"added {spec.event} opcode=0x{spec.opcode:04X}")
        else:
            lines.append("no new specs added (all were already present)")
        return "\n".join(lines)
