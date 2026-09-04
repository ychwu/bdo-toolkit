"""Opcode profile calibration.

After a game patch shifts opcodes or byte offsets, developers can rebuild a
local opcode profile from a capture of a known in-game action:

    from bdo_toolkit.calibration import calibrate_pcap, update_profile

    result = calibrate_pcap(
        "unstackable_1_in_4_in_5_out.pcapng",
        item_id=15156,         # replace with the unstackable item used
        quantity=1,            # each serialized unstackable record has qty 1
        action="auto",
    )
    update_profile(result, "opcodes.json")

Then point the decoding APIs at the local profile:

    replay_pcap("session.pcapng", opcode_profile="opcodes.json")

Storage calibration requires two distinct validated record counts so a moving
wrapper flag cannot be mistaken for the authoritative count column. Capture,
for example, a deposit of one matching unstackable followed by a deposit of
four, then one withdrawal of all five in the same automatic session. The
single deposit also anchors manual-origin evidence, while the multi deposit and
withdrawal prove repeated geometry in both directions. The calibration
session only observes these user-performed actions: ``quantity=1`` remains the
expected value in every serialized record and is not changed to the action's
batch size. The calibration heuristics score every frame containing the watched
item ID and promote only structurally proven layouts.

The batch sizes are observed evidence, not API arguments or hard-coded values;
another valid sequence is deposit one, deposit six, then withdraw seven.
Repeating the same deposit count does not establish storage count authority.
``action="auto"`` covers transfer directions only. Loot preview requires a
separate ``action="loot-preview"`` capture; when its quantity is random, watch
the known item ID and leave ``quantity=None``.
"""

from __future__ import annotations

from collections import deque
import datetime as dt
import json
import math
import shutil
from dataclasses import dataclass, field, replace
from pathlib import Path
from threading import Lock, RLock
from typing import Any, Iterable, Optional

from ._capture_backend import (
    make_packet_handler,
    replay_pcap_file,
    validate_server_ports,
)
from ._capture_options import PacketCaptureOptions
from ._capture_runtime import (
    DEFAULT_STARTUP_TIMEOUT_SECONDS,
    LivePacketCapture,
    _attach_cleanup_owner,
)
from ._profile_io import (
    atomic_write_text as _atomic_write_text,
    next_backup_path as _backup_path,
)
from ._framing import FrameCollectorScanner
from ._protocol import (
    CHARACTER_LOAD_CONTEXT,
    DEFAULT_SERVER_PORTS,
    LOOT_PREVIEW_SENTINEL_INSTANCE,
    MAX_PLAUSIBLE_ITEM_ID,
    SOURCE_CONTEXT_LABELS,
    STORAGE_DELTA_CONTEXTS,
    BDOFrame,
    storage_destination_candidates,
)
from ._reassembly import FlowManager
from ._specs import _validate_loot_profile_entries
from .profiles import (
    OPCODE_PROFILE_SCHEMA_VERSION,
    ProfileError,
    _validate_profile_entry,
    load_opcode_profile,
)

__all__ = [
    "CALIBRATION_ACTIONS",
    "DEFAULT_CALIBRATION_MAX_RETAINED_BYTES",
    "DEFAULT_CALIBRATION_MAX_RETAINED_FRAMES",
    "CalibrationAuthorityError",
    "CalibrationResult",
    "CalibrationRetention",
    "CalibrationSession",
    "DirectionEvidence",
    "DirectionMismatchError",
    "MessageSpec",
    "ProfileError",
    "ProfileUpdate",
    "calibrate_and_update",
    "calibrate_frames",
    "calibrate_live",
    "calibrate_pcap",
    "collect_frames_pcap",
    "detect_transfer_family",
    "reset_profile",
    "update_profile",
]

CALIBRATION_ACTIONS = (
    "loot-preview",
    "storage-to-inventory",
    "inventory-to-storage",
)

# Live calibration retains the newest contiguous tail. These defaults cover
# ordinary short item-transfer workflows by a wide margin while placing a
# hard ceiling on an accidentally unattended session.
DEFAULT_CALIBRATION_MAX_RETAINED_FRAMES = 50_000
DEFAULT_CALIBRATION_MAX_RETAINED_BYTES = 64 * 1024 * 1024
_CALIBRATION_MAX_ACTIVE_FLOWS = 64

OPCODE_PROFILE_EVENTS = (
    "LOOT_PREVIEW",
    "INVENTORY_TRANSFER",
    "SOURCE_CONTAINER_DECREMENT",
    "SOURCE_STACK_DECREMENT",
    "SOURCE_ITEM_REFERENCE",
    "STORAGE_ITEM_DELTA",
)


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


_FAMILY_LABELS = {
    "into_inventory": "storage->inventory",
    "into_storage": "inventory->storage",
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


class _FrameIndex:
    """One-pass same-flow position index for calibration context lookups."""

    def __init__(self, frames: list[BDOFrame]) -> None:
        by_flow: dict[tuple[object, int], list[BDOFrame]] = {}
        positions: dict[
            int,
            Optional[tuple[tuple[object, int], int]],
        ] = {}
        for frame in frames:
            flow_identity = (
                frame.context.flow,
                frame.context.flow_generation,
            )
            flow_frames = by_flow.setdefault(flow_identity, [])
            identity = id(frame)
            location = (flow_identity, len(flow_frames))
            positions[identity] = (
                location if identity not in positions else None
            )
            flow_frames.append(frame)
        self._by_flow = {
            flow: tuple(flow_frames) for flow, flow_frames in by_flow.items()
        }
        self._positions = positions

    def context_before(
        self,
        target_frame: BDOFrame,
        context_frames: int,
    ) -> tuple[BDOFrame, ...]:
        if context_frames <= 0:
            return ()
        flow_identity = (
            target_frame.context.flow,
            target_frame.context.flow_generation,
        )
        flow_frames = self._by_flow.get(flow_identity, ())
        has_identity = id(target_frame) in self._positions
        location = self._positions.get(id(target_frame))
        index = None if location is None else location[1]
        if not has_identity:
            # Public helpers may be passed an equal reconstructed frame rather
            # than the exact object from ``frames``. Accept one unambiguous
            # equality match; fail closed if multiple positions compare equal.
            matches = tuple(
                candidate_index
                for candidate_index, candidate in enumerate(flow_frames)
                if candidate == target_frame
            )
            index = matches[0] if len(matches) == 1 else None
        if index is None:
            return ()
        return flow_frames[max(0, index - context_frames) : index]


@dataclass(frozen=True)
class _Options:
    item_id: int
    quantity: Optional[int]
    action: str
    context_frames: int
    min_confidence: float
    frame_index: Optional[_FrameIndex] = None


@dataclass(frozen=True)
class _CalibratedItemRecord:
    frame: BDOFrame
    item_offset: int
    item_id: int
    quantity: int
    instance_offset: Optional[int]
    instance: Optional[bytes]
    confidence: float
    reasons: tuple[str, ...]


def _validate_calibration_options(
    *,
    item_id: int,
    quantity: Optional[int],
    action: str,
    context_frames: int,
    min_confidence: float,
) -> None:
    if isinstance(item_id, bool) or not isinstance(item_id, int):
        raise ValueError("item_id must be an integer")
    if not 1 <= item_id <= MAX_PLAUSIBLE_ITEM_ID:
        raise ValueError(
            f"item_id must be between 1 and {MAX_PLAUSIBLE_ITEM_ID}"
        )
    if quantity is not None and (
        isinstance(quantity, bool)
        or not isinstance(quantity, int)
        or not 1 <= quantity <= 0xFFFFFFFF
    ):
        raise ValueError("quantity must be None or a positive uint32")
    if action != "auto" and action not in CALIBRATION_ACTIONS:
        raise ValueError(
            f"unknown calibration action {action!r}; "
            f"expected one of {CALIBRATION_ACTIONS} or 'auto'"
        )
    if (
        isinstance(context_frames, bool)
        or not isinstance(context_frames, int)
        or context_frames <= 0
    ):
        raise ValueError("context_frames must be a positive integer")
    if (
        isinstance(min_confidence, bool)
        or not isinstance(min_confidence, (int, float))
        or not math.isfinite(min_confidence)
        or not 0 <= min_confidence <= 1
    ):
        raise ValueError("min_confidence must be a finite number from 0 to 1")


def _validate_calibration_retention_limits(
    *,
    max_retained_frames: int,
    max_retained_bytes: int,
    context_frames: int,
) -> None:
    for name, value in (
        ("max_retained_frames", max_retained_frames),
        ("max_retained_bytes", max_retained_bytes),
    ):
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise ValueError(f"{name} must be a positive integer")
    if max_retained_frames <= context_frames:
        raise ValueError(
            "max_retained_frames must be greater than context_frames so one "
            "candidate and its requested preceding context can be retained"
        )


def collect_frames_pcap(
    path: str | Path,
    *,
    ports: tuple[int, ...] = DEFAULT_SERVER_PORTS,
) -> list[BDOFrame]:
    """Reassemble a pcap and return every generic BDO frame."""
    validated_ports = validate_server_ports(ports)
    frames: list[BDOFrame] = []
    manager = FlowManager(
        server_ports=validated_ports,
        scanner_factory=lambda: FrameCollectorScanner(frames.append),
        track_flow_generations=True,
    )
    replay_pcap_file(Path(path), manager)
    return frames


def calibrate_frames(
    frames: list[BDOFrame],
    *,
    item_id: int,
    quantity: Optional[int] = None,
    action: str = "auto",
    context_frames: int = 5,
    min_confidence: float = 0.80,
) -> CalibrationResult:
    """Score collected frames and promote plausible message specs."""
    _validate_calibration_options(
        item_id=item_id,
        quantity=quantity,
        action=action,
        context_frames=context_frames,
        min_confidence=min_confidence,
    )

    frame_index = _FrameIndex(frames)
    options = _Options(
        item_id=item_id,
        quantity=quantity,
        action=action,
        context_frames=context_frames,
        min_confidence=min_confidence,
        frame_index=frame_index,
    )
    ignored: list[str] = []
    evidence: list[DirectionEvidence] = []
    specs: list[MessageSpec] = []

    # Auto covers both transfer directions and classifies each from structure.
    # Storage authority additionally needs two distinct record counts so an
    # unrelated small header integer cannot impersonate the count column. Use
    # an unstackable item with quantity=1 and perform at least two different
    # deposit sizes, plus one storage->inventory move. The guided example uses
    # deposits of 1 and 4 followed by one withdrawal of all 5. Direction is
    # never taken on faith. Loot preview needs a gathering action, so it stays
    # an explicit, optional mode.
    actions: tuple[str, ...]
    if action == "auto":
        actions = ("storage-to-inventory", "inventory-to-storage")
        strict = False
    else:
        actions = (action,)
        strict = True

    for current_action in actions:
        if current_action == "loot-preview":
            specs.extend(_calibrate_loot_preview(frames, options, ignored))
        elif current_action == "storage-to-inventory":
            specs.extend(
                _calibrate_storage_to_inventory(
                    frames, options, ignored, evidence, strict
                )
            )
        elif current_action == "inventory-to-storage":
            specs.extend(
                _calibrate_inventory_to_storage(
                    frames, options, ignored, evidence, strict
                )
            )

    retained_bytes = sum(len(frame.message) for frame in frames)
    return CalibrationResult(
        specs=tuple(_dedupe_message_specs(specs)),
        ignored=tuple(ignored),
        frames_scanned=len(frames),
        evidence=tuple(evidence),
        calibration_item_id=item_id,
        retention=CalibrationRetention(
            frames_observed=len(frames),
            frames_retained=len(frames),
            frames_discarded=0,
            bytes_observed=retained_bytes,
            bytes_retained=retained_bytes,
            bytes_discarded=0,
        ),
    )


def calibrate_pcap(
    path: str | Path,
    *,
    item_id: int,
    quantity: Optional[int] = None,
    action: str = "auto",
    ports: tuple[int, ...] = DEFAULT_SERVER_PORTS,
    context_frames: int = 5,
    min_confidence: float = 0.80,
) -> CalibrationResult:
    """Calibrate message specs from a pcap of a known in-game action."""
    _validate_calibration_options(
        item_id=item_id,
        quantity=quantity,
        action=action,
        context_frames=context_frames,
        min_confidence=min_confidence,
    )
    frames = collect_frames_pcap(path, ports=ports)
    return calibrate_frames(
        frames,
        item_id=item_id,
        quantity=quantity,
        action=action,
        context_frames=context_frames,
        min_confidence=min_confidence,
    )


class CalibrationSession:
    """Live calibration with programmatic start/stop, for embedding in apps.

    The session captures passively in the background between ``start()`` and
    ``stop()``. ``start()`` returns after the capture adapter reports ready,
    or raises after a finite startup deadline. Typical app flow::

        # quantity=1 matches each serialized unstackable record; it is not
        # the number of items moved by each user-performed action.
        session = CalibrationSession(item_id=15156, quantity=1)
        session.start()
        # ... deposit 1; deposit the remaining 4; withdraw all 5;
        #     then have the user click "Done" ...
        result = session.stop()
        if result.specs:
            update_profile(result, my_profile_path)

    Auto calibration (the default) classifies each transfer direction from
    packet structure, so no ``action`` need be declared. Storage authority
    requires at least two distinct deposit counts plus one withdrawal. The
    guided five-unstackable sequence is deposit one, deposit four, withdraw
    all five. The user performs those actions; the session passively observes
    them, and ``quantity=1`` continues to describe every repeated item record.
    The values 1, 4, and 5 are a recommended operator workflow rather than
    constructor arguments; the session learns batch cardinality from traffic.
    Loot preview is a separate explicit action and may use ``quantity=None``
    when only the watched item ID is stable.

    Live evidence is bounded by both ``max_retained_frames`` and
    ``max_retained_bytes``. The newest contiguous frame tail is retained so a
    transfer performed shortly before ``stop()`` keeps its preceding context.
    ``frames_collected`` remains the total-observed progress count; use
    ``frames_retained``, ``frames_discarded``, or ``retention`` to surface
    eviction. A truncated result calibrates only the retained tail.

    TCP reassembly is also bounded to 64 active flows. Admitting another flow
    finalizes the least-recently active state. FIN/RST or session finalization
    releases remaining flow state; live calibration does not configure
    time-based idle eviction.

    Used as a context manager, the capture is stopped on exit even if the
    block raises; call ``stop()`` inside the block to get the result.
    """

    _STARTUP_TIMEOUT_SECONDS = DEFAULT_STARTUP_TIMEOUT_SECONDS

    def __init__(
        self,
        *,
        item_id: int,
        quantity: Optional[int] = None,
        action: str = "auto",
        capture_options: Optional[PacketCaptureOptions] = None,
        context_frames: int = 5,
        min_confidence: float = 0.80,
        max_retained_frames: int = DEFAULT_CALIBRATION_MAX_RETAINED_FRAMES,
        max_retained_bytes: int = DEFAULT_CALIBRATION_MAX_RETAINED_BYTES,
    ) -> None:
        _validate_calibration_options(
            item_id=item_id,
            quantity=quantity,
            action=action,
            context_frames=context_frames,
            min_confidence=min_confidence,
        )
        _validate_calibration_retention_limits(
            max_retained_frames=max_retained_frames,
            max_retained_bytes=max_retained_bytes,
            context_frames=context_frames,
        )
        if capture_options is not None and not isinstance(
            capture_options, PacketCaptureOptions
        ):
            raise TypeError(
                "capture_options must be a PacketCaptureOptions or None"
            )
        self._item_id = item_id
        self._quantity = quantity
        self._action = action
        self._capture_options = capture_options or PacketCaptureOptions()
        self._context_frames = context_frames
        self._min_confidence = min_confidence
        self._max_retained_frames = max_retained_frames
        self._max_retained_bytes = max_retained_bytes
        self._frames: deque[BDOFrame] = deque()
        self._frames_observed = 0
        self._frames_discarded = 0
        self._bytes_observed = 0
        self._bytes_retained = 0
        self._bytes_discarded = 0
        self._manager: Optional[FlowManager] = None
        self._capture: Optional[LivePacketCapture] = None
        self._error: Optional[BaseException] = None
        self._lifecycle_lock = RLock()
        # Scanner callbacks run on the capture thread. Keep their short data
        # lock independent from lifecycle operations that may join that thread.
        self._retention_lock = Lock()

    @property
    def running(self) -> bool:
        with self._lifecycle_lock:
            capture = self._capture
            return capture is not None and capture.running

    @property
    def cleanup_incomplete(self) -> bool:
        """Whether capture shutdown retained resources for a stop retry."""

        with self._lifecycle_lock:
            capture = self._capture
            return capture is not None and capture.cleanup_incomplete

    @property
    def error(self) -> Optional[BaseException]:
        """First startup, callback, or shutdown failure for the current run."""

        with self._lifecycle_lock:
            if self._error is not None:
                return self._error
            capture = self._capture
            return capture.error if capture is not None else None

    @property
    def frames_collected(self) -> int:
        """Total frames observed, including frames later evicted."""

        return self.frames_observed

    @property
    def frames_observed(self) -> int:
        with self._retention_lock:
            return self._frames_observed

    @property
    def frames_retained(self) -> int:
        with self._retention_lock:
            return len(self._frames)

    @property
    def frames_discarded(self) -> int:
        with self._retention_lock:
            return self._frames_discarded

    @property
    def bytes_observed(self) -> int:
        """Total generic-frame payload bytes observed."""

        with self._retention_lock:
            return self._bytes_observed

    @property
    def bytes_retained(self) -> int:
        """Generic-frame payload bytes currently retained."""

        with self._retention_lock:
            return self._bytes_retained

    @property
    def bytes_discarded(self) -> int:
        with self._retention_lock:
            return self._bytes_discarded

    @property
    def retention_truncated(self) -> bool:
        return self.retention.truncated

    @property
    def retention(self) -> CalibrationRetention:
        """Atomic snapshot of observed, retained, and discarded evidence."""

        with self._retention_lock:
            return self._retention_unlocked()

    def start(self) -> None:
        """Begin passive capture and return once the adapter is ready."""

        with self._lifecycle_lock:
            if self._capture is not None or self._manager is not None:
                raise RuntimeError("calibration session is already running")

            self._reset_retention()
            self._error = None
            manager = FlowManager(
                server_ports=self._capture_options.ports,
                scanner_factory=lambda: FrameCollectorScanner(
                    self._retain_frame
                ),
                max_flows=_CALIBRATION_MAX_ACTIVE_FLOWS,
                track_flow_generations=True,
            )
            capture = LivePacketCapture(
                capture_options=self._capture_options,
                on_packet=make_packet_handler(manager),
                startup_timeout=self._STARTUP_TIMEOUT_SECONDS,
            )
            self._manager = manager
            self._capture = capture
            try:
                capture.start()
            except BaseException as exc:
                self._record_error(exc)
                if capture.cleanup_incomplete:
                    # The capture thread may still call into this manager. Keep
                    # both objects alive so stop() can retry verified shutdown
                    # before finalizing stream state.
                    _attach_cleanup_owner(
                        exc,
                        self,
                        context="live calibration startup",
                    )
                    raise
                try:
                    manager.finish()
                except BaseException as cleanup_error:
                    exc.add_note(
                        "calibration flow cleanup also failed: "
                        f"{cleanup_error!r}"
                    )
                self._manager = None
                self._capture = None
                raise

    def stop(self) -> CalibrationResult:
        """End the capture and calibrate the collected frames."""
        with self._lifecycle_lock:
            self._finish_capture()
            with self._retention_lock:
                frames = list(self._frames)
                retention = self._retention_unlocked()
            result = calibrate_frames(
                frames,
                item_id=self._item_id,
                quantity=self._quantity,
                action=self._action,
                context_frames=self._context_frames,
                min_confidence=self._min_confidence,
            )
            return replace(result, retention=retention)

    def raise_if_failed(self) -> None:
        """Re-raise a background capture failure in the calling thread."""

        with self._lifecycle_lock:
            if self._error is not None:
                raise self._error
            capture = self._capture
            if capture is None:
                return
            try:
                capture.raise_if_failed()
            except BaseException as exc:
                self._record_error(exc)
                raise
            if not capture.running:
                error = RuntimeError(
                    "live calibration capture ended unexpectedly"
                )
                self._record_error(error)
                raise error

    def _finish_capture(self) -> None:
        capture = self._capture
        manager = self._manager
        if capture is None or manager is None:
            raise RuntimeError("calibration session was not started")

        failures: list[BaseException] = []

        def retain(error: BaseException) -> None:
            if not any(error is previous for previous in failures):
                failures.append(error)

        if self._error is not None:
            retain(self._error)
        stop_failure: Optional[BaseException] = None
        try:
            capture.stop()
        except BaseException as exc:
            stop_failure = exc
            retain(exc)
        capture_stopped = bool(
            getattr(capture, "stopped", not capture.running)
        )
        if not capture_stopped:
            if stop_failure is None:
                stop_failure = capture.cleanup_error or RuntimeError(
                    "live calibration capture cleanup is incomplete"
                )
                retain(stop_failure)
            self._record_error(failures[0])
            # Reassembly state is still reachable from the capture callback.
            # Do not finish or discard it until a later stop() verifies that
            # the capture thread has terminated.
            raise stop_failure
        try:
            capture.raise_if_failed()
        except BaseException as exc:
            retain(exc)
        try:
            manager.finish()
        except BaseException as exc:
            retain(exc)
        finally:
            self._capture = None
            self._manager = None

        if failures:
            self._record_error(failures[0])
            raise failures[0]

    def _record_error(self, error: BaseException) -> None:
        with self._lifecycle_lock:
            if self._error is None:
                self._error = error

    def _reset_retention(self) -> None:
        with self._retention_lock:
            self._frames.clear()
            self._frames_observed = 0
            self._frames_discarded = 0
            self._bytes_observed = 0
            self._bytes_retained = 0
            self._bytes_discarded = 0

    def _retain_frame(self, frame: BDOFrame) -> None:
        """Retain one frame, evicting the oldest tail prefix as needed."""

        payload_bytes = len(frame.message)
        with self._retention_lock:
            self._frames_observed += 1
            self._bytes_observed += payload_bytes
            self._frames.append(frame)
            self._bytes_retained += payload_bytes

            while self._frames and (
                len(self._frames) > self._max_retained_frames
                or self._bytes_retained > self._max_retained_bytes
            ):
                discarded = self._frames.popleft()
                discarded_bytes = len(discarded.message)
                self._frames_discarded += 1
                self._bytes_discarded += discarded_bytes
                self._bytes_retained -= discarded_bytes

    def _retention_unlocked(self) -> CalibrationRetention:
        return CalibrationRetention(
            frames_observed=self._frames_observed,
            frames_retained=len(self._frames),
            frames_discarded=self._frames_discarded,
            bytes_observed=self._bytes_observed,
            bytes_retained=self._bytes_retained,
            bytes_discarded=self._bytes_discarded,
            max_retained_frames=self._max_retained_frames,
            max_retained_bytes=self._max_retained_bytes,
        )

    def __enter__(self) -> "CalibrationSession":
        with self._lifecycle_lock:
            if self._capture is None:
                self.start()
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        # Safety net only: discard the capture if the block exited without
        # calling stop() (for example on an exception).
        with self._lifecycle_lock:
            if self._capture is None:
                return
            try:
                self._finish_capture()
            except BaseException as cleanup_error:
                if exc_value is None:
                    raise
                if self.cleanup_incomplete:
                    _attach_cleanup_owner(
                        exc_value,
                        self,
                        context="live calibration context",
                    )
                exc_value.add_note(
                    "calibration context cleanup also failed: "
                    f"{cleanup_error!r}"
                )


def calibrate_live(
    *,
    item_id: int,
    capture_seconds: Optional[float] = None,
    quantity: Optional[int] = None,
    action: str = "auto",
    capture_options: Optional[PacketCaptureOptions] = None,
    context_frames: int = 5,
    min_confidence: float = 0.80,
    max_retained_frames: int = DEFAULT_CALIBRATION_MAX_RETAINED_FRAMES,
    max_retained_bytes: int = DEFAULT_CALIBRATION_MAX_RETAINED_BYTES,
) -> CalibrationResult:
    """Blocking convenience wrapper around :class:`CalibrationSession`.

    Suited to console scripts: perform the required in-game sequence while the
    capture runs. For automatic transfer calibration, the guided sequence is
    deposit one matching unstackable, deposit four, then withdraw all five.
    The toolkit does not perform those actions; ``quantity=1`` matches every
    serialized item record rather than the batch totals 1, 4, or 5.
    These counts are observed from traffic and are not hard-coded. Loot preview
    is a separate explicit action; omit ``quantity`` when its displayed amount
    is random.
    With ``capture_seconds`` the capture stops automatically; without it, the
    capture runs until the user interrupts (Ctrl+C), which is treated as
    "actions performed, calibrate now" rather than as an abort. Apps with
    their own UI should use :class:`CalibrationSession` directly.
    """
    import time

    if capture_seconds is not None and (
        isinstance(capture_seconds, bool)
        or not isinstance(capture_seconds, (int, float))
        or not math.isfinite(capture_seconds)
        or capture_seconds < 0
    ):
        raise ValueError("capture_seconds must be finite and non-negative")

    session = CalibrationSession(
        item_id=item_id,
        quantity=quantity,
        action=action,
        capture_options=capture_options,
        context_frames=context_frames,
        min_confidence=min_confidence,
        max_retained_frames=max_retained_frames,
        max_retained_bytes=max_retained_bytes,
    )
    with session:
        deadline = (
            None
            if capture_seconds is None
            else time.monotonic() + capture_seconds
        )
        try:
            while True:
                session.raise_if_failed()
                if deadline is None:
                    wait_seconds = 0.2
                else:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    wait_seconds = min(0.2, remaining)
                time.sleep(wait_seconds)
        except KeyboardInterrupt:
            # Ctrl+C ends the listening window; the collected frames still get
            # calibrated, matching the legacy stop-to-finish workflow.
            pass
        return session.stop()


def update_profile(
    result: CalibrationResult | Iterable[MessageSpec],
    path: str | Path,
    *,
    action: str = "auto",
    replace: bool = True,
    replace_entire_action: bool = False,
    backup: bool = True,
    calibration_item_id: Optional[int] = None,
) -> ProfileUpdate:
    """Persist promoted specs into a local opcode profile file.

    By default, only the event families represented by the supplied specs are
    cleared first.  Explicit-action and raw-spec callers can therefore apply a
    reviewed partial update without erasing unrelated evidence. Automatic
    transfer results must contain every runtime-required transfer family.
    Pass ``replace_entire_action=True`` for an explicit reset of every family
    belonging to ``action``. Pass ``replace=False`` only for an intentional
    advanced merge that preserves and deduplicates existing specs. The
    previous file is backed up next to it unless ``backup=False``.
    """
    if action != "auto" and action not in CALIBRATION_ACTIONS:
        raise ValueError(
            f"unknown calibration action {action!r}; "
            f"expected one of {CALIBRATION_ACTIONS} or 'auto'"
        )
    if isinstance(result, CalibrationResult):
        from_calibration_result = True
        specs = tuple(result.specs)
        if calibration_item_id is None:
            calibration_item_id = result.calibration_item_id
    else:
        from_calibration_result = False
        specs = tuple(result)
    if any(not isinstance(spec, MessageSpec) for spec in specs):
        raise TypeError("update_profile expects MessageSpec objects")
    _validate_profile_replacement_options(replace, replace_entire_action)
    if from_calibration_result and action == "auto" and specs:
        transfer_events = {
            "INVENTORY_TRANSFER",
            "SOURCE_CONTAINER_DECREMENT",
            "SOURCE_STACK_DECREMENT",
            "SOURCE_ITEM_REFERENCE",
            "STORAGE_ITEM_DELTA",
        }
        observed_events = {spec.event for spec in specs}
        if observed_events & transfer_events:
            required = {
                "INVENTORY_TRANSFER",
                "SOURCE_STACK_DECREMENT",
                "STORAGE_ITEM_DELTA",
            }
            missing = sorted(required - observed_events)
            if missing:
                raise CalibrationAuthorityError(
                    "auto calibration is incomplete and cannot safely replace a "
                    "post-patch profile; missing required runtime family/families: "
                    f"{', '.join(missing)}. Capture the complete guided transfer "
                    "sequence so both directions and the source-stack decrement "
                    "are observed, including an unstackable multi-record deposit, "
                    "or pass the matching explicit action only for an intentional "
                    "reviewed partial update. No profile was written."
                )
    profile_path = Path(path)
    if not specs:
        return ProfileUpdate(
            path=profile_path,
            added=(),
            replaced_events=(),
            backup_path=None,
            written=False,
        )
    if calibration_item_id is not None and (
        isinstance(calibration_item_id, bool)
        or not isinstance(calibration_item_id, int)
        or not 1 <= calibration_item_id <= 0xFFFFFFFF
    ):
        raise ValueError("calibration_item_id must be None or a positive uint32")
    data = _load_profile_data(profile_path)

    replaced_events: tuple[str, ...] = ()
    if replace and specs:
        replacement_scope = (
            _events_for_action(action)
            if replace_entire_action
            else tuple(dict.fromkeys(spec.event for spec in specs))
        )
        removed_events: list[str] = []
        for event in replacement_scope:
            if data["specs"].get(event):
                removed_events.append(event)
            data["specs"][event] = []
        replaced_events = tuple(removed_events)

    existing_keys = _profile_dedupe_keys(data)
    added: list[MessageSpec] = []
    for spec in specs:
        key = spec.dedupe_key()
        if key in existing_keys:
            continue
        data["specs"].setdefault(spec.event, [])
        data["specs"][spec.event].append(spec.to_json_dict())
        existing_keys.add(key)
        added.append(spec)

    if not added and not replaced_events:
        return ProfileUpdate(
            path=profile_path,
            added=(),
            replaced_events=(),
            backup_path=None,
            written=False,
        )

    # Reject a LOOT merge that would make runtime layout selection impossible
    # before creating a backup or replacing the destination file. Other
    # calibration families may intentionally persist partial evidence that is
    # not yet a runtime-decodable spec.
    _validate_loot_profile_entries(
        data["specs"].get("LOOT_PREVIEW", ()),
        source=profile_path,
    )

    data["profile_active"] = True
    data["updated_at"] = _utc_now_text()
    if calibration_item_id is not None:
        data["calibration_item_id"] = calibration_item_id

    backup_path = None
    profile_path.parent.mkdir(parents=True, exist_ok=True)
    if backup and profile_path.exists():
        backup_path = _backup_path(profile_path)
        shutil.copy2(profile_path, backup_path)

    _atomic_write_text(
        profile_path,
        json.dumps(data, indent=2, sort_keys=True) + "\n",
    )

    return ProfileUpdate(
        path=profile_path,
        added=tuple(added),
        replaced_events=replaced_events,
        backup_path=backup_path,
    )


def calibrate_and_update(
    profile_path: str | Path,
    *,
    item_id: int,
    pcap: Optional[str | Path] = None,
    capture_seconds: Optional[float] = None,
    quantity: Optional[int] = None,
    action: str = "auto",
    capture_options: Optional[PacketCaptureOptions] = None,
    pcap_ports: Optional[tuple[int, ...]] = None,
    context_frames: int = 5,
    min_confidence: float = 0.80,
    max_retained_frames: int = DEFAULT_CALIBRATION_MAX_RETAINED_FRAMES,
    max_retained_bytes: int = DEFAULT_CALIBRATION_MAX_RETAINED_BYTES,
    replace: bool = True,
    replace_entire_action: bool = False,
    backup: bool = True,
) -> tuple[CalibrationResult, Optional[ProfileUpdate]]:
    """Calibrate and persist in one call — a facade over the two-step API.

    With ``pcap`` set the capture is replayed from disk; otherwise a live
    capture runs (``capture_seconds`` timer, or Ctrl+C to stop, exactly like
    :func:`calibrate_live`). ``pcap_ports`` applies only to the recording;
    ``capture_options`` applies only to live packet acquisition. If calibration
    promoted specs, they replace the applicable scope in ``profile_path`` by
    default and both objects come back; if it found nothing the profile file
    is left untouched and the update slot is ``None``::

        result, update = calibrate_and_update(
            "opcodes.local",
            item_id=15156,
            quantity=1,
        )
        print(result.summary())
        if update is not None:
            print(update.summary())

    Replacement is also the default on :func:`update_profile`: normal
    post-patch recalibration supersedes stale entries for the event families
    actually found. Pass ``replace_entire_action=True`` for an explicit reset
    of every family owned by ``action``. Pass ``replace=False`` only for an
    intentional reviewed merge, or use the two-step API when specs must be
    inspected or filtered before persistence.
    """
    _validate_profile_replacement_options(replace, replace_entire_action)
    if pcap is not None:
        for name, value in (
            ("capture_seconds", capture_seconds),
            ("capture_options", capture_options),
        ):
            if value is not None:
                raise ValueError(
                    f"{name} applies to live calibration only; omit it with pcap"
                )
        for name, value, default in (
            (
                "max_retained_frames",
                max_retained_frames,
                DEFAULT_CALIBRATION_MAX_RETAINED_FRAMES,
            ),
            (
                "max_retained_bytes",
                max_retained_bytes,
                DEFAULT_CALIBRATION_MAX_RETAINED_BYTES,
            ),
        ):
            if value != default:
                raise ValueError(
                    f"{name} applies to live calibration only; omit it with pcap"
                )
        result = calibrate_pcap(
            pcap,
            item_id=item_id,
            quantity=quantity,
            action=action,
            ports=DEFAULT_SERVER_PORTS if pcap_ports is None else pcap_ports,
            context_frames=context_frames,
            min_confidence=min_confidence,
        )
    else:
        if pcap_ports is not None:
            raise ValueError(
                "pcap_ports applies to offline calibration only; omit it "
                "without pcap"
            )
        result = calibrate_live(
            item_id=item_id,
            capture_seconds=capture_seconds,
            quantity=quantity,
            action=action,
            capture_options=capture_options,
            context_frames=context_frames,
            min_confidence=min_confidence,
            max_retained_frames=max_retained_frames,
            max_retained_bytes=max_retained_bytes,
        )

    if not result.specs:
        return result, None

    update = update_profile(
        result,
        profile_path,
        action=action,
        replace=replace,
        replace_entire_action=replace_entire_action,
        backup=backup,
    )
    return result, update


def reset_profile(
    path: str | Path,
    calibration_item_id: int = 15156,
    *,
    backup: bool = True,
) -> Optional[Path]:
    """Write an empty active profile, returning the backup path if any.

    ``calibration_item_id`` is maintenance metadata only. The default names the
    recommended unstackable calibration item and remains explicitly
    overrideable; resetting a profile does not itself calibrate that item.
    """
    if (
        isinstance(calibration_item_id, bool)
        or not isinstance(calibration_item_id, int)
        or not 1 <= calibration_item_id <= 0xFFFFFFFF
    ):
        raise ValueError("calibration_item_id must be a positive uint32")
    profile_path = Path(path)
    profile_path.parent.mkdir(parents=True, exist_ok=True)
    backup_path = None
    if backup and profile_path.exists():
        backup_path = _backup_path(profile_path)
        shutil.copy2(profile_path, backup_path)

    data = {
        "version": OPCODE_PROFILE_SCHEMA_VERSION,
        "updated_at": _utc_now_text(),
        "calibration_item_id": calibration_item_id,
        "profile_active": True,
        "specs": {event: [] for event in OPCODE_PROFILE_EVENTS},
    }
    _atomic_write_text(
        profile_path,
        json.dumps(data, indent=2, sort_keys=True) + "\n",
    )
    return backup_path


# --- opcode-free transfer-direction classification (2026-07-07 re-audit) ---

# Item-id-bearing frame lengths are bimodal in every labeled capture:
# reference frames run 24-39 bytes (39 = a TWO-record worker deposit, and the
# reference grows ~15 bytes per additional record), while record/wrapper
# frames start at 251. The cut sits mid-gap so multi-record deposit
# references stay classified without ever reaching wrapper territory.
REFERENCE_FRAME_MAX_LENGTH = 128
# Source-stack decrement batches are compact repeated records rather than item
# wrappers. The observed five-record legacy batch is 144 bytes, so inspect a
# wider but still bounded window only inside the instance-anchored decrement
# detector; do not broaden direction classification's generic references.
SOURCE_DECREMENT_FRAME_MAX_LENGTH = 512

# Context labels with real per-source entropy. The low-entropy storage-delta
# reasons (05.., 20..) and the all-zero character-load context are excluded:
# they appear on storage-delta frames and would blur the receipt signal.
_HIGH_ENTROPY_CONTEXTS = tuple(
    value
    for value in SOURCE_CONTEXT_LABELS
    if value != CHARACTER_LOAD_CONTEXT and value not in STORAGE_DELTA_CONTEXTS
)

# Which structural family each explicit transfer action expects to observe.
_EXPECTED_FAMILY = {
    "storage-to-inventory": "into_inventory",
    "inventory-to-storage": "into_storage",
}


def _has_context_label_before(frame: BDOFrame, before_offset: int) -> bool:
    for value in _HIGH_ENTROPY_CONTEXTS:
        offset = frame.message.find(value)
        if 0 <= offset < before_offset:
            return True
    return False


def _has_item_reference_frame(
    frame_index: _FrameIndex,
    record_frame: BDOFrame,
    item_id: int,
    context_frames: int,
) -> bool:
    """A small same-flow frame carrying the raw item id, PRECEDING the record.

    Only preceding frames are considered — the reference precedes its record
    in every labeled capture across both opcode generations — and the
    backward scan stops at the first frame that itself carries a plausible
    watched-item record: that frame belongs to an adjacent transaction, and
    its companion frames must not bleed into this record's classification.
    """
    item_bytes = item_id.to_bytes(4, "little")
    for frame in reversed(frame_index.context_before(record_frame, context_frames)):
        if _plausible_record_offsets(frame, item_bytes):
            return False  # adjacent transaction's record frame: boundary
        if frame.length <= REFERENCE_FRAME_MAX_LENGTH and item_bytes in frame.message:
            return True
    return False


def _has_storage_delta_context(frame: BDOFrame, before_offset: int) -> bool:
    """Whether a validated storage destination field precedes the record."""
    return _discover_storage_context_offset(frame, before_offset) is not None


def detect_transfer_family(
    frames: list[BDOFrame],
    record_frame: BDOFrame,
    item_offset: int,
    item_id: int,
    context_frames: int = 5,
    *,
    _frame_index: Optional[_FrameIndex] = None,
) -> tuple[Optional[str], bool, bool, bool]:
    """Classify a record frame's transfer direction, opcode-free.

    Returns ``(family, reference_frame, context_label, storage_context)`` where
    ``family`` is:

    - ``"into_inventory"`` — the record frame carries a high-entropy source
      context label before the item record. The item is entering inventory (a
      receipt: storage pull, mob drop, gathering, mail, ...).
    - ``"into_storage"`` — the record frame carries a storage-delta reason at
      the known context offset (intrinsic), OR a small companion frame nearby
      carries the raw item id (windowed reference). The item is entering
      storage; covers player inventory->storage moves AND worker deposits.
    - ``None`` — no feature fires, or the two intrinsic features contradict.

    Two INTRINSIC features (both in-frame, both validated across two opcode
    generations; see docs/PACKET_PROTOCOL_WIKI.md) decide direction and take
    priority: the high-entropy context label => into_inventory, the
    storage-delta context => into_storage. If both fire the frame is refused
    (``None``), never guessed. The WINDOWED reference frame is only a fallback
    for into_storage when no intrinsic feature fired (e.g. the legacy
    generation, whose storage delta has no offset-8 context) — it can bleed in
    from an adjacent transaction, so an intrinsic signal always outranks it.
    """
    frame_index = _frame_index or _FrameIndex(frames)
    reference_frame = _has_item_reference_frame(
        frame_index, record_frame, item_id, context_frames
    )
    context_label = _has_context_label_before(record_frame, item_offset)
    storage_context = _has_storage_delta_context(record_frame, item_offset)

    if context_label and storage_context:
        family: Optional[str] = None  # contradictory intrinsic signals: refuse
    elif context_label:
        family = "into_inventory"
    elif storage_context:
        family = "into_storage"
    elif reference_frame:
        family = "into_storage"
    else:
        family = None
    return family, reference_frame, context_label, storage_context


def _select_records_by_family(
    frames: list[BDOFrame],
    records: list["_CalibratedItemRecord"],
    action: str,
    context_frames: int,
    evidence: list[DirectionEvidence],
    strict: bool,
    frame_index: _FrameIndex,
    allow_unclassified: bool = False,
) -> list["_CalibratedItemRecord"]:
    """Keep only records whose detected family matches ``action``.

    Records the classification of every candidate in ``evidence``. In strict
    (explicit single-direction) mode, a candidate that clearly belongs to the
    opposite family with none matching raises :class:`DirectionMismatchError`.

    ``allow_unclassified`` keeps records neither feature can classify. It is
    set only for explicit inventory-to-storage calibration: an explicit
    declaration must stay usable even if a future patch silences both
    features (the post-patch recovery path), so strictness there means
    "refuse contradiction", not "require positive proof". Auto mode never
    allows unclassified records — with no declaration to fall back on, an
    unclassifiable record is dropped.
    """
    expected = _EXPECTED_FAMILY[action]
    matched: list[_CalibratedItemRecord] = []
    opposite: Optional[str] = None
    contradictory_intrinsics = False
    for record in records:
        family, reference_frame, context_label, storage_context = detect_transfer_family(
            frames,
            record.frame,
            record.item_offset,
            record.item_id,
            context_frames,
            _frame_index=frame_index,
        )
        evidence.append(
            DirectionEvidence(
                action=action,
                opcode=record.frame.opcode,
                detected_family=family,
                reference_frame=reference_frame,
                context_label=context_label,
                storage_context=storage_context,
            )
        )
        contradictory = family is None and context_label and storage_context
        contradictory_intrinsics = contradictory_intrinsics or contradictory
        genuinely_unclassified = (
            family is None
            and not context_label
            and not storage_context
            and not reference_frame
        )
        if family == expected or (
            allow_unclassified and genuinely_unclassified
        ):
            matched.append(record)
        elif family is not None:
            opposite = family

    if not matched and contradictory_intrinsics and strict:
        raise DirectionMismatchError(
            f"declared action {action!r} but the capture contains a candidate "
            "with contradictory intrinsic direction signals; refusing to guess"
        )
    if not matched and opposite is not None and strict:
        observed = (
            "storage-to-inventory"
            if opposite == "into_inventory"
            else "inventory-to-storage"
        )
        raise DirectionMismatchError(
            f"declared action {action!r} but the capture's structure indicates "
            f"{observed!r} (item entering "
            f"{'inventory' if opposite == 'into_inventory' else 'storage'}). "
            "Perform the declared action, or use auto calibration."
        )
    return matched


# --- calibration heuristics, ported unchanged from the research prototype ---


def _calibrate_loot_preview(
    frames: list[BDOFrame],
    options: _Options,
    ignored: list[str],
) -> list[MessageSpec]:
    records = _find_calibration_item_records(frames, options, "loot-preview", ignored)
    preview_records = [
        record
        for record in records
        if record.instance == LOOT_PREVIEW_SENTINEL_INSTANCE
        and _passes_min_confidence(record.confidence, options.min_confidence)
    ]
    if not preview_records:
        return []

    best = max(preview_records, key=lambda record: record.confidence)
    return [
        MessageSpec(
            event="LOOT_PREVIEW",
            opcode=best.frame.opcode,
            length=best.frame.length,
            item_id_offset=best.item_offset,
            quantity_offset=best.item_offset + 4,
            item_instance_offset=best.instance_offset,
            confidence=_confidence_label(best.confidence),
            source=_calibration_source(options, "loot-preview"),
            observed_at=_iso_timestamp(best.frame.context.timestamp),
            score=best.confidence,
        )
    ]


def _calibrate_storage_to_inventory(
    frames: list[BDOFrame],
    options: _Options,
    ignored: list[str],
    evidence: list[DirectionEvidence],
    strict: bool,
) -> list[MessageSpec]:
    records = _find_calibration_item_records(
        frames,
        options,
        "storage-to-inventory",
        ignored,
    )
    receipt_records = [
        record
        for record in records
        if record.instance is not None
        and record.instance != LOOT_PREVIEW_SENTINEL_INSTANCE
        and _passes_min_confidence(record.confidence, options.min_confidence)
    ]
    # Family selection subsumes the legacy "known context label before the
    # record" receipt filter (into_inventory fires on exactly that label), and
    # running it on ALL structural candidates makes strict mismatch detection
    # symmetric: a wrong-direction capture raises here with evidence recorded
    # instead of silently pre-filtering down to an empty result.
    frame_index = options.frame_index or _FrameIndex(frames)
    receipt_records = _select_records_by_family(
        frames,
        receipt_records,
        "storage-to-inventory",
        options.context_frames,
        evidence,
        strict,
        frame_index,
    )
    if not receipt_records:
        return []

    # On ties (a multi-record frame yields one candidate per record, all with
    # equal confidence) prefer the FIRST record: spec offsets are relative to
    # the first record and later ones are reached via repeat_stride.
    best = max(
        receipt_records, key=lambda record: (record.confidence, -record.item_offset)
    )
    source_decrement = _discover_source_container_decrement(frames, best, options)
    if source_decrement is None:
        ignored.append(
            f'NOTE opcode=0x{best.frame.opcode:04X} '
            f'length={best.frame.length} item_offset={best.item_offset} '
            'reason="source-decrement-not-found;promoting-receipt-only"'
        )

    # Write the SINGLE-record length even when calibrated from a multi-record
    # frame (unstackables): the recorded length acts as a minimum at load
    # time, so the observed multi-record length would block single transfers.
    layout_item_offset, layout_instance_offset = _first_transfer_record_layout(
        best.frame,
        best.item_offset,
        best.instance_offset,
    )
    single_record_length, observed_stride = _record_frame_shape(
        best.frame,
        best.item_id,
        layout_item_offset,
        layout_instance_offset,
    )
    specs = [
        MessageSpec(
            event="INVENTORY_TRANSFER",
            opcode=best.frame.opcode,
            length=single_record_length,
            item_id_offset=layout_item_offset,
            quantity_offset=layout_item_offset + 4,
            item_instance_offset=layout_instance_offset,
            context_offset=_discover_context_offset(best.frame, layout_item_offset),
            repeat_stride=observed_stride,
            confidence=_confidence_label(best.confidence),
            source=_calibration_source(options, "storage-to-inventory"),
            observed_at=_iso_timestamp(best.frame.context.timestamp),
            score=best.confidence,
        )
    ]

    if source_decrement is not None:
        specs.append(source_decrement)
    return specs


def _calibrate_inventory_to_storage(
    frames: list[BDOFrame],
    options: _Options,
    ignored: list[str],
    evidence: list[DirectionEvidence],
    strict: bool,
) -> list[MessageSpec]:
    records = _find_calibration_item_records(
        frames,
        options,
        "inventory-to-storage",
        ignored,
    )
    storage_records = [
        record
        for record in records
        if record.instance is not None
        and record.instance != LOOT_PREVIEW_SENTINEL_INSTANCE
        and _passes_min_confidence(record.confidence, options.min_confidence)
    ]
    frame_index = options.frame_index or _FrameIndex(frames)
    storage_records = _select_records_by_family(
        frames,
        storage_records,
        "inventory-to-storage",
        options.context_frames,
        evidence,
        strict,
        frame_index,
        allow_unclassified=strict,
    )
    if not storage_records:
        return []

    # Same first-record tie-break as the receipt path (multi-record frames).
    best = max(
        storage_records, key=lambda record: (record.confidence, -record.item_offset)
    )
    specs: list[MessageSpec] = []
    # The single-record wrapper normally wins the primary-record score because
    # its normalized message length is directly observable.  Do not let that
    # choice discard stronger repeated decrement evidence from another
    # validated deposit in the same calibration run.  Evaluate record zero of
    # every unique target deposit frame; repeated shapes already outrank their
    # single-record counterparts in companion scoring, while incompatible
    # equal-strength shapes still fail closed in the shared selector.
    first_storage_records: dict[int, _CalibratedItemRecord] = {}
    for record in storage_records:
        frame_identity = id(record.frame)
        previous = first_storage_records.get(frame_identity)
        if previous is None or record.item_offset < previous.item_offset:
            first_storage_records[frame_identity] = record
    source_stack_candidates: list[MessageSpec] = []
    for record in first_storage_records.values():
        candidate = _discover_source_stack_decrement(frames, record, options)
        if candidate is not None:
            source_stack_candidates.append(candidate)
    source_stack = _unique_best_companion_spec(source_stack_candidates)
    if source_stack is not None:
        specs.append(source_stack)

    source_ref = _discover_source_item_reference(frames, best, options)
    if source_ref is not None:
        specs.append(source_ref)

    # Same single-record length normalization as the receipt spec; also record
    # the observed stride so a multi-record storage delta (unstackable
    # deposits) decodes all records under the written profile.
    layout_item_offset, layout_instance_offset = _first_transfer_record_layout(
        best.frame,
        best.item_offset,
        best.instance_offset,
    )
    single_record_length, observed_stride = _record_frame_shape(
        best.frame,
        best.item_id,
        layout_item_offset,
        layout_instance_offset,
    )
    storage_context_offset = _discover_storage_context_offset_from_frames(
        (record.frame for record in storage_records),
        opcode=best.frame.opcode,
        item_offset=layout_item_offset,
    )
    record_count_offset = _discover_storage_record_count_offset(
        frames,
        records=storage_records,
        opcode=best.frame.opcode,
        item_offset=layout_item_offset,
        instance_offset=layout_instance_offset,
        single_record_length=single_record_length,
    )
    # The strongest target record can be the single-record action even when
    # the same guided run also contains the multi-record shape that proves the
    # wrapper stride. Learn that stride across every structurally compatible
    # same-opcode frame instead of coupling it to whichever record won the score
    # tie. This lets character-state analysis validate count-zero envelopes
    # even for an account whose storages are all empty after calibration.
    observed_strides = {observed_stride} if observed_stride is not None else set()
    seen_shape_messages: set[bytes] = set()
    for frame in frames:
        if frame.opcode != best.frame.opcode or frame.message in seen_shape_messages:
            continue
        seen_shape_messages.add(frame.message)
        candidate_base, candidate_stride = _record_frame_shape(
            frame,
            best.item_id,
            layout_item_offset,
            layout_instance_offset,
        )
        if candidate_base == single_record_length and candidate_stride is not None:
            observed_strides.add(candidate_stride)
    repeat_stride = (
        next(iter(observed_strides)) if len(observed_strides) == 1 else None
    )
    missing_authority: list[str] = []
    if storage_context_offset is None:
        missing_authority.append("destination-field")
    if record_count_offset is None:
        missing_authority.append("record-count-field")
    if missing_authority:
        missing_text = ", ".join(missing_authority)
        guidance: list[str] = []
        if "destination-field" in missing_authority:
            guidance.append(
                "repeat the deposit in an unambiguous registered town such as "
                "Velia or Heidel (or include controlled deposits to different towns)"
            )
        if "record-count-field" in missing_authority:
            guidance.append(
                "include two independently validated record counts (for example "
                "one single-record and one unstackable multi-record deposit, or "
                "two unstackable deposits with different counts)"
            )
        raise CalibrationAuthorityError(
            f"storage opcode 0x{best.frame.opcode:04X} was observed, but its "
            f"{missing_text} could not be uniquely proven. No calibration "
            "result was produced and no profile should be updated. To resolve "
            f"this, {'; and '.join(guidance)}. Then retry calibration."
        )
    specs.append(
        MessageSpec(
            event="STORAGE_ITEM_DELTA",
            opcode=best.frame.opcode,
            length=single_record_length,
            item_id_offset=layout_item_offset,
            quantity_added_offset=layout_item_offset + 4,
            destination_instance_offset=layout_instance_offset,
            context_offset=storage_context_offset,
            record_count_offset=record_count_offset,
            repeat_stride=repeat_stride,
            confidence=_confidence_label(best.confidence),
            source=_calibration_source(options, "inventory-to-storage"),
            observed_at=_iso_timestamp(best.frame.context.timestamp),
            score=best.confidence,
        )
    )
    return specs


def _find_calibration_item_records(
    frames: list[BDOFrame],
    options: _Options,
    action: str,
    ignored: list[str],
) -> list[_CalibratedItemRecord]:
    item_bytes = options.item_id.to_bytes(4, "little")
    records: list[_CalibratedItemRecord] = []

    for frame in frames:
        frame_quantity_total = _sum_plausible_item_record_quantities(
            frame,
            item_bytes,
        )
        quantity_only = (
            options.quantity is not None
            and options.quantity.to_bytes(4, "little") in frame.message
            and item_bytes not in frame.message
        )
        if quantity_only:
            ignored.append(
                f'IGNORED opcode=0x{frame.opcode:04X} length={frame.length} '
                'reason="quantity-only"'
            )

        search_at = 0
        while True:
            item_offset = frame.message.find(item_bytes, search_at)
            if item_offset < 0:
                break
            search_at = item_offset + 1

            if item_offset + 8 > len(frame.message):
                ignored.append(
                    f'IGNORED opcode=0x{frame.opcode:04X} length={frame.length} '
                    f'item_offset={item_offset} reason="truncated-item-record"'
                )
                continue

            quantity = int.from_bytes(
                frame.message[item_offset + 4 : item_offset + 8],
                "little",
            )
            instance_offset = item_offset + 35
            instance = (
                bytes(frame.message[instance_offset : instance_offset + 8])
                if instance_offset + 8 <= len(frame.message)
                else None
            )
            confidence, reasons = _score_item_record_candidate(
                frame=frame,
                quantity=quantity,
                instance=instance,
                options=options,
                action=action,
                frame_quantity_total=frame_quantity_total,
            )
            if not _passes_min_confidence(confidence, options.min_confidence):
                ignored.append(
                    f'IGNORED opcode=0x{frame.opcode:04X} length={frame.length} '
                    f'item_offset={item_offset} reason="low-confidence:{confidence:.2f}"'
                )
                continue

            records.append(
                _CalibratedItemRecord(
                    frame=frame,
                    item_offset=item_offset,
                    item_id=options.item_id,
                    quantity=quantity,
                    instance_offset=instance_offset if instance is not None else None,
                    instance=instance,
                    confidence=confidence,
                    reasons=tuple(reasons),
                )
            )

    return records


def _passes_min_confidence(confidence: float, min_confidence: float) -> bool:
    return confidence + 1e-9 >= min_confidence


def _score_item_record_candidate(
    *,
    frame: BDOFrame,
    quantity: int,
    instance: Optional[bytes],
    options: _Options,
    action: str,
    frame_quantity_total: Optional[int],
) -> tuple[float, list[str]]:
    score = 0.35
    reasons = ["contains-watched-item"]

    if 0 < quantity <= 1_000_000:
        reasons.append("plausible-quantity")
        if options.quantity is None:
            score += 0.15
        elif quantity == options.quantity:
            score += 0.25
            reasons.append("quantity-match")
        elif frame_quantity_total == options.quantity:
            score += 0.20
            reasons.append("multi-record-total-quantity-match")
        else:
            score -= 0.20
            reasons.append("quantity-mismatch")
    else:
        score -= 0.30
        reasons.append("implausible-quantity")

    if instance is not None:
        score += 0.20
        reasons.append("instance-present")
    else:
        score -= 0.20
        reasons.append("instance-missing")

    if 200 <= frame.length <= 300:
        score += 0.10
        reasons.append("plausible-wrapper-length")

    score += 0.10
    reasons.append(f"action-window:{action}")

    if action == "loot-preview":
        if instance == LOOT_PREVIEW_SENTINEL_INSTANCE:
            score += 0.10
            reasons.append("preview-sentinel-instance")
        else:
            score -= 0.20
            reasons.append("preview-instance-not-sentinel")
    elif action in {"storage-to-inventory", "inventory-to-storage"}:
        if instance == LOOT_PREVIEW_SENTINEL_INSTANCE:
            score -= 0.20
            reasons.append("real-transfer-has-preview-sentinel")

    if instance is None and frame.length < 100:
        score -= 0.20
        reasons.append("tiny-hit-without-instance")

    return max(0.0, min(1.0, score)), reasons


def _plausible_record_offsets(frame: BDOFrame, item_bytes: bytes) -> list[int]:
    """Offsets of plausible watched-item records (item id + qty + instance)."""
    offsets: list[int] = []
    search_at = 0
    while True:
        item_offset = frame.message.find(item_bytes, search_at)
        if item_offset < 0:
            return offsets
        search_at = item_offset + 1
        if item_offset + 43 > len(frame.message):
            continue
        quantity = int.from_bytes(
            frame.message[item_offset + 4 : item_offset + 8], "little"
        )
        instance = frame.message[item_offset + 35 : item_offset + 43]
        if 0 < quantity <= 1_000_000 and _is_plausible_instance(instance):
            offsets.append(item_offset)


def _sum_plausible_item_record_quantities(
    frame: BDOFrame,
    item_bytes: bytes,
) -> Optional[int]:
    offsets = _plausible_record_offsets(frame, item_bytes)
    if not offsets:
        return None
    return sum(
        int.from_bytes(frame.message[offset + 4 : offset + 8], "little")
        for offset in offsets
    )


def _record_frame_shape(
    frame: BDOFrame,
    item_id: int,
    item_offset: int,
    instance_offset: Optional[int],
) -> tuple[int, Optional[int]]:
    """``(single_record_length, stride)`` for a repeated-record frame.

    A frame carrying N watched-item records at a uniform stride (unstackables
    move as N records of quantity 1) must be written into the profile at its
    SINGLE-record length: the profile loader treats the recorded length as a
    minimum message length, so writing the observed multi-record length would
    produce a profile that cannot decode ordinary single transfers.

    Full transfer-record markers are used first so mixed-item batches can be
    normalized too. Repeated watched-item offsets remain as a fallback for
    older layouts without those markers.
    """
    offsets = _full_transfer_record_offsets(frame, item_offset, instance_offset)
    if len(offsets) < 2:
        offsets = _plausible_record_offsets(frame, item_id.to_bytes(4, "little"))
    if len(offsets) < 2:
        return frame.length, None
    deltas = {b - a for a, b in zip(offsets, offsets[1:])}
    if len(deltas) != 1:
        return frame.length, None
    stride = deltas.pop()
    return frame.length - (len(offsets) - 1) * stride, stride


def _first_transfer_record_layout(
    frame: BDOFrame,
    item_offset: int,
    instance_offset: Optional[int],
) -> tuple[int, Optional[int]]:
    """Normalize a watched later batch item back to record zero's offsets."""
    if instance_offset is None:
        return item_offset, None
    instance_delta = instance_offset - item_offset
    offsets = _full_transfer_record_offsets(frame, item_offset, instance_offset)
    if not offsets:
        return item_offset, instance_offset
    first_item_offset = offsets[0]
    return first_item_offset, first_item_offset + instance_delta


def _full_transfer_record_offsets(
    frame: BDOFrame,
    item_offset: int,
    instance_offset: Optional[int],
) -> list[int]:
    """Locate structurally complete item records, including mixed-item batches."""
    if instance_offset is None:
        return []
    instance_delta = instance_offset - item_offset
    if instance_delta < 8:
        return []
    return [
        offset
        for offset in range(5, len(frame.message))
        if _looks_like_transfer_record(frame, offset, instance_delta)
    ]


def _looks_like_transfer_record(
    frame: BDOFrame,
    item_offset: int,
    instance_delta: int,
) -> bool:
    required_end = item_offset + max(20, instance_delta + 8)
    if required_end > len(frame.message):
        return False
    item_id = int.from_bytes(frame.message[item_offset : item_offset + 4], "little")
    quantity = int.from_bytes(
        frame.message[item_offset + 4 : item_offset + 8], "little"
    )
    instance = bytes(
        frame.message[
            item_offset + instance_delta : item_offset + instance_delta + 8
        ]
    )
    return (
        0 < item_id <= MAX_PLAUSIBLE_ITEM_ID
        and 0 < quantity <= 1_000_000
        and _is_plausible_instance(instance)
        and frame.message[item_offset + 8 : item_offset + 12] == b"\x00" * 4
        and frame.message[item_offset + 12 : item_offset + 20] == b"\xff" * 8
    )


def _discover_source_container_decrement(
    frames: list[BDOFrame],
    receipt: _CalibratedItemRecord,
    options: _Options,
) -> Optional[MessageSpec]:
    """Find the storage-side decrement that precedes an inventory receipt.

    Companion layouts have changed field order across patches, so neither the
    source instance nor the context is located relative to a fixed field. The
    moved quantity and a source context identify the companion; an exact
    receipt-instance match strengthens the result and supplies its offset.
    """
    item_bytes = receipt.item_id.to_bytes(4, "little")
    quantity_bytes = receipt.quantity.to_bytes(4, "little")
    candidates: list[MessageSpec] = []

    context = _context_before(
        options.frame_index or _FrameIndex(frames),
        receipt.frame,
        options.context_frames,
    )
    for frame in reversed(context):
        if not 20 <= frame.length <= REFERENCE_FRAME_MAX_LENGTH:
            continue
        if item_bytes in frame.message:
            continue
        quantity_offsets = _find_all(frame.message, quantity_bytes)
        if not quantity_offsets:
            continue

        instance_offsets = (
            _find_all(frame.message, receipt.instance)
            if receipt.instance is not None
            else []
        )
        # Multiple occurrences do not prove which field is the source
        # instance. Keep the family calibratable, but omit the uncertain
        # optional offset instead of choosing one by position.
        exact_instance_offset = (
            instance_offsets[0] if len(instance_offsets) == 1 else None
        )

        for quantity_offset in quantity_offsets:
            # Known layouts vary whether context is before or after instance.
            # Historical layouts put context before quantity. A newer layout
            # puts quantity first, so admit a trailing context only when the
            # same frame has one exact receipt-instance anchor; quantity and a
            # context label alone are too weak.
            context_offset = _discover_context_offset(frame, quantity_offset)
            if context_offset is None and exact_instance_offset is not None:
                trailing_context_offset = (
                    _discover_source_container_trailing_context_offset(
                        frame,
                        quantity_offset + 4,
                    )
                )
                if (
                    trailing_context_offset is not None
                    and not _ranges_overlap(
                        exact_instance_offset,
                        8,
                        trailing_context_offset,
                        4,
                    )
                ):
                    context_offset = trailing_context_offset
            if context_offset is None:
                continue
            if exact_instance_offset is not None and _ranges_overlap(
                exact_instance_offset, 8, quantity_offset, 4
            ):
                continue
            structural_instance_offset = _source_container_structural_instance_offset(
                frame, quantity_offset
            )
            instance_offset: Optional[int] = exact_instance_offset
            if instance_offset is not None:
                score = 0.90
            elif structural_instance_offset is not None:
                instance_offset = structural_instance_offset
                score = 0.86
            else:
                score = 0.82
            candidates.append(
                MessageSpec(
                    event="SOURCE_CONTAINER_DECREMENT",
                    opcode=frame.opcode,
                    length=frame.length,
                    context_offset=context_offset,
                    source_instance_offset=instance_offset,
                    quantity_removed_offset=quantity_offset,
                    confidence=_confidence_label(score),
                    source=_calibration_source(options, "storage-to-inventory"),
                    observed_at=_iso_timestamp(frame.context.timestamp),
                    score=score,
                )
            )
    return _unique_best_companion_spec(candidates)


def _discover_source_stack_decrement(
    frames: list[BDOFrame],
    storage_delta: _CalibratedItemRecord,
    options: _Options,
) -> Optional[MessageSpec]:
    """Find the inventory-side decrement that precedes a storage delta.

    Older layouts put the source instance before the quantity; the current
    layout puts it after. Search for the exact instance independently. If it
    cannot be correlated, a unique decrement -> item-reference -> delta chain
    can still identify the family without inventing an instance offset.
    """
    item_bytes = storage_delta.item_id.to_bytes(4, "little")
    quantity = (
        options.quantity
        if options.quantity is not None
        else storage_delta.quantity
    )
    quantity_bytes = quantity.to_bytes(4, "little")
    storage_record_offsets = _full_transfer_record_offsets(
        storage_delta.frame,
        storage_delta.item_offset,
        storage_delta.instance_offset,
    )
    expected_record_count = (
        len(storage_record_offsets) if len(storage_record_offsets) > 1 else None
    )
    context = _context_before(
        options.frame_index or _FrameIndex(frames),
        storage_delta.frame,
        options.context_frames,
    )
    candidates: list[MessageSpec] = []

    for frame_index, frame in enumerate(context):
        if not 20 <= frame.length <= SOURCE_DECREMENT_FRAME_MAX_LENGTH:
            continue
        if item_bytes in frame.message:
            continue
        instance_offsets = (
            _find_all(frame.message, storage_delta.instance)
            if storage_delta.instance is not None
            else []
        )
        exact_instance_offset = (
            instance_offsets[0] if len(instance_offsets) == 1 else None
        )
        if (
            frame.length > REFERENCE_FRAME_MAX_LENGTH
            and exact_instance_offset is None
        ):
            # Wider decrement batches are admitted only through an exact
            # cross-frame instance anchor. Otherwise ordinary context frames
            # carrying common quantities can tie the established compact
            # structural candidate.
            continue
        has_later_reference = any(
            _is_source_item_reference(candidate, item_bytes)
            for candidate in context[frame_index + 1 :]
        )
        if exact_instance_offset is None and not has_later_reference:
            continue

        repeated_shape = _source_stack_repeated_shape(
            frame,
            quantity_bytes,
            exact_instance_offset,
            expected_record_count=expected_record_count,
        )
        if repeated_shape is not None:
            base_length, repeat_stride, instance_offset, quantity_offset = (
                repeated_shape
            )
            candidates.append(
                MessageSpec(
                    event="SOURCE_STACK_DECREMENT",
                    opcode=frame.opcode,
                    length=base_length,
                    repeat_stride=repeat_stride,
                    source_instance_offset=instance_offset,
                    quantity_removed_offset=quantity_offset,
                    confidence=_confidence_label(0.90),
                    source=_calibration_source(options, "inventory-to-storage"),
                    observed_at=_iso_timestamp(frame.context.timestamp),
                    score=0.90,
                )
            )
            continue

        for quantity_offset in _find_all(frame.message, quantity_bytes):
            if exact_instance_offset is not None and _ranges_overlap(
                exact_instance_offset, 8, quantity_offset, 4
            ):
                continue
            structural_instance_offset = _source_stack_structural_instance_offset(
                frame, quantity_offset
            )
            candidate_instance_offset: Optional[int] = exact_instance_offset
            if candidate_instance_offset is not None:
                score = 0.88
            elif structural_instance_offset is not None:
                candidate_instance_offset = structural_instance_offset
                score = 0.86
            else:
                score = 0.82
            candidates.append(
                MessageSpec(
                    event="SOURCE_STACK_DECREMENT",
                    opcode=frame.opcode,
                    length=frame.length,
                    source_instance_offset=candidate_instance_offset,
                    quantity_removed_offset=quantity_offset,
                    confidence=_confidence_label(score),
                    source=_calibration_source(options, "inventory-to-storage"),
                    observed_at=_iso_timestamp(frame.context.timestamp),
                    score=score,
                )
            )
    return _unique_best_companion_spec(candidates)


def _source_stack_repeated_shape(
    frame: BDOFrame,
    quantity_bytes: bytes,
    exact_instance_offset: Optional[int],
    *,
    expected_record_count: Optional[int] = None,
) -> Optional[tuple[int, int, int, int]]:
    """Normalize an instance-anchored decrement batch to record-one geometry.

    The quantity/instance phase is part of the repeated record, not a stable
    patch constant.  Anchor record zero with the exact destination instance,
    try every repeated quantity phase that keeps both fields inside one
    record, and retain only one longest valid geometry.  Longer stride
    multiples can be aliases that skip records; equal-strength distinct
    phases are ambiguous and fail closed.
    """

    if exact_instance_offset is None:
        return None
    if expected_record_count is not None and expected_record_count < 2:
        return None
    quantity_offsets = tuple(sorted(set(_find_all(frame.message, quantity_bytes))))
    if len(quantity_offsets) < 2:
        return None
    quantity_offset_set = set(quantity_offsets)

    # Four quantity bytes and eight instance bytes must coexist without
    # overlap inside one repeated record, so a smaller stride cannot be a
    # valid record geometry. This is a field-width invariant, not a layout
    # constant.
    minimum_stride = 12
    candidates: list[tuple[int, int, int, int]] = []
    for first_quantity_offset in quantity_offsets:
        if _ranges_overlap(
            first_quantity_offset,
            4,
            exact_instance_offset,
            8,
        ):
            continue
        for later_quantity_offset in quantity_offsets:
            repeat_stride = later_quantity_offset - first_quantity_offset
            if repeat_stride < minimum_stride:
                continue

            record_count = 0
            while True:
                delta = record_count * repeat_stride
                quantity_offset = first_quantity_offset + delta
                instance_offset = exact_instance_offset + delta
                if quantity_offset not in quantity_offset_set:
                    break
                if (
                    quantity_offset < 5
                    or quantity_offset + 4 > frame.length
                    or instance_offset < 5
                    or instance_offset + 8 > frame.length
                    or _ranges_overlap(
                        quantity_offset,
                        4,
                        instance_offset,
                        8,
                    )
                    or not _is_plausible_instance(
                        frame.message[instance_offset : instance_offset + 8]
                    )
                ):
                    break
                record_count += 1
            if record_count < 2 or (
                expected_record_count is not None
                and record_count != expected_record_count
            ):
                continue

            prefix_length = frame.length - record_count * repeat_stride
            base_length = prefix_length + repeat_stride
            if (
                prefix_length < 5
                or first_quantity_offset < prefix_length
                or exact_instance_offset < prefix_length
                or first_quantity_offset + 4 > base_length
                or exact_instance_offset + 8 > base_length
            ):
                continue
            candidates.append(
                (
                    record_count,
                    base_length,
                    repeat_stride,
                    first_quantity_offset,
                )
            )

    if not candidates:
        return None
    best_count = max(candidate[0] for candidate in candidates)
    best_shapes = {
        (base_length, repeat_stride, first_quantity_offset)
        for (
            record_count,
            base_length,
            repeat_stride,
            first_quantity_offset,
        ) in candidates
        if record_count == best_count
    }
    if len(best_shapes) != 1:
        return None
    base_length, repeat_stride, first_quantity_offset = next(iter(best_shapes))
    return (
        base_length,
        repeat_stride,
        exact_instance_offset,
        first_quantity_offset,
    )


def _source_container_structural_instance_offset(
    frame: BDOFrame,
    quantity_offset: int,
) -> Optional[int]:
    """Recognize the legacy ``instance + separator + quantity`` layout."""
    instance_offset = quantity_offset - 9
    separator = frame.message[quantity_offset - 1 : quantity_offset]
    if instance_offset < 5 or separator != b"\x02":
        return None
    instance = frame.message[instance_offset : instance_offset + 8]
    return instance_offset if _is_structural_source_instance(instance) else None


def _source_stack_structural_instance_offset(
    frame: BDOFrame,
    quantity_offset: int,
) -> Optional[int]:
    """Recognize known pre- and post-quantity source-instance layouts.

    The older family places the instance immediately before quantity. The
    current family uses ``quantity + uint32(0) + instance``. If a frame happens
    to satisfy both shapes, the instance remains unproven.
    """
    offsets: set[int] = set()

    before_offset = quantity_offset - 8
    if before_offset >= 5 and _is_structural_source_instance(
        frame.message[before_offset:quantity_offset]
    ):
        offsets.add(before_offset)

    after_offset = quantity_offset + 8
    if (
        after_offset + 8 <= frame.length
        and frame.message[quantity_offset + 4 : after_offset] == b"\x00" * 4
        and _is_structural_source_instance(
            frame.message[after_offset : after_offset + 8]
        )
    ):
        offsets.add(after_offset)

    return next(iter(offsets)) if len(offsets) == 1 else None


def _is_structural_source_instance(value: bytes) -> bool:
    """Stronger guard for an uncorrelated instance-shaped field.

    Exact cross-frame matches use the broader instance validator. A field
    inferred only from layout must have entropy in both uint32 halves; this
    rejects current frames' incidental ``uint32(0) + small value`` at q-8.
    """
    if not _is_plausible_instance(value):
        return False
    empty_halves = {b"\x00" * 4, b"\xff" * 4}
    return value[:4] not in empty_halves and value[4:] not in empty_halves


def _ranges_overlap(
    first_offset: int,
    first_width: int,
    second_offset: int,
    second_width: int,
) -> bool:
    return (
        first_offset < second_offset + second_width
        and second_offset < first_offset + first_width
    )


def _is_source_item_reference(frame: BDOFrame, item_bytes: bytes) -> bool:
    """Whether a small frame carries a non-record reference to the item."""
    if not 20 <= frame.length <= REFERENCE_FRAME_MAX_LENGTH:
        return False
    return any(
        not _looks_like_full_item_record(frame, item_offset)
        for item_offset in _find_all(frame.message, item_bytes)
    )


def _unique_best_companion_spec(
    candidates: Iterable[MessageSpec],
) -> Optional[MessageSpec]:
    """Return one strongest companion candidate, refusing an equal-score tie."""
    unique = {candidate.dedupe_key(): candidate for candidate in candidates}
    if not unique:
        return None
    best_score = max(candidate.score or 0.0 for candidate in unique.values())
    best = [
        candidate
        for candidate in unique.values()
        if (candidate.score or 0.0) == best_score
    ]
    return best[0] if len(best) == 1 else None


def _discover_source_item_reference(
    frames: list[BDOFrame],
    storage_delta: _CalibratedItemRecord,
    options: _Options,
) -> Optional[MessageSpec]:
    item_bytes = storage_delta.item_id.to_bytes(4, "little")

    context = _context_before(
        options.frame_index or _FrameIndex(frames),
        storage_delta.frame,
        options.context_frames,
    )
    for frame in reversed(context):
        if not 20 <= frame.length <= REFERENCE_FRAME_MAX_LENGTH:
            continue
        item_offset = frame.message.find(item_bytes)
        if item_offset < 0:
            continue
        if _looks_like_full_item_record(frame, item_offset):
            continue
        return MessageSpec(
            event="SOURCE_ITEM_REFERENCE",
            opcode=frame.opcode,
            length=frame.length,
            item_id_offset=item_offset,
            confidence=_confidence_label(0.82),
            source=_calibration_source(options, "inventory-to-storage"),
            observed_at=_iso_timestamp(frame.context.timestamp),
            score=0.82,
        )
    return None


def _context_before(
    frame_index: _FrameIndex,
    target_frame: BDOFrame,
    context_frames: int,
) -> list[BDOFrame]:
    return list(frame_index.context_before(target_frame, context_frames))


def _discover_context_offset(frame: BDOFrame, before_offset: int) -> Optional[int]:
    best_offset = None
    for context_bytes in SOURCE_CONTEXT_LABELS:
        if (
            context_bytes == CHARACTER_LOAD_CONTEXT
            or context_bytes in STORAGE_DELTA_CONTEXTS
        ):
            continue
        search_at = 0
        while True:
            offset = frame.message.find(context_bytes, search_at)
            if offset < 0:
                break
            if offset < before_offset:
                best_offset = offset if best_offset is None else max(best_offset, offset)
            search_at = offset + 1
    return best_offset


def _discover_source_container_trailing_context_offset(
    frame: BDOFrame,
    after_offset: int,
) -> Optional[int]:
    """Return one unique source context after a container quantity field.

    This is deliberately narrower than ``_discover_context_offset``. The
    caller requires an exact receipt-instance match before using this fallback,
    and ambiguity among trailing context labels fails closed.
    """

    offsets: set[int] = set()
    for context_bytes in SOURCE_CONTEXT_LABELS:
        if (
            context_bytes == CHARACTER_LOAD_CONTEXT
            or context_bytes in STORAGE_DELTA_CONTEXTS
        ):
            continue
        search_at = max(5, after_offset)
        while True:
            offset = frame.message.find(context_bytes, search_at)
            if offset < 0:
                break
            offsets.add(offset)
            search_at = offset + 1
    return next(iter(offsets)) if len(offsets) == 1 else None


def _discover_storage_context_offset(
    frame: BDOFrame,
    before_offset: int,
) -> Optional[int]:
    """Return one unambiguous town column in a structurally valid wrapper."""
    if not _has_dynamic_storage_record_geometry(frame, before_offset):
        return None
    candidates = storage_destination_candidates(
        frame.message,
        before_offset=before_offset,
    )
    if len(candidates) == 1:
        return candidates[0][0]
    return None


def _discover_storage_context_offset_from_frames(
    frames: Iterable[BDOFrame],
    *,
    opcode: int,
    item_offset: int,
) -> Optional[int]:
    """Learn the destination column by cross-frame offset consistency.

    This intentionally assumes neither the byte envelope around a town ID nor
    an item-relative position.  Registered-ID overlaps disappear when the
    same field column is intersected across different destination values.
    """

    candidate_intersection: Optional[set[int]] = None
    unregistered_messages: list[bytes] = []
    messages_seen: set[bytes] = set()
    for frame in frames:
        if (
            frame.opcode != opcode
            or frame.message in messages_seen
            or not _has_dynamic_storage_record_geometry(frame, item_offset)
        ):
            continue
        candidates = {
            offset
            for offset, _storage_id in storage_destination_candidates(
                frame.message,
                before_offset=item_offset,
            )
        }
        messages_seen.add(frame.message)
        if not candidates:
            # A newly added town can be structurally valid before the toolkit
            # name registry knows its numeric key. Let registered destinations
            # establish the column, then require that same column to contain a
            # nonzero uint32 here. An unknown town must not veto an otherwise
            # provable patch schema or be relabeled from a decoy elsewhere.
            unregistered_messages.append(frame.message)
            continue
        candidate_intersection = (
            candidates
            if candidate_intersection is None
            else candidate_intersection & candidates
        )
        if not candidate_intersection:
            return None
    if candidate_intersection is None or len(candidate_intersection) != 1:
        return None
    selected = next(iter(candidate_intersection))
    if any(
        selected + 4 > item_offset
        or int.from_bytes(message[selected : selected + 4], "little") == 0
        for message in unregistered_messages
    ):
        return None
    return selected


def _has_dynamic_storage_record_geometry(
    frame: BDOFrame,
    item_offset: int,
) -> bool:
    """Whether some prefix count proves every full storage item record."""

    if item_offset + 43 > frame.length:
        return False
    geometries: set[tuple[int, int]] = set()
    for count_offset in range(5, max(5, item_offset - 1)):
        count = int.from_bytes(
            frame.message[count_offset : count_offset + 2],
            "little",
        )
        if count <= 0:
            continue
        for prefix_length in range(max(5, count_offset + 2), item_offset + 1):
            record_bytes = frame.length - prefix_length
            if record_bytes <= 0 or record_bytes % count:
                continue
            stride = record_bytes // count
            relative_item_offset = item_offset - prefix_length
            if relative_item_offset < 0 or relative_item_offset + 43 > stride:
                continue
            if all(
                _looks_like_full_item_record(
                    frame,
                    item_offset + index * stride,
                )
                for index in range(count)
            ):
                geometries.add((count, stride))
    return bool(geometries)


def _discover_storage_record_count_offset(
    frames: Iterable[BDOFrame],
    *,
    records: Iterable[_CalibratedItemRecord],
    opcode: int,
    item_offset: int,
    instance_offset: Optional[int],
    single_record_length: int,
) -> Optional[int]:
    """Learn one authoritative uint16 count column from record geometry.

    A single wrapper can contain another small integer equal to its item
    count.  Intersecting candidates across independently validated frames and
    count shapes prevents such a field from silently impersonating the real
    declaration.  No absolute or item-relative count position is assumed.
    """

    if instance_offset is None:
        return None
    records_by_message: dict[bytes, list[int]] = {}
    for record in records:
        if record.frame.opcode != opcode:
            continue
        records_by_message.setdefault(record.frame.message, []).append(
            record.item_offset
        )
    candidate_intersection: Optional[set[int]] = None
    messages_seen: set[bytes] = set()
    counts_seen: set[int] = set()
    for frame in frames:
        if frame.opcode != opcode or frame.message in messages_seen:
            continue
        offsets = _full_transfer_record_offsets(
            frame,
            item_offset,
            instance_offset,
        )
        if not offsets:
            offsets = sorted(set(records_by_message.get(frame.message, ())))
        if not offsets or offsets[0] != item_offset:
            continue
        count = len(offsets)
        if count == 1:
            if frame.length != single_record_length:
                continue
        else:
            strides = {later - earlier for earlier, later in zip(offsets, offsets[1:])}
            if len(strides) != 1:
                continue
            stride = next(iter(strides))
            if frame.length - (count - 1) * stride != single_record_length:
                continue

        search_end = min(item_offset, len(frame.message))
        candidates = {
            offset
            for offset in range(5, max(5, search_end - 1))
            if int.from_bytes(frame.message[offset : offset + 2], "little")
            == count
        }
        if not candidates:
            return None
        messages_seen.add(frame.message)
        counts_seen.add(count)
        candidate_intersection = (
            candidates
            if candidate_intersection is None
            else candidate_intersection & candidates
        )
        if not candidate_intersection:
            return None

    # One count shape cannot distinguish the declaration from an unrelated
    # header integer that happens to carry the same value. Two independently
    # validated shapes are the minimum patch-agnostic semantic proof.
    if (
        len(counts_seen) < 2
        or candidate_intersection is None
        or len(candidate_intersection) != 1
    ):
        return None
    return next(iter(candidate_intersection))


def _looks_like_full_item_record(frame: BDOFrame, item_offset: int) -> bool:
    if item_offset + 43 > len(frame.message):
        return False
    quantity = int.from_bytes(frame.message[item_offset + 4 : item_offset + 8], "little")
    instance = frame.message[item_offset + 35 : item_offset + 43]
    return 0 < quantity <= 1_000_000 and _is_plausible_instance(instance)


def _is_plausible_instance(value: bytes) -> bool:
    return len(value) == 8 and value != b"\x00" * 8 and value != b"\xff" * 8


def _find_all(haystack: bytes, needle: bytes) -> list[int]:
    offsets: list[int] = []
    search_at = 0
    while True:
        offset = haystack.find(needle, search_at)
        if offset < 0:
            return offsets
        offsets.append(offset)
        search_at = offset + 1


def _dedupe_message_specs(specs: Iterable[MessageSpec]) -> list[MessageSpec]:
    output: list[MessageSpec] = []
    seen: set[tuple[object, ...]] = set()
    for spec in specs:
        key = spec.dedupe_key()
        if key in seen:
            continue
        seen.add(key)
        output.append(spec)
    return output


def _confidence_label(score: float) -> str:
    level = "high" if score >= 0.90 else "medium"
    return f"calibrated-{level}"


def _calibration_source(options: _Options, action: str) -> str:
    parts = [f"calibrate {action}", f"item_id={options.item_id}"]
    if options.quantity is not None:
        parts.append(f"qty={options.quantity}")
    return " ".join(parts)


def _iso_timestamp(timestamp: float) -> str:
    return (
        dt.datetime.fromtimestamp(timestamp, tz=dt.UTC)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def _utc_now_text() -> str:
    return (
        dt.datetime.now(tz=dt.UTC)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def _events_for_action(action: str) -> tuple[str, ...]:
    if action == "loot-preview":
        return ("LOOT_PREVIEW",)
    if action == "storage-to-inventory":
        return ("INVENTORY_TRANSFER", "SOURCE_CONTAINER_DECREMENT")
    if action == "inventory-to-storage":
        return (
            "SOURCE_STACK_DECREMENT",
            "SOURCE_ITEM_REFERENCE",
            "STORAGE_ITEM_DELTA",
        )
    # ``auto`` observes both transfer directions but never owns the separate
    # loot-preview workflow.
    return tuple(event for event in OPCODE_PROFILE_EVENTS if event != "LOOT_PREVIEW")


def _validate_profile_replacement_options(
    replace: bool,
    replace_entire_action: bool,
) -> None:
    if not isinstance(replace, bool):
        raise TypeError("replace must be a boolean")
    if not isinstance(replace_entire_action, bool):
        raise TypeError("replace_entire_action must be a boolean")
    if replace_entire_action and not replace:
        raise ValueError(
            "replace_entire_action=True cannot be combined with replace=False"
        )


def _load_profile_data(path: Path) -> dict[str, Any]:
    if path.exists():
        # Validate every supported top-level section, including explicitly
        # promoted origin companion families, before preserving the file.
        load_opcode_profile(path)
        try:
            data = json.loads(path.read_text(encoding="utf-8-sig"))
        except (json.JSONDecodeError, UnicodeError) as exc:
            raise ProfileError(f"Could not parse opcodes JSON {path}: {exc}") from exc
        if not isinstance(data, dict):
            raise ProfileError(f"Opcodes JSON {path} must be a top-level object")
    else:
        data = {"version": OPCODE_PROFILE_SCHEMA_VERSION}

    version = data.get("version")
    if (
        isinstance(version, bool)
        or not isinstance(version, int)
        or version != OPCODE_PROFILE_SCHEMA_VERSION
    ):
        raise ProfileError(
            f"version in {path} must be {OPCODE_PROFILE_SCHEMA_VERSION}"
        )
    active = data.get("profile_active", False)
    if not isinstance(active, bool):
        raise ProfileError(f"profile_active in {path} must be a boolean")
    updated_at = data.get("updated_at")
    if updated_at is not None and not isinstance(updated_at, str):
        raise ProfileError(f"updated_at in {path} must be a string")
    calibration_item_id = data.get("calibration_item_id")
    if calibration_item_id is not None and (
        isinstance(calibration_item_id, bool)
        or not isinstance(calibration_item_id, int)
        or not 1 <= calibration_item_id <= 0xFFFFFFFF
    ):
        raise ProfileError(
            f"calibration_item_id in {path} must be a positive uint32"
        )

    specs = data.get("specs", {})
    if not isinstance(specs, dict):
        raise ProfileError(f"specs in {path} must be an object")
    for event, entries in specs.items():
        if not isinstance(event, str):
            raise ProfileError(f"spec event names in {path} must be strings")
        if not isinstance(entries, list):
            raise ProfileError(f"specs[{event!r}] in {path} must be a list")
        if any(not isinstance(entry, dict) for entry in entries):
            raise ProfileError(
                f"every specs[{event!r}] entry in {path} must be an object"
            )
        for index, entry in enumerate(entries):
            _validate_profile_entry(path, event, index, entry)
    for event in OPCODE_PROFILE_EVENTS:
        specs.setdefault(event, [])

    data["version"] = version
    data["profile_active"] = active
    data["specs"] = specs
    data.setdefault("updated_at", _utc_now_text())
    return data


def _profile_dedupe_keys(data: dict[str, Any]) -> set[tuple[object, ...]]:
    specs = data.get("specs", {})
    if not isinstance(specs, dict):
        return set()

    keys: set[tuple[object, ...]] = set()
    for event, entries in specs.items():
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            opcode = _profile_opcode(entry.get("opcode"), event)
            keys.add(
                (
                    event,
                    opcode,
                    entry.get("length"),
                    entry.get("item_id_offset"),
                    entry.get("quantity_offset"),
                    entry.get("item_instance_offset"),
                    entry.get("context_offset"),
                    entry.get("record_count_offset"),
                    entry.get("inventory_slot_offset"),
                    entry.get("source_instance_offset"),
                    entry.get("quantity_removed_offset"),
                    entry.get("quantity_added_offset"),
                    entry.get("destination_instance_offset"),
                    entry.get("repeat_stride"),
                )
            )
    return keys


def _profile_opcode(value: object, event: str) -> int:
    if isinstance(value, bool):
        raise ProfileError(f"invalid opcode for {event}: {value!r}")
    if isinstance(value, int):
        opcode = value
    elif isinstance(value, str):
        try:
            opcode = int(value, 16 if value.lower().startswith("0x") else 10)
        except ValueError as exc:
            raise ProfileError(f"invalid opcode for {event}: {value!r}") from exc
    else:
        raise ProfileError(f"invalid opcode for {event}: {value!r}")
    if not 0 <= opcode <= 0xFFFF:
        raise ProfileError(f"opcode for {event} must be a uint16")
    return opcode
