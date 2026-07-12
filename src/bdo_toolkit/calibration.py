"""Opcode profile calibration.

After a game patch shifts opcodes or byte offsets, developers can rebuild a
local opcode profile from a capture of a known in-game action:

    from bdo_toolkit.calibration import calibrate_pcap, update_profile

    result = calibrate_pcap(
        "move_3_potatoes_to_storage.pcapng",
        item_id=7003,          # the item used for the action (Potato)
        quantity=3,            # how many were moved
        action="inventory-to-storage",
    )
    update_profile(result, "opcodes.json", action="inventory-to-storage", replace=True)

Then point the decoding APIs at the local profile:

    replay_pcap("session.pcapng", opcode_profile="opcodes.json")

The calibration heuristics score every frame containing the watched item id
and promote the most plausible record layouts. They are ported unchanged from
the original research prototype.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import json
import math
import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Optional

from ._capture_backend import replay_pcap_file, validate_server_ports
from ._framing import FrameCollectorScanner
from ._protocol import (
    CHARACTER_LOAD_CONTEXT,
    CURRENT_INVENTORY_TRANSFER_RECORD_BASE_LENGTH,
    CURRENT_STORAGE_DELTA_RECORD_STRIDE,
    DEFAULT_SERVER_PORTS,
    LOOT_PREVIEW_SENTINEL_INSTANCE,
    MAX_PLAUSIBLE_ITEM_ID,
    SOURCE_CONTEXT_LABELS,
    STORAGE_DELTA_CONTEXTS,
    BDOFrame,
)
from ._reassembly import FlowManager
from .profiles import ProfileError, _validate_profile_entry, load_opcode_profile

__all__ = [
    "CALIBRATION_ACTIONS",
    "CalibrationResult",
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

    def dedupe_key(self) -> tuple[object, ...]:
        return (
            self.event,
            self.opcode,
            self.length,
            self.item_id_offset,
            self.quantity_offset,
            self.item_instance_offset,
            self.context_offset,
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
            "specs": [spec.to_json_dict() for spec in self.specs],
            "ignored": list(self.ignored),
            "evidence": [e.to_json_dict() for e in self.evidence],
        }


@dataclass(frozen=True)
class ProfileUpdate:
    """Outcome of merging calibration specs into a profile file."""

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


@dataclass(frozen=True)
class _Options:
    item_id: int
    quantity: Optional[int]
    action: str
    context_frames: int
    min_confidence: float


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

    options = _Options(
        item_id=item_id,
        quantity=quantity,
        action=action,
        context_frames=context_frames,
        min_confidence=min_confidence,
    )
    ignored: list[str] = []
    evidence: list[DirectionEvidence] = []
    specs: list[MessageSpec] = []

    # Auto covers both transfer directions and classifies each from structure,
    # so the user need only move an item storage->inventory and back (in either
    # order). Direction is never taken on faith. Loot preview needs a gathering
    # action, so it stays an explicit, optional mode.
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

    return CalibrationResult(
        specs=tuple(_dedupe_message_specs(specs)),
        ignored=tuple(ignored),
        frames_scanned=len(frames),
        evidence=tuple(evidence),
        calibration_item_id=item_id,
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
    ``stop()``; the capture thread never blocks the caller. Typical app flow::

        session = CalibrationSession(item_id=7003, quantity=3)  # action="auto"
        session.start()
        # ... tell the user to move the item to storage and back,
        #     then have them click "Done" in your UI ...
        result = session.stop()
        if result.specs:
            update_profile(result, my_profile_path, replace=True)

    Auto calibration (the default) classifies each transfer direction from
    packet structure, so the user only needs to move an item to storage and
    back in either order; no ``action`` need be declared.

    ``frames_collected`` can drive a UI indicator that traffic is arriving.
    Used as a context manager, the capture is stopped on exit even if the
    block raises; call ``stop()`` inside the block to get the result.
    """

    def __init__(
        self,
        *,
        item_id: int,
        quantity: Optional[int] = None,
        action: str = "auto",
        ports: tuple[int, ...] = DEFAULT_SERVER_PORTS,
        interface: Optional[str] = None,
        local_ip: Optional[str] = None,
        context_frames: int = 5,
        min_confidence: float = 0.80,
    ) -> None:
        _validate_calibration_options(
            item_id=item_id,
            quantity=quantity,
            action=action,
            context_frames=context_frames,
            min_confidence=min_confidence,
        )
        if local_ip is not None:
            try:
                local_ip = str(ipaddress.IPv4Address(local_ip))
            except ipaddress.AddressValueError as exc:
                raise ValueError(
                    f"local_ip must be an IPv4 address: {local_ip!r}"
                ) from exc
        self._item_id = item_id
        self._quantity = quantity
        self._action = action
        self._ports = validate_server_ports(ports)
        self._interface = interface
        self._local_ip = local_ip
        self._context_frames = context_frames
        self._min_confidence = min_confidence
        self._frames: list[BDOFrame] = []
        self._manager: Optional[FlowManager] = None
        self._capture: Any = None

    @property
    def running(self) -> bool:
        return self._capture is not None and bool(self._capture.running)

    @property
    def frames_collected(self) -> int:
        return len(self._frames)

    def start(self) -> None:
        """Begin passive background capture."""
        if self._capture is not None:
            raise RuntimeError("calibration session is already running")

        from ._capture_backend import (
            build_bpf_filter,
            detect_default_capture_target,
            import_scapy,
            make_packet_handler,
        )

        import_scapy()
        from scapy.sendrecv import AsyncSniffer  # type: ignore

        self._frames = []
        self._manager = FlowManager(
            server_ports=self._ports,
            scanner_factory=lambda: FrameCollectorScanner(self._frames.append),
        )

        detected_target = None
        if self._interface is None:
            detected_target = detect_default_capture_target()
            capture_interface = detected_target.interface
        else:
            capture_interface = self._interface
        capture_local_ip = self._local_ip
        if capture_local_ip is None and self._interface is None:
            assert detected_target is not None
            capture_local_ip = detected_target.local_ip

        capture = AsyncSniffer(
            iface=capture_interface,
            filter=build_bpf_filter(self._ports, capture_local_ip),
            prn=make_packet_handler(self._manager),
            store=False,
        )
        try:
            capture.start()
        except BaseException:
            if capture.running:
                capture.stop()
            self._manager = None
            raise
        self._capture = capture

    def stop(self) -> CalibrationResult:
        """End the capture and calibrate the collected frames."""
        if self._capture is None or self._manager is None:
            raise RuntimeError("calibration session was not started")

        capture, self._capture = self._capture, None
        if capture.running:
            capture.stop()
        self._manager.finish()
        self._manager = None

        return calibrate_frames(
            self._frames,
            item_id=self._item_id,
            quantity=self._quantity,
            action=self._action,
            context_frames=self._context_frames,
            min_confidence=self._min_confidence,
        )

    def __enter__(self) -> "CalibrationSession":
        if self._capture is None:
            self.start()
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        # Safety net only: discard the capture if the block exited without
        # calling stop() (for example on an exception).
        if self._capture is not None:
            capture, self._capture = self._capture, None
            if capture.running:
                capture.stop()
            self._manager = None


def calibrate_live(
    *,
    item_id: int,
    capture_seconds: Optional[float] = None,
    quantity: Optional[int] = None,
    action: str = "auto",
    ports: tuple[int, ...] = DEFAULT_SERVER_PORTS,
    interface: Optional[str] = None,
    local_ip: Optional[str] = None,
    context_frames: int = 5,
    min_confidence: float = 0.80,
) -> CalibrationResult:
    """Blocking convenience wrapper around :class:`CalibrationSession`.

    Suited to console scripts: perform the in-game action once while the
    capture runs. With ``capture_seconds`` the capture stops automatically;
    without it, the capture runs until the user interrupts (Ctrl+C), which is
    treated as "action performed, calibrate now" rather than as an abort.
    Apps with their own UI should use :class:`CalibrationSession` directly.
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
        ports=ports,
        interface=interface,
        local_ip=local_ip,
        context_frames=context_frames,
        min_confidence=min_confidence,
    )
    with session:
        try:
            if capture_seconds is not None:
                time.sleep(capture_seconds)
            else:
                while True:
                    time.sleep(0.2)
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
    replace: bool = False,
    backup: bool = True,
    calibration_item_id: Optional[int] = None,
) -> ProfileUpdate:
    """Merge promoted specs into a local opcode profile file.

    With ``replace=True`` the profile entries belonging to ``action`` are
    cleared first, so a recalibration fully supersedes stale entries. The
    previous file is backed up next to it unless ``backup=False``.
    """
    if action != "auto" and action not in CALIBRATION_ACTIONS:
        raise ValueError(
            f"unknown calibration action {action!r}; "
            f"expected one of {CALIBRATION_ACTIONS} or 'auto'"
        )
    if isinstance(result, CalibrationResult):
        specs = tuple(result.specs)
        if calibration_item_id is None:
            calibration_item_id = result.calibration_item_id
    else:
        specs = tuple(result)
    if any(not isinstance(spec, MessageSpec) for spec in specs):
        raise TypeError("update_profile expects MessageSpec objects")
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
        replaced_events = _events_for_action(action, specs)
        for event in replaced_events:
            data["specs"][event] = []

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
    ports: tuple[int, ...] = DEFAULT_SERVER_PORTS,
    interface: Optional[str] = None,
    local_ip: Optional[str] = None,
    context_frames: int = 5,
    min_confidence: float = 0.80,
    replace: bool = True,
    backup: bool = True,
) -> tuple[CalibrationResult, Optional[ProfileUpdate]]:
    """Calibrate and persist in one call — a facade over the two-step API.

    With ``pcap`` set the capture is replayed from disk; otherwise a live
    capture runs (``capture_seconds`` timer, or Ctrl+C to stop, exactly like
    :func:`calibrate_live`). If calibration promoted specs they are merged
    into ``profile_path`` and both objects come back; if it found nothing the
    profile file is left untouched and the update slot is ``None``::

        result, update = calibrate_and_update("opcodes.local", item_id=7003)
        print(result.summary())
        if update is not None:
            print(update.summary())

    Unlike :func:`update_profile`, ``replace`` defaults to ``True`` here: the
    one-call path exists for post-patch recalibration, where superseding the
    stale entries is what you want. Devs who need to inspect or filter specs
    before persisting should stay on the two-step API.
    """
    if pcap is not None:
        for name, value in (
            ("capture_seconds", capture_seconds),
            ("interface", interface),
            ("local_ip", local_ip),
        ):
            if value is not None:
                raise ValueError(
                    f"{name} applies to live calibration only; omit it with pcap"
                )
        result = calibrate_pcap(
            pcap,
            item_id=item_id,
            quantity=quantity,
            action=action,
            ports=ports,
            context_frames=context_frames,
            min_confidence=min_confidence,
        )
    else:
        result = calibrate_live(
            item_id=item_id,
            capture_seconds=capture_seconds,
            quantity=quantity,
            action=action,
            ports=ports,
            interface=interface,
            local_ip=local_ip,
            context_frames=context_frames,
            min_confidence=min_confidence,
        )

    if not result.specs:
        return result, None

    update = update_profile(
        result,
        profile_path,
        action=action,
        replace=replace,
        backup=backup,
    )
    return result, update


def reset_profile(
    path: str | Path,
    calibration_item_id: int = 7003,
    *,
    backup: bool = True,
) -> Optional[Path]:
    """Write an empty active profile, returning the backup path if any."""
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
        "version": 1,
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
    frames: list[BDOFrame],
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
    same_flow = [
        frame for frame in frames if frame.context.flow == record_frame.context.flow
    ]
    try:
        index = same_flow.index(record_frame)
    except ValueError:
        return False
    for frame in reversed(same_flow[max(0, index - context_frames) : index]):
        if _plausible_record_offsets(frame, item_bytes):
            return False  # adjacent transaction's record frame: boundary
        if frame.length <= REFERENCE_FRAME_MAX_LENGTH and item_bytes in frame.message:
            return True
    return False


def _has_storage_delta_context(frame: BDOFrame, before_offset: int) -> bool:
    """Whether an observed storage reason code precedes the item record."""
    return _discover_storage_context_offset(frame, before_offset) is not None


def detect_transfer_family(
    frames: list[BDOFrame],
    record_frame: BDOFrame,
    item_offset: int,
    item_id: int,
    context_frames: int = 5,
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
    reference_frame = _has_item_reference_frame(
        frames, record_frame, item_id, context_frames
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
            frames, record.frame, record.item_offset, record.item_id, context_frames
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
    receipt_records = _select_records_by_family(
        frames,
        receipt_records,
        "storage-to-inventory",
        options.context_frames,
        evidence,
        strict,
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
    single_record_length, observed_stride = _record_frame_shape(
        best.frame,
        best.item_id,
        best.item_offset,
        best.instance_offset,
    )
    specs = [
        MessageSpec(
            event="INVENTORY_TRANSFER",
            opcode=best.frame.opcode,
            length=single_record_length,
            item_id_offset=best.item_offset,
            quantity_offset=best.item_offset + 4,
            item_instance_offset=best.instance_offset,
            context_offset=_discover_context_offset(best.frame, best.item_offset),
            repeat_stride=_discover_repeat_stride(best.frame, best.item_offset)
            or observed_stride,
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
    storage_records = _select_records_by_family(
        frames,
        storage_records,
        "inventory-to-storage",
        options.context_frames,
        evidence,
        strict,
        allow_unclassified=strict,
    )
    if not storage_records:
        return []

    # Same first-record tie-break as the receipt path (multi-record frames).
    best = max(
        storage_records, key=lambda record: (record.confidence, -record.item_offset)
    )
    specs: list[MessageSpec] = []
    source_stack = _discover_source_stack_decrement(frames, best, options)
    if source_stack is not None:
        specs.append(source_stack)

    source_ref = _discover_source_item_reference(frames, best, options)
    if source_ref is not None:
        specs.append(source_ref)

    # Same single-record length normalization as the receipt spec; also record
    # the observed stride so a multi-record storage delta (unstackable
    # deposits) decodes all records under the written profile.
    single_record_length, observed_stride = _record_frame_shape(
        best.frame,
        best.item_id,
        best.item_offset,
        best.instance_offset,
    )
    storage_context_offset = _discover_storage_context_offset(
        best.frame,
        best.item_offset,
    )
    repeat_stride = observed_stride or _discover_storage_repeat_stride(
        best.frame,
        best.item_offset,
        best.instance_offset,
    )
    specs.append(
        MessageSpec(
            event="STORAGE_ITEM_DELTA",
            opcode=best.frame.opcode,
            length=single_record_length,
            item_id_offset=best.item_offset,
            quantity_added_offset=best.item_offset + 4,
            destination_instance_offset=best.instance_offset,
            context_offset=storage_context_offset,
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
        for offset in range(item_offset, len(frame.message))
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
    item_bytes = receipt.item_id.to_bytes(4, "little")
    quantity_bytes = receipt.quantity.to_bytes(4, "little")

    for frame in reversed(_context_before(frames, receipt.frame, options.context_frames)):
        if not 30 <= frame.length <= 60:
            continue
        if item_bytes in frame.message:
            continue
        quantity_offsets = _find_all(frame.message, quantity_bytes)
        if not quantity_offsets:
            continue

        instance_offset = (
            frame.message.find(receipt.instance)
            if receipt.instance is not None
            else -1
        )
        quantity_offset = quantity_offsets[0]
        context_offset = None
        score = 0.80

        if instance_offset >= 0:
            context_offset = _discover_context_offset(frame, instance_offset)
            score = 0.90 if quantity_offset > instance_offset else 0.82
        else:
            for candidate_quantity_offset in quantity_offsets:
                context_offset = _discover_context_offset(
                    frame,
                    candidate_quantity_offset,
                )
                if context_offset is None:
                    continue
                quantity_offset = candidate_quantity_offset
                candidate_instance_offset = candidate_quantity_offset - 9
                if candidate_instance_offset >= 5:
                    candidate_instance = frame.message[
                        candidate_instance_offset : candidate_instance_offset + 8
                    ]
                    if _is_plausible_instance(candidate_instance):
                        instance_offset = candidate_instance_offset
                        score = 0.86
                break

        if context_offset is None:
            continue

        return MessageSpec(
            event="SOURCE_CONTAINER_DECREMENT",
            opcode=frame.opcode,
            length=frame.length,
            context_offset=context_offset,
            source_instance_offset=instance_offset if instance_offset >= 0 else None,
            quantity_removed_offset=quantity_offset,
            confidence=_confidence_label(score),
            source=_calibration_source(options, "storage-to-inventory"),
            observed_at=_iso_timestamp(frame.context.timestamp),
            score=score,
        )
    return None


def _discover_source_stack_decrement(
    frames: list[BDOFrame],
    storage_delta: _CalibratedItemRecord,
    options: _Options,
) -> Optional[MessageSpec]:
    item_bytes = storage_delta.item_id.to_bytes(4, "little")
    quantity = options.quantity if options.quantity is not None else storage_delta.quantity
    quantity_bytes = quantity.to_bytes(4, "little")

    for frame in reversed(_context_before(frames, storage_delta.frame, options.context_frames)):
        if not 35 <= frame.length <= 60:
            continue
        if item_bytes in frame.message:
            continue
        for quantity_offset in _find_all(frame.message, quantity_bytes):
            instance_offset = quantity_offset - 8
            if instance_offset < 5:
                continue
            instance = frame.message[instance_offset:quantity_offset]
            if not _is_plausible_instance(instance):
                continue
            return MessageSpec(
                event="SOURCE_STACK_DECREMENT",
                opcode=frame.opcode,
                length=frame.length,
                source_instance_offset=instance_offset,
                quantity_removed_offset=quantity_offset,
                confidence=_confidence_label(0.88),
                source=_calibration_source(options, "inventory-to-storage"),
                observed_at=_iso_timestamp(frame.context.timestamp),
                score=0.88,
            )
    return None


def _discover_source_item_reference(
    frames: list[BDOFrame],
    storage_delta: _CalibratedItemRecord,
    options: _Options,
) -> Optional[MessageSpec]:
    item_bytes = storage_delta.item_id.to_bytes(4, "little")

    for frame in reversed(_context_before(frames, storage_delta.frame, options.context_frames)):
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
    frames: list[BDOFrame],
    target_frame: BDOFrame,
    context_frames: int,
) -> list[BDOFrame]:
    if context_frames <= 0:
        return []
    try:
        index = frames.index(target_frame)
    except ValueError:
        return []

    same_flow_before = [
        frame
        for frame in frames[:index]
        if frame.context.flow == target_frame.context.flow
    ]
    return same_flow_before[-context_frames:]


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


def _discover_storage_context_offset(
    frame: BDOFrame,
    before_offset: int,
) -> Optional[int]:
    """Find the nearest observed storage reason code before an item record."""
    best_offset = None
    for context_bytes in STORAGE_DELTA_CONTEXTS:
        search_at = 0
        while True:
            offset = frame.message.find(context_bytes, search_at, before_offset)
            if offset < 0:
                break
            best_offset = offset if best_offset is None else max(best_offset, offset)
            search_at = offset + 1
    return best_offset


def _discover_repeat_stride(frame: BDOFrame, item_offset: int) -> Optional[int]:
    if item_offset != 33:
        return None
    record_bytes = frame.length - CURRENT_INVENTORY_TRANSFER_RECORD_BASE_LENGTH
    if record_bytes > 0 and record_bytes % 228 == 0:
        return 228
    return None


def _discover_storage_repeat_stride(
    frame: BDOFrame,
    item_offset: int,
    instance_offset: Optional[int],
) -> Optional[int]:
    """Recognize the observed storage wrapper shape without trusting opcode."""
    if item_offset != 37 or instance_offset != 72:
        return None
    record_bytes = frame.length - 35
    if record_bytes > 0 and record_bytes % CURRENT_STORAGE_DELTA_RECORD_STRIDE == 0:
        return CURRENT_STORAGE_DELTA_RECORD_STRIDE
    return None


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
        dt.datetime.fromtimestamp(timestamp, tz=dt.timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def _utc_now_text() -> str:
    return (
        dt.datetime.now(tz=dt.timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def _events_for_action(
    action: str,
    specs: Iterable[MessageSpec] = (),
) -> tuple[str, ...]:
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
    discovered = tuple(dict.fromkeys(spec.event for spec in specs))
    return discovered or OPCODE_PROFILE_EVENTS


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
        data = {}

    version = data.get("version")
    if version is None:
        version = 1
    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
        raise ProfileError(f"version in {path} must be a positive integer")
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
                    entry.get("inventory_slot_offset"),
                    entry.get("source_instance_offset"),
                    entry.get("quantity_removed_offset"),
                    entry.get("quantity_added_offset"),
                    entry.get("destination_instance_offset"),
                    entry.get("repeat_stride"),
                )
            )
    return keys


def _backup_path(path: Path) -> Path:
    backup_dir = path.parent / "opcodes_backups"
    backup_dir.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now(tz=dt.timezone.utc).strftime("%Y%m%d%H%M%S%f")
    candidate = backup_dir / f"{path.name}.bak.{stamp}"
    suffix = 1
    while candidate.exists():
        candidate = backup_dir / f"{path.name}.bak.{stamp}.{suffix}"
        suffix += 1
    return candidate


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


def _atomic_write_text(path: Path, text: str) -> None:
    """Atomically replace a UTF-8 text file in its destination directory."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Optional[Path] = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary_path = Path(handle.name)
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
    finally:
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()
