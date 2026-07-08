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
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

from ._capture_backend import replay_pcap_file
from ._framing import FrameCollectorScanner
from ._protocol import (
    CHARACTER_LOAD_CONTEXT,
    CURRENT_STORAGE_DELTA_CONTEXT_OFFSET,
    DEFAULT_SERVER_PORTS,
    LOOT_PREVIEW_SENTINEL_INSTANCE,
    SOURCE_CONTEXT_LABELS,
    STORAGE_DELTA_CONTEXTS,
    BDOFrame,
)
from ._reassembly import FlowManager
from ._specs import ProfileError

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
class OpcodeSpec:
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

    def dedupe_key(self) -> tuple[object, ...]:
        return (
            self.event,
            self.opcode,
            self.length,
            self.item_id_offset,
            self.quantity_offset,
            self.item_instance_offset,
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


@dataclass(frozen=True)
class CalibrationResult:
    """Promoted opcode specs plus diagnostics for rejected candidates."""

    specs: tuple[OpcodeSpec, ...]
    ignored: tuple[str, ...]
    frames_scanned: int
    evidence: tuple[DirectionEvidence, ...] = ()


@dataclass(frozen=True)
class ProfileUpdate:
    """Outcome of merging calibration specs into a profile file."""

    path: Path
    added: tuple[OpcodeSpec, ...]
    replaced_events: tuple[str, ...]
    backup_path: Optional[Path]


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


def collect_frames_pcap(
    path: str | Path,
    *,
    ports: tuple[int, ...] = DEFAULT_SERVER_PORTS,
) -> list[BDOFrame]:
    """Reassemble a pcap and return every generic BDO frame."""
    frames: list[BDOFrame] = []
    manager = FlowManager(
        server_ports=ports,
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
    """Score collected frames and promote plausible opcode specs."""
    if action != "auto" and action not in CALIBRATION_ACTIONS:
        raise ValueError(
            f"unknown calibration action {action!r}; "
            f"expected one of {CALIBRATION_ACTIONS} or 'auto'"
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
    specs: list[OpcodeSpec] = []

    # Auto covers both transfer directions and classifies each from structure,
    # so the user need only move an item storage->inventory and back (in either
    # order). Direction is never taken on faith. Loot preview needs a gathering
    # action, so it stays an explicit, optional mode.
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
        specs=tuple(_dedupe_opcode_specs(specs)),
        ignored=tuple(ignored),
        frames_scanned=len(frames),
        evidence=tuple(evidence),
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
    """Calibrate opcode specs from a pcap of a known in-game action."""
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
        self._item_id = item_id
        self._quantity = quantity
        self._action = action
        self._ports = ports
        self._interface = interface
        self._local_ip = local_ip
        self._context_frames = context_frames
        self._min_confidence = min_confidence
        self._frames: list[BDOFrame] = []
        self._manager: Optional[FlowManager] = None
        self._capture = None

    @property
    def running(self) -> bool:
        return self._capture is not None

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

        detected_target = detect_default_capture_target()
        capture_interface = self._interface or detected_target.interface
        capture_local_ip = self._local_ip
        if capture_local_ip is None and self._interface is None:
            capture_local_ip = detected_target.local_ip

        capture = AsyncSniffer(
            iface=capture_interface,
            filter=build_bpf_filter(self._ports, capture_local_ip),
            prn=make_packet_handler(self._manager),
            store=False,
        )
        capture.start()
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
    session.start()
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
    result: CalibrationResult | Iterable[OpcodeSpec],
    path: str | Path,
    *,
    action: str = "auto",
    replace: bool = False,
    backup: bool = True,
) -> ProfileUpdate:
    """Merge promoted specs into a local opcode profile file.

    With ``replace=True`` the profile entries belonging to ``action`` are
    cleared first, so a recalibration fully supersedes stale entries. The
    previous file is backed up next to it unless ``backup=False``.
    """
    specs = tuple(result.specs if isinstance(result, CalibrationResult) else result)
    profile_path = Path(path)
    data = _load_profile_data(profile_path)

    replaced_events: tuple[str, ...] = ()
    if replace and specs:
        replaced_events = _events_for_action(action, specs)
        for event in replaced_events:
            data["specs"][event] = []

    existing_keys = _profile_dedupe_keys(data)
    added: list[OpcodeSpec] = []
    for spec in specs:
        key = spec.dedupe_key()
        if key in existing_keys:
            continue
        data["specs"].setdefault(spec.event, [])
        data["specs"][spec.event].append(spec.to_json_dict())
        existing_keys.add(key)
        added.append(spec)

    data["profile_active"] = True
    data["updated_at"] = dt.datetime.now().isoformat(timespec="seconds")

    backup_path = None
    if backup and profile_path.exists():
        backup_path = _backup_path(profile_path)
        backup_path.write_bytes(profile_path.read_bytes())

    profile_path.write_text(
        json.dumps(data, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    return ProfileUpdate(
        path=profile_path,
        added=tuple(added),
        replaced_events=replaced_events,
        backup_path=backup_path,
    )


def reset_profile(
    path: str | Path,
    calibration_item_id: int = 7003,
    *,
    backup: bool = True,
) -> Optional[Path]:
    """Write an empty active profile, returning the backup path if any."""
    profile_path = Path(path)
    backup_path = None
    if backup and profile_path.exists():
        backup_path = _backup_path(profile_path)
        backup_path.write_bytes(profile_path.read_bytes())

    data = {
        "version": 1,
        "updated_at": dt.datetime.now().isoformat(timespec="seconds"),
        "calibration_item_id": calibration_item_id,
        "profile_active": True,
        "specs": {event: [] for event in OPCODE_PROFILE_EVENTS},
    }
    profile_path.write_text(
        json.dumps(data, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
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


def _has_storage_delta_context(frame: BDOFrame) -> bool:
    """A storage-delta reason code at the known current-gen context offset.

    Every current-generation storage delta (0x0E6A) carries `05000000`
    (single/manual-style) or `20000000` (batch-style) at offset 8, with zero
    collisions on any receipt frame in the labeled set. This is an INTRINSIC
    into_storage signal, symmetric with the into_inventory context label, and
    it does not depend on a companion reference frame, so it classifies multi-record
    unstackable deposits, which carry no reference frame.
    """
    end = CURRENT_STORAGE_DELTA_CONTEXT_OFFSET + 4
    if end > len(frame.message):
        return False
    return bytes(frame.message[CURRENT_STORAGE_DELTA_CONTEXT_OFFSET:end]) in STORAGE_DELTA_CONTEXTS


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
    storage_context = _has_storage_delta_context(record_frame)

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
        if family == expected or (allow_unclassified and family is None):
            matched.append(record)
        elif family is not None:
            opposite = family

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
) -> list[OpcodeSpec]:
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
        OpcodeSpec(
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
) -> list[OpcodeSpec]:
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
        best.frame, best.item_id
    )
    specs = [
        OpcodeSpec(
            event="INVENTORY_TRANSFER",
            opcode=best.frame.opcode,
            length=single_record_length,
            item_id_offset=best.item_offset,
            quantity_offset=best.item_offset + 4,
            item_instance_offset=best.instance_offset,
            context_offset=_discover_context_offset(best.frame, best.item_offset),
            inventory_slot_offset=_discover_inventory_slot_offset(best.frame, best.item_offset),
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
) -> list[OpcodeSpec]:
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
    specs: list[OpcodeSpec] = []
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
        best.frame, best.item_id
    )
    specs.append(
        OpcodeSpec(
            event="STORAGE_ITEM_DELTA",
            opcode=best.frame.opcode,
            length=single_record_length,
            item_id_offset=best.item_offset,
            quantity_added_offset=best.item_offset + 4,
            destination_instance_offset=best.instance_offset,
            repeat_stride=observed_stride,
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


def _record_frame_shape(frame: BDOFrame, item_id: int) -> tuple[int, Optional[int]]:
    """``(single_record_length, stride)`` for a repeated-record frame.

    A frame carrying N watched-item records at a uniform stride (unstackables
    move as N records of quantity 1) must be written into the profile at its
    SINGLE-record length: the profile loader treats the recorded length as a
    minimum message length, so writing the observed multi-record length would
    produce a profile that cannot decode ordinary single transfers.

    Limitation: only records of the watched item are counted, so a mixed-item
    multi-record frame (e.g. a worker deposit batching different items) does
    not normalize; calibrate with a dedicated item move, not ambient traffic.
    """
    offsets = _plausible_record_offsets(frame, item_id.to_bytes(4, "little"))
    if len(offsets) < 2:
        return frame.length, None
    deltas = {b - a for a, b in zip(offsets, offsets[1:])}
    if len(deltas) != 1:
        return frame.length, None
    stride = deltas.pop()
    return frame.length - (len(offsets) - 1) * stride, stride


def _discover_source_container_decrement(
    frames: list[BDOFrame],
    receipt: _CalibratedItemRecord,
    options: _Options,
) -> Optional[OpcodeSpec]:
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

        return OpcodeSpec(
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
) -> Optional[OpcodeSpec]:
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
            return OpcodeSpec(
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
) -> Optional[OpcodeSpec]:
    item_bytes = storage_delta.item_id.to_bytes(4, "little")

    for frame in reversed(_context_before(frames, storage_delta.frame, options.context_frames)):
        if not 20 <= frame.length <= 35:
            continue
        item_offset = frame.message.find(item_bytes)
        if item_offset < 0:
            continue
        if _looks_like_full_item_record(frame, item_offset):
            continue
        return OpcodeSpec(
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


def _discover_inventory_slot_offset(frame: BDOFrame, item_offset: int) -> Optional[int]:
    if frame.opcode == 0x19E9 and item_offset > 0:
        return item_offset - 1
    return None


def _discover_repeat_stride(frame: BDOFrame, item_offset: int) -> Optional[int]:
    if item_offset != 33:
        return None
    if frame.length <= 255:
        return 228
    if (frame.length - 27) % 228 == 0:
        return 228
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


def _dedupe_opcode_specs(specs: Iterable[OpcodeSpec]) -> list[OpcodeSpec]:
    output: list[OpcodeSpec] = []
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
    return dt.datetime.fromtimestamp(timestamp).isoformat(timespec="seconds")


def _events_for_action(
    action: str,
    specs: Iterable[OpcodeSpec] = (),
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


def _load_profile_data(path: Path) -> dict:
    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8-sig"))
        except json.JSONDecodeError as exc:
            raise ProfileError(f"Could not parse opcodes JSON {path}: {exc}") from exc
        if not isinstance(data, dict):
            raise ProfileError(f"Opcodes JSON {path} must be a top-level object")
    else:
        data = {}

    specs = data.get("specs")
    if not isinstance(specs, dict):
        specs = {}
    for event in OPCODE_PROFILE_EVENTS:
        specs.setdefault(event, [])

    data["version"] = int(data.get("version", 1))
    data["profile_active"] = bool(data.get("profile_active", False))
    data["specs"] = specs
    data.setdefault("updated_at", dt.datetime.now().isoformat(timespec="seconds"))
    return data


def _profile_dedupe_keys(data: dict) -> set[tuple[object, ...]]:
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
            opcode_value = entry.get("opcode")
            opcode = (
                int(opcode_value, 16)
                if isinstance(opcode_value, str)
                else opcode_value
            )
            keys.add(
                (
                    event,
                    opcode,
                    entry.get("length"),
                    entry.get("item_id_offset"),
                    entry.get("quantity_offset"),
                    entry.get("item_instance_offset"),
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
    return backup_dir / f"{path.name}.bak.{dt.datetime.now().strftime('%Y%m%d%H%M%S')}"
