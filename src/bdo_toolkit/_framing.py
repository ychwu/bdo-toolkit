"""Scan a reassembled application byte stream for target BDO messages."""

from __future__ import annotations

from typing import Callable, Iterable, Optional

from ._protocol import (
    CHARACTER_LOAD_CONTEXT,
    MAX_PLAUSIBLE_ITEM_ID,
    MAX_TARGET_MESSAGE_LENGTH,
    BDOFrame,
    EventCallback,
    EventSpec,
    LootEvent,
    PacketContext,
)

_TRANSFER_RECORD_MARKER = b"\x00" * 4 + b"\xff" * 8
_TRANSFER_RECORD_MARKER_DELTA = 8

type MessageObserver = Callable[
    [int, int, str, int, PacketContext, Optional[int]],
    object,
]


def _structural_instance_offset(spec: EventSpec) -> Optional[int]:
    if spec.label == "INVENTORY_TRANSFER":
        return spec.item_instance_offset
    if spec.label == "INVENTORY_TO_STORAGE":
        return spec.storage_instance_offset
    return None


def _supports_structural_record_scan(spec: EventSpec) -> bool:
    instance_offset = _structural_instance_offset(spec)
    return (
        instance_offset is not None
        and spec.quantity_offset - spec.item_offset == 4
        and instance_offset - spec.item_offset >= 20
    )


def _looks_like_transfer_record(
    message: bytes,
    item_offset: int,
    instance_delta: int,
) -> bool:
    required_end = item_offset + max(20, instance_delta + 8)
    if item_offset < 0 or required_end > len(message):
        return False
    item_id = int.from_bytes(message[item_offset : item_offset + 4], "little")
    quantity = int.from_bytes(message[item_offset + 4 : item_offset + 8], "little")
    instance = message[item_offset + instance_delta : item_offset + instance_delta + 8]
    return (
        0 < item_id <= MAX_PLAUSIBLE_ITEM_ID
        and quantity > 0
        and instance not in (b"\x00" * 8, b"\xff" * 8)
        and message[
            item_offset
            + _TRANSFER_RECORD_MARKER_DELTA : item_offset
            + _TRANSFER_RECORD_MARKER_DELTA
            + len(_TRANSFER_RECORD_MARKER)
        ]
        == _TRANSFER_RECORD_MARKER
    )


def _has_plausible_transfer_record_values(
    message: bytes,
    *,
    item_offset: int,
    quantity_offset: int,
    instance_offset: int,
) -> bool:
    """Validate the value-bearing fields that every transfer record needs."""
    required_end = max(item_offset + 4, quantity_offset + 4, instance_offset + 8)
    if min(item_offset, quantity_offset, instance_offset) < 0:
        return False
    if required_end > len(message):
        return False

    item_id = int.from_bytes(message[item_offset : item_offset + 4], "little")
    quantity = int.from_bytes(message[quantity_offset : quantity_offset + 4], "little")
    instance = message[instance_offset : instance_offset + 8]
    return (
        0 < item_id <= MAX_PLAUSIBLE_ITEM_ID
        and quantity > 0
        and instance not in (b"\x00" * 8, b"\xff" * 8)
    )


def _declared_inventory_snapshot_record_deltas(
    spec: EventSpec,
    message: bytes,
) -> Optional[list[int]]:
    """Prove a character-load inventory batch from its declared count.

    The wrapper's uint16 count has moved between patches, so search the framed
    header rather than pinning its offset.  Each viable declaration must imply
    the same ``length = base + (count - 1) * stride`` geometry, and every
    declared item/quantity/instance tuple must validate.  This makes a
    zero-context load atomic: a corrupt record invalidates the whole frame.

    Multiple copies of the same count are harmless.  Competing declarations
    that imply different geometries are ambiguous and fail closed.
    """
    if spec.label != "INVENTORY_TRANSFER":
        return None
    instance_offset = spec.item_instance_offset
    base_length = spec.single_record_message_length
    if instance_offset is None or base_length is None:
        return None

    # Counts are wrapper metadata and therefore must precede the calibrated
    # first item.  Skip the five-byte generic frame header itself.
    search_end = min(spec.item_offset, len(message))
    geometries: dict[tuple[int, Optional[int]], list[int]] = {}
    for count_offset in range(5, max(5, search_end - 1)):
        declared_count = int.from_bytes(
            message[count_offset : count_offset + 2], "little"
        )
        if declared_count <= 0:
            continue

        if declared_count == 1:
            if len(message) != base_length:
                continue
            stride: Optional[int] = None
            deltas = [0]
        else:
            extra_length = len(message) - base_length
            divisor = declared_count - 1
            if extra_length <= 0 or extra_length % divisor:
                continue
            stride = extra_length // divisor
            prefix_length = base_length - stride
            if prefix_length < 5 or count_offset + 2 > prefix_length:
                continue
            if len(message) - prefix_length != declared_count * stride:
                continue

            relative_offsets = (
                spec.item_offset - prefix_length,
                spec.quantity_offset - prefix_length,
                instance_offset - prefix_length,
            )
            if min(relative_offsets) < 0:
                continue
            required_record_end = max(
                relative_offsets[0] + 4,
                relative_offsets[1] + 4,
                relative_offsets[2] + 8,
            )
            if required_record_end > stride:
                continue
            deltas = [stride * index for index in range(declared_count)]

        if not all(
            _has_plausible_transfer_record_values(
                message,
                item_offset=spec.item_offset + delta,
                quantity_offset=spec.quantity_offset + delta,
                instance_offset=instance_offset + delta,
            )
            for delta in deltas
        ):
            continue
        geometries[(declared_count, stride)] = deltas

    if len(geometries) != 1:
        return None
    return next(iter(geometries.values()))


def _declared_storage_record_deltas(
    spec: EventSpec,
    message: bytes,
) -> Optional[list[int]]:
    """Validate storage records against the calibration-learned count field.

    The count position is profile data discovered from record geometry; it is
    not a decoder layout constant.  A different header byte can coincidentally
    equal the right count, so production decoding must never select a count
    column independently for each message.  Missing authority or any
    contradiction returns an empty list and therefore cannot fall back to
    marker-only partial decoding.
    """
    if spec.label != "INVENTORY_TO_STORAGE":
        return None
    instance_offset = _structural_instance_offset(spec)
    base_length = spec.single_record_message_length
    count_offset = spec.record_count_offset
    if instance_offset is None or base_length is None or count_offset is None:
        return []
    if count_offset < 5 or count_offset + 2 > min(spec.item_offset, len(message)):
        return []

    declared_count = int.from_bytes(
        message[count_offset : count_offset + 2],
        "little",
    )
    if declared_count <= 0:
        return []
    if declared_count == 1:
        if len(message) != base_length:
            return []
        deltas = [0]
    else:
        extra_length = len(message) - base_length
        divisor = declared_count - 1
        if extra_length <= 0 or extra_length % divisor:
            return []
        stride = extra_length // divisor
        prefix_length = base_length - stride
        if (
            prefix_length < 5
            or count_offset + 2 > prefix_length
            or len(message) - prefix_length != declared_count * stride
        ):
            return []

        relative_offsets = (
            spec.item_offset - prefix_length,
            spec.quantity_offset - prefix_length,
            instance_offset - prefix_length,
        )
        if min(relative_offsets) < 0:
            return []
        required_record_end = max(
            relative_offsets[0] + 4,
            relative_offsets[1] + 4,
            relative_offsets[2] + 8,
        )
        if required_record_end > stride:
            return []
        deltas = [stride * index for index in range(declared_count)]

    if not all(
        _has_plausible_transfer_record_values(
            message,
            item_offset=spec.item_offset + delta,
            quantity_offset=spec.quantity_offset + delta,
            instance_offset=instance_offset + delta,
        )
        for delta in deltas
    ):
        return []
    return deltas


def _structural_record_deltas(
    spec: EventSpec,
    message: bytes,
    declared_storage_deltas: Optional[list[int]],
) -> Optional[list[int]]:
    """Find every repeated transfer record without trusting a saved stride.

    Profiles calibrated from a single action know the first-record offsets and
    base message length but cannot know the distance to a record that was never
    observed. Storage wrappers use their calibration-owned count field above;
    other transfer families may use their item-record marker and relative
    instance offset. The base-length equation guards against marker-like bytes
    elsewhere in the same message.
    """
    if declared_storage_deltas is not None:
        return declared_storage_deltas

    instance_offset = _structural_instance_offset(spec)
    if instance_offset is None or not _supports_structural_record_scan(spec):
        return None
    instance_delta = instance_offset - spec.item_offset

    offsets: list[int] = []
    search_at = spec.item_offset + _TRANSFER_RECORD_MARKER_DELTA
    while True:
        marker_at = message.find(_TRANSFER_RECORD_MARKER, search_at)
        if marker_at < 0:
            break
        search_at = marker_at + 1
        item_offset = marker_at - _TRANSFER_RECORD_MARKER_DELTA
        if item_offset < spec.item_offset:
            continue
        if _looks_like_transfer_record(message, item_offset, instance_delta):
            offsets.append(item_offset)

    # The calibrated first record is the anchor. Refuse a partial or shifted
    # match instead of turning an embedded item structure into an event.
    if not offsets or offsets[0] != spec.item_offset:
        return None

    if len(offsets) > 1:
        strides = [b - a for a, b in zip(offsets, offsets[1:])]
        minimum_stride = max(20, instance_delta + 8)
        if any(stride < minimum_stride for stride in strides):
            return None
        if len(set(strides)) != 1:
            return None
        inferred_stride = strides[0]
    else:
        inferred_stride = 0

    base_length = spec.single_record_message_length
    if base_length is not None:
        expected_length = base_length + (len(offsets) - 1) * inferred_stride
        if len(message) != expected_length:
            return None

    return [offset - spec.item_offset for offset in offsets]


def _configured_message_length_matches_spec(
    spec: EventSpec,
    message_length: int,
) -> bool:
    base_length = spec.single_record_message_length
    if base_length is None:
        return True
    if spec.repeat_stride is None:
        return message_length == base_length
    extra_records_length = message_length - base_length
    return extra_records_length >= 0 and extra_records_length % spec.repeat_stride == 0


class FrameCollectorScanner:
    """Collect generic length-framed BDO messages with midstream recovery.

    A live capture can attach in the middle of an established application
    frame.  In that state the first two bytes are arbitrary payload, not a
    trustworthy length.  Known target opcodes provide an immediate anchor;
    opcode-free calibration instead waits for two consecutive complete frame
    boundaries (or one exact standalone frame) before declaring sync.
    """

    _MAX_UNSYNCHRONIZED_BUFFER = MAX_TARGET_MESSAGE_LENGTH + 4

    def __init__(
        self,
        callback: Callable[[BDOFrame], None],
        known_opcodes: Iterable[int] = (),
    ) -> None:
        self._callback = callback
        self._known_opcodes = frozenset(known_opcodes)
        self._buffer = bytearray()
        self._buffer_start_sequence: Optional[int] = None
        self._frame_index = 0
        self._synchronized = False

    def reset(self) -> None:
        self._buffer.clear()
        self._buffer_start_sequence = None
        self._synchronized = False

    def can_anchor_at_start(self, data: bytes) -> bool:
        """Return whether byte zero is an evidence-backed frame boundary."""
        if len(data) < 5:
            return False
        first_length = int.from_bytes(data[0:2], "little")
        if not 5 <= first_length <= MAX_TARGET_MESSAGE_LENGTH:
            return False
        opcode = int.from_bytes(data[3:5], "little")
        if opcode in self._known_opcodes:
            return True
        if first_length == len(data):
            return True
        if first_length + 5 > len(data):
            return False
        second_length = int.from_bytes(
            data[first_length : first_length + 2], "little"
        )
        return (
            5 <= second_length <= MAX_TARGET_MESSAGE_LENGTH
            and first_length + second_length <= len(data)
        )

    def feed(self, data: bytes, context: PacketContext) -> None:
        if not data:
            return
        if not self._buffer:
            self._buffer_start_sequence = context.stream_start
        self._buffer.extend(data)
        self._scan(context)

    def scan_standalone(self, data: bytes, context: PacketContext) -> None:
        if not data:
            return
        saved_buffer = self._buffer
        saved_buffer_start_sequence = self._buffer_start_sequence
        saved_synchronized = self._synchronized
        self._buffer = bytearray(data)
        self._buffer_start_sequence = context.stream_start
        self._synchronized = False
        try:
            self._scan(context)
        finally:
            self._buffer = saved_buffer
            self._buffer_start_sequence = saved_buffer_start_sequence
            self._synchronized = saved_synchronized

    def _discard_prefix(self, byte_count: int) -> None:
        if byte_count <= 0:
            return
        del self._buffer[:byte_count]
        if self._buffer_start_sequence is not None:
            self._buffer_start_sequence += byte_count
        if not self._buffer:
            self._buffer_start_sequence = None

    def _scan(self, context: PacketContext) -> None:
        while len(self._buffer) >= 5:
            if not self._synchronized:
                candidate_start = self._find_synchronization_candidate()
                if candidate_start is None:
                    self._bound_unsynchronized_buffer()
                    return
                if candidate_start:
                    self._discard_prefix(candidate_start)
                self._synchronized = True

            message_length = int.from_bytes(self._buffer[0:2], "little")
            if not 5 <= message_length <= MAX_TARGET_MESSAGE_LENGTH:
                self._synchronized = False
                self._discard_prefix(1)
                continue

            if message_length > len(self._buffer):
                # Fragmentation is normal after a boundary has been proven.
                # Do not reinterpret item bytes inside this incomplete frame
                # as a later opcode anchor; FlowManager.reset() explicitly
                # drops synchronization after a real TCP gap.
                return

            message = bytes(self._buffer[:message_length])
            frame = BDOFrame(
                index=self._frame_index,
                message=message,
                context=context,
                stream_sequence=self._buffer_start_sequence,
            )
            self._frame_index += 1
            self._callback(frame)
            self._discard_prefix(message_length)

    def _find_synchronization_candidate(
        self,
        *,
        start_at: int = 0,
    ) -> Optional[int]:
        """Return the earliest defensible frame boundary in the buffer."""
        limit = len(self._buffer) - 4
        for start in range(start_at, max(start_at, limit)):
            first_length = int.from_bytes(self._buffer[start : start + 2], "little")
            if not 5 <= first_length <= MAX_TARGET_MESSAGE_LENGTH:
                continue
            first_end = start + first_length
            if first_end > len(self._buffer):
                continue

            opcode = int.from_bytes(self._buffer[start + 3 : start + 5], "little")
            if opcode in self._known_opcodes:
                return start

            # Preserve exact standalone/single-frame collection when capture
            # begins at a real boundary.  A candidate found after discarded
            # prefix bytes still needs stronger evidence.
            if start == 0 and first_end == len(self._buffer):
                return start

            if first_end + 5 <= len(self._buffer):
                second_length = int.from_bytes(
                    self._buffer[first_end : first_end + 2], "little"
                )
                if (
                    5 <= second_length <= MAX_TARGET_MESSAGE_LENGTH
                    and first_end + second_length <= len(self._buffer)
                ):
                    return start
        return None

    def _bound_unsynchronized_buffer(self) -> None:
        """Retain at most one maximum frame plus a split header."""
        excess = len(self._buffer) - self._MAX_UNSYNCHRONIZED_BUFFER
        if excess > 0:
            self._discard_prefix(excess)


class TargetMessageScanner:
    """Find target BDO messages in a contiguous application byte stream."""

    def __init__(
        self,
        callback: EventCallback,
        event_specs: Iterable[EventSpec],
        message_observer: Optional[MessageObserver] = None,
    ) -> None:
        self._buffer = bytearray()
        self._buffer_start_sequence: Optional[int] = None
        self._callback = callback
        self._message_observer = message_observer
        signature_groups: dict[bytes, list[EventSpec]] = {}
        for spec in event_specs:
            signature_groups.setdefault(spec.signature, []).append(spec)
        self._signature_groups = tuple(
            (signature, tuple(specs))
            for signature, specs in signature_groups.items()
        )

    def reset(self) -> None:
        self._buffer.clear()
        self._buffer_start_sequence = None

    def can_anchor_at_start(self, data: bytes) -> bool:
        """Return whether the bytes contain a configured recovery header."""
        if len(data) < 5:
            return False
        for signature, specs in self._signature_groups:
            signature_at = data.find(signature, 2)
            while signature_at >= 0:
                message_start = signature_at - 2
                message_length = int.from_bytes(
                    data[message_start:signature_at], "little"
                )
                for spec in specs:
                    if not (
                        spec.min_message_length
                        <= message_length
                        <= MAX_TARGET_MESSAGE_LENGTH
                    ):
                        continue
                    if self._message_length_matches_spec(spec, message_length):
                        return True
                signature_at = data.find(signature, signature_at + 1)
        return False

    def feed(self, data: bytes, context: PacketContext) -> None:
        if not data:
            return
        if not self._buffer:
            self._buffer_start_sequence = context.stream_start
        self._buffer.extend(data)
        self._scan(context)

    def scan_standalone(self, data: bytes, context: PacketContext) -> None:
        if not data:
            return
        saved_buffer = self._buffer
        saved_buffer_start_sequence = self._buffer_start_sequence
        self._buffer = bytearray(data)
        self._buffer_start_sequence = context.stream_start
        try:
            self._scan(context)
        finally:
            self._buffer = saved_buffer
            self._buffer_start_sequence = saved_buffer_start_sequence

    def _discard_prefix(self, byte_count: int) -> None:
        if byte_count <= 0:
            return
        del self._buffer[:byte_count]
        if self._buffer_start_sequence is not None:
            self._buffer_start_sequence += byte_count
        if not self._buffer:
            self._buffer_start_sequence = None

    def _scan(self, context: PacketContext) -> None:
        while True:
            complete_candidates: list[tuple[int, int, EventSpec]] = []
            incomplete_candidate: Optional[tuple[int, int, EventSpec]] = None

            # Search all known opcode signatures. A signature begins at header
            # byte 2, so the two bytes immediately before it are the length.
            for signature, specs in self._signature_groups:
                search_at = 0
                while True:
                    signature_at = self._buffer.find(signature, search_at)
                    if signature_at < 0:
                        break
                    search_at = signature_at + 1

                    message_start = signature_at - 2
                    if message_start < 0:
                        continue

                    message_length = int.from_bytes(
                        self._buffer[message_start : message_start + 2], "little"
                    )
                    for spec in specs:
                        if not (
                            spec.min_message_length
                            <= message_length
                            <= MAX_TARGET_MESSAGE_LENGTH
                        ):
                            continue
                        if not self._message_length_matches_spec(
                            spec, message_length
                        ):
                            continue

                        candidate = (message_start, message_length, spec)
                        if message_start + message_length <= len(self._buffer):
                            if (
                                not complete_candidates
                                or message_start < complete_candidates[0][0]
                            ):
                                complete_candidates = [candidate]
                            elif message_start == complete_candidates[0][0]:
                                complete_candidates.append(candidate)
                        elif (
                            incomplete_candidate is None
                            or message_start < incomplete_candidate[0]
                        ):
                            incomplete_candidate = candidate

            if not complete_candidates:
                if incomplete_candidate is not None:
                    # Retain the incomplete target frame and wait for more TCP
                    # bytes. Bytes before it cannot be part of that frame.
                    message_start = incomplete_candidate[0]
                    if message_start:
                        self._discard_prefix(message_start)
                else:
                    # Retain enough trailing bytes to catch a five-byte header
                    # split across the next TCP segment.
                    if len(self._buffer) > 4:
                        self._discard_prefix(len(self._buffer) - 4)
                return

            # An earlier incomplete frame may contain a later complete-looking
            # signature in its payload.  Preserve it until its declared bytes
            # arrive instead of skipping ahead and decoding the nested bytes.
            if (
                incomplete_candidate is not None
                and incomplete_candidate[0] < complete_candidates[0][0]
            ):
                message_start = incomplete_candidate[0]
                if message_start:
                    self._discard_prefix(message_start)
                return

            message_start, message_length, _ = complete_candidates[0]
            message_end = message_start + message_length
            message = bytes(self._buffer[message_start:message_end])
            stream_sequence = (
                self._buffer_start_sequence + message_start
                if self._buffer_start_sequence is not None
                else None
            )

            valid_decodes: list[tuple[EventSpec, list[LootEvent]]] = []
            for _, candidate_length, spec in complete_candidates:
                source_context_candidate = None
                if spec.source_context_offset is not None:
                    source_context_end = (
                        spec.source_context_offset + spec.source_context_length
                    )
                    source_context_candidate = bytes(
                        message[spec.source_context_offset : source_context_end]
                    )

                decoded_events = self._decode_events_from_message(
                    spec=spec,
                    message=message,
                    message_length=candidate_length,
                    source_context_candidate=source_context_candidate,
                    context=context,
                    stream_sequence=stream_sequence,
                )
                if decoded_events is not None:
                    valid_decodes.append((spec, decoded_events))

            storage_candidate = next(
                (
                    spec
                    for _, _, spec in complete_candidates
                    if spec.label == "INVENTORY_TO_STORAGE"
                ),
                None,
            )
            if storage_candidate is not None and self._message_observer is not None:
                storage_decodes = tuple(
                    decoded
                    for decoded in valid_decodes
                    if decoded[0].label == "INVENTORY_TO_STORAGE" and decoded[1]
                )
                # A different same-opcode layout that validates uniquely is not
                # a rejected storage wrapper. It belongs to that other family.
                if not (valid_decodes and not storage_decodes):
                    decoded_storage = (
                        storage_decodes[0]
                        if len(valid_decodes) == 1 and len(storage_decodes) == 1
                        else None
                    )
                    self._message_observer(
                    storage_candidate.opcode,
                    message_length,
                    "decoded" if decoded_storage is not None else "rejected",
                    len(decoded_storage[1]) if decoded_storage is not None else 0,
                    context,
                    stream_sequence,
                )

            # Same-opcode layouts are alternatives, not an order-dependent
            # fallback list.  Decode only when exactly one layout proves its
            # geometry; reject both malformed and genuinely ambiguous frames.
            if len(valid_decodes) != 1:
                self._discard_prefix(message_start + 1)
                continue

            for event in valid_decodes[0][1]:
                self._callback(event, message)

            # Consume through the end of the decoded message and continue in
            # case another target message is already buffered.
            self._discard_prefix(message_end)

    @staticmethod
    def _message_length_matches_spec(spec: EventSpec, message_length: int) -> bool:
        # A structurally self-validating transfer may carry a stride that was
        # absent from a single-record calibration or changed after a patch.
        # Let the complete message reach the structural validator below.
        if _supports_structural_record_scan(spec):
            return True
        return _configured_message_length_matches_spec(spec, message_length)

    def _decode_events_from_message(
        self,
        *,
        spec: EventSpec,
        message: bytes,
        message_length: int,
        source_context_candidate: Optional[bytes],
        context: PacketContext,
        stream_sequence: Optional[int],
    ) -> Optional[list[LootEvent]]:
        is_inventory_snapshot = (
            spec.label == "INVENTORY_TRANSFER"
            and source_context_candidate == CHARACTER_LOAD_CONTEXT
        )
        declared_storage_deltas = (
            _declared_storage_record_deltas(spec, message)
            if spec.label == "INVENTORY_TO_STORAGE"
            else None
        )

        if is_inventory_snapshot:
            # Character-load frames are all-or-nothing.  They may resemble a
            # normal transfer record, but must never fall back to record-one
            # or marker scanning when their declared layout is malformed.
            snapshot_deltas = _declared_inventory_snapshot_record_deltas(
                spec,
                message,
            )
            if snapshot_deltas is None:
                return None
            candidate_deltas = snapshot_deltas
        else:
            structural_deltas = _structural_record_deltas(
                spec,
                message,
                declared_storage_deltas,
            )
            if structural_deltas is not None:
                candidate_deltas = structural_deltas
            else:
                # Structural discovery is deliberately strict. Preserve support
                # for older/synthetic layouts through the calibrated stride, but
                # never accept an off-stride message merely because record 1 fits.
                if not _configured_message_length_matches_spec(spec, message_length):
                    return None
                candidate_deltas = []
                offset_delta = 0
                while True:
                    required_end = max(
                        spec.item_offset + offset_delta + 4,
                        spec.quantity_offset + offset_delta + 4,
                    )
                    if spec.inventory_slot_offset is not None:
                        required_end = max(
                            required_end,
                            spec.inventory_slot_offset + offset_delta + 1,
                        )
                    if spec.item_instance_offset is not None:
                        required_end = max(
                            required_end,
                            spec.item_instance_offset + offset_delta + 8,
                        )
                    if spec.storage_instance_offset is not None:
                        required_end = max(
                            required_end,
                            spec.storage_instance_offset + offset_delta + 8,
                        )
                    if required_end > len(message):
                        break
                    candidate_deltas.append(offset_delta)
                    if spec.repeat_stride is None:
                        break
                    offset_delta += spec.repeat_stride

        records: list[tuple[int, int]] = []
        for offset_delta in candidate_deltas:
            item_offset = spec.item_offset + offset_delta
            quantity_offset = spec.quantity_offset + offset_delta
            required_end = max(item_offset + 4, quantity_offset + 4)
            if spec.inventory_slot_offset is not None:
                required_end = max(
                    required_end, spec.inventory_slot_offset + offset_delta + 1
                )
            if spec.item_instance_offset is not None:
                required_end = max(
                    required_end, spec.item_instance_offset + offset_delta + 8
                )
            if spec.storage_instance_offset is not None:
                required_end = max(
                    required_end, spec.storage_instance_offset + offset_delta + 8
                )
            if required_end > len(message):
                continue
            records.append((offset_delta, item_offset))

        storage_id: Optional[int] = None
        storage_operation: Optional[str] = None
        if spec.label == "INVENTORY_TO_STORAGE" and records:
            if (
                spec.source_context_offset is not None
                and source_context_candidate is not None
                and len(source_context_candidate) == 4
            ):
                # Calibration owns this column. Runtime never scans for a
                # known-looking town key: an incomplete profile stays
                # unresolved, and a new numeric ID stays attached to its true
                # field for an explicit registry diagnostic.
                storage_id = int.from_bytes(source_context_candidate, "little")
            # Framing proves records and destination only.  Operation semantics
            # are stateful: decrement evidence proves manual live activity,
            # the shared-token companion chain proves worker live activity,
            # and a hydration cohort proves snapshot state.  No patch-specific
            # mode or token byte is consulted here.
            storage_operation = "unknown"

        events: list[LootEvent] = []
        for record_index, (offset_delta, item_offset) in enumerate(records, 1):
            quantity_offset = spec.quantity_offset + offset_delta
            item_id = int.from_bytes(message[item_offset : item_offset + 4], "little")
            quantity = int.from_bytes(
                message[quantity_offset : quantity_offset + 4],
                "little",
            )

            if item_id <= 0 or item_id > MAX_PLAUSIBLE_ITEM_ID or quantity <= 0:
                continue

            inventory_slot = (
                message[spec.inventory_slot_offset + offset_delta]
                if spec.inventory_slot_offset is not None
                else None
            )
            item_instance = (
                bytes(
                    message[
                        spec.item_instance_offset
                        + offset_delta : spec.item_instance_offset
                        + offset_delta
                        + 8
                    ]
                )
                if spec.item_instance_offset is not None
                else None
            )
            storage_instance = (
                bytes(
                    message[
                        spec.storage_instance_offset
                        + offset_delta : spec.storage_instance_offset
                        + offset_delta
                        + 8
                    ]
                )
                if spec.storage_instance_offset is not None
                else None
            )
            events.append(
                LootEvent(
                    label=spec.label,
                    opcode=spec.opcode,
                    item_id=item_id,
                    quantity=quantity,
                    inventory_slot=inventory_slot,
                    source_context_candidate=source_context_candidate,
                    item_instance=item_instance,
                    storage_instance=storage_instance,
                    message_length=message_length,
                    default_context=spec.default_context,
                    context=context,
                    stream_sequence=stream_sequence,
                    record_offset=item_offset,
                    record_index=record_index if len(records) > 1 else None,
                    record_count=len(records) if len(records) > 1 else None,
                    storage_id=storage_id,
                    storage_operation=storage_operation,
                )
            )
        if events:
            return events
        return [] if is_inventory_snapshot and not candidate_deltas else None
