"""Scan a reassembled application byte stream for target BDO messages."""

from __future__ import annotations

from typing import Iterable, Optional

from typing import Callable

from ._protocol import (
    CHARACTER_LOAD_CONTEXT,
    MAX_PLAUSIBLE_ITEM_ID,
    MAX_TARGET_MESSAGE_LENGTH,
    BDOFrame,
    EventCallback,
    EventSpec,
    LootEvent,
    PacketContext,
    storage_location,
)

_TRANSFER_RECORD_MARKER = b"\x00" * 4 + b"\xff" * 8
_TRANSFER_RECORD_MARKER_DELTA = 8
_STORAGE_RECORD_COUNT_DELTA = 20
_STORAGE_OPERATION_MODE_DELTA = 30
_STORAGE_OPERATION_TOKEN_START_DELTA = 29
_STORAGE_OPERATION_TOKEN_END_DELTA = 21


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


def _storage_operation_fields(
    spec: EventSpec,
    message: bytes,
) -> Optional[tuple[int, bytes]]:
    """Return current-wrapper mode/token fields when their layout fits."""
    if (
        spec.label != "INVENTORY_TO_STORAGE"
        or spec.source_context_offset not in (None, spec.item_offset - 9)
        or spec.source_context_length != 4
    ):
        return None
    mode_offset = spec.item_offset - _STORAGE_OPERATION_MODE_DELTA
    token_start = spec.item_offset - _STORAGE_OPERATION_TOKEN_START_DELTA
    token_end = spec.item_offset - _STORAGE_OPERATION_TOKEN_END_DELTA
    if mode_offset < 5 or token_start < 0 or token_end > len(message):
        return None
    return message[mode_offset], message[token_start:token_end]


def _current_storage_context_candidate(
    spec: EventSpec,
    message: bytes,
    source_context_candidate: Optional[bytes] = None,
) -> Optional[bytes]:
    """Return an explicit or safely positioned current-wrapper destination."""
    if source_context_candidate is not None:
        return source_context_candidate if len(source_context_candidate) == 4 else None
    if spec.source_context_offset is not None:
        return None
    context_offset = spec.item_offset - 9
    if context_offset < 0 or context_offset + 4 > len(message):
        return None
    return bytes(message[context_offset : context_offset + 4])


def _has_known_storage_operation_signature(
    spec: EventSpec,
    message: bytes,
) -> bool:
    fields = _storage_operation_fields(spec, message)
    if fields is None:
        return False
    mode, token = fields
    return (mode == 2 and token == b"\x00" * 8) or (mode == 1 and token != b"\x00" * 8)


def _declared_storage_record_deltas(
    spec: EventSpec,
    message: bytes,
) -> Optional[list[int]]:
    """Use a storage wrapper's declared count to prove its record geometry.

    The current wrapper places a little-endian uint16 count 20 bytes before
    the calibrated first item.  A single-record calibration supplies the base
    message length.  For a later batch, those two facts determine the stride
    and wrapper-prefix length without trusting a saved stride or requiring an
    item-type-specific marker inside every record.

    ``None`` means this is not demonstrably the declared-count layout and the
    older marker-based validator may still inspect it.  An empty list means
    the layout was proven but at least one declared record was invalid, so the
    whole message must fail closed rather than emitting a partial batch.
    """
    if spec.label != "INVENTORY_TO_STORAGE":
        return None
    context_candidate = _current_storage_context_candidate(spec, message)
    inferred_storage_id = (
        int.from_bytes(context_candidate, "little")
        if context_candidate is not None
        else None
    )
    strict_declared_layout = (
        _has_known_storage_operation_signature(spec, message)
        or storage_location(inferred_storage_id) is not None
    )

    def invalid_geometry() -> Optional[list[int]]:
        # Once the current wrapper layout is identified, a contradictory
        # declaration is malformed rather than an invitation to reinterpret
        # the same bytes through the legacy marker fallback.
        return [] if strict_declared_layout else None

    instance_offset = _structural_instance_offset(spec)
    base_length = spec.single_record_message_length
    if instance_offset is None or base_length is None:
        return None

    count_offset = spec.item_offset - _STORAGE_RECORD_COUNT_DELTA
    if count_offset < 5 or count_offset + 2 > len(message):
        return None
    declared_count = int.from_bytes(message[count_offset : count_offset + 2], "little")
    if declared_count <= 0:
        return invalid_geometry()

    if declared_count == 1:
        if len(message) != base_length:
            return invalid_geometry()
        deltas = [0]
    else:
        extra_length = len(message) - base_length
        divisor = declared_count - 1
        if extra_length <= 0 or extra_length % divisor:
            return invalid_geometry()

        stride = extra_length // divisor
        prefix_length = base_length - stride
        if prefix_length < 5 or count_offset + 2 > prefix_length:
            return invalid_geometry()
        if len(message) - prefix_length != declared_count * stride:
            return invalid_geometry()

        # All calibrated fields must fit wholly inside one inferred record.
        # This rejects coincidental integers in an older wrapper's header.
        relative_offsets = (
            spec.item_offset - prefix_length,
            spec.quantity_offset - prefix_length,
            instance_offset - prefix_length,
        )
        if min(relative_offsets) < 0:
            return invalid_geometry()
        required_record_end = max(
            relative_offsets[0] + 4,
            relative_offsets[1] + 4,
            relative_offsets[2] + 8,
        )
        if required_record_end > stride:
            return invalid_geometry()
        deltas = [stride * index for index in range(declared_count)]

    for delta in deltas:
        if not _has_plausible_transfer_record_values(
            message,
            item_offset=spec.item_offset + delta,
            quantity_offset=spec.quantity_offset + delta,
            instance_offset=instance_offset + delta,
        ):
            return []
    return deltas


def _storage_wrapper_metadata(
    spec: EventSpec,
    message: bytes,
    source_context_candidate: Optional[bytes],
    declared_deltas: Optional[list[int]],
) -> tuple[Optional[int], Optional[str], Optional[bytes]]:
    """Decode metadata only for the observed destination-key wrapper layout."""
    fields = _storage_operation_fields(spec, message)
    if fields is None or not declared_deltas:
        return None, None, None
    context_candidate = _current_storage_context_candidate(
        spec,
        message,
        source_context_candidate,
    )
    if context_candidate is None:
        return None, None, None
    mode, token = fields
    # The wrapper is recognized, but an unfamiliar mode/token combination is
    # deliberately neutral. It must not silently become a live deposit after
    # a patch changes the operation discriminator.
    operation: Optional[str] = "unknown"
    if mode == 2 and token == b"\x00" * 8:
        operation = "snapshot"
    elif mode == 1 and token != b"\x00" * 8:
        operation = "live"
    storage_id = int.from_bytes(context_candidate, "little")
    if operation == "unknown" and storage_location(storage_id) is None:
        # The unfamiliar discriminator cannot authenticate an otherwise
        # arbitrary uint32 at item-9.  Keep the frame neutral without
        # publishing that value as a destination.
        return None, operation, None
    return storage_id, operation, context_candidate


def _structural_record_deltas(
    spec: EventSpec,
    message: bytes,
    declared_storage_deltas: Optional[list[int]],
) -> Optional[list[int]]:
    """Find every repeated transfer record without trusting a saved stride.

    Profiles calibrated from a single action know the first-record offsets and
    base message length but cannot know the distance to a record that was never
    observed. Prefer a wrapper-declared count when its full geometry and every
    record validate. Older wrappers fall back to the item-record marker and
    relative instance offset. The base-length equation guards against
    marker-like bytes elsewhere in the same message.
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
    ) -> None:
        self._buffer = bytearray()
        self._buffer_start_sequence: Optional[int] = None
        self._callback = callback
        self._event_specs = tuple(event_specs)

    def reset(self) -> None:
        self._buffer.clear()
        self._buffer_start_sequence = None

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
            for spec in self._event_specs:
                search_at = 0
                while True:
                    signature_at = self._buffer.find(spec.signature, search_at)
                    if signature_at < 0:
                        break
                    search_at = signature_at + 1

                    message_start = signature_at - 2
                    if message_start < 0:
                        continue

                    message_length = int.from_bytes(
                        self._buffer[message_start : message_start + 2], "little"
                    )
                    if not (
                        spec.min_message_length
                        <= message_length
                        <= MAX_TARGET_MESSAGE_LENGTH
                    ):
                        continue
                    if not self._message_length_matches_spec(spec, message_length):
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

            valid_decodes: list[list[LootEvent]] = []
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
                    valid_decodes.append(decoded_events)

            # Same-opcode layouts are alternatives, not an order-dependent
            # fallback list.  Decode only when exactly one layout proves its
            # geometry; reject both malformed and genuinely ambiguous frames.
            if len(valid_decodes) != 1:
                self._discard_prefix(message_start + 1)
                continue

            for event in valid_decodes[0]:
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

        storage_id, storage_operation, inferred_context = _storage_wrapper_metadata(
            spec,
            message,
            source_context_candidate,
            declared_storage_deltas,
        )
        if source_context_candidate is None and inferred_context is not None:
            source_context_candidate = inferred_context

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
