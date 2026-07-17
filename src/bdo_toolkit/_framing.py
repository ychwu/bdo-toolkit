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
)


_TRANSFER_RECORD_MARKER = b"\x00" * 4 + b"\xff" * 8
_TRANSFER_RECORD_MARKER_DELTA = 8


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
    instance = message[
        item_offset + instance_delta : item_offset + instance_delta + 8
    ]
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


def _structural_record_deltas(
    spec: EventSpec,
    message: bytes,
) -> Optional[list[int]]:
    """Find every repeated transfer record without trusting a saved stride.

    Profiles calibrated from a single action know the first-record offsets and
    base message length but cannot know the distance to a record that was never
    observed. The item-record marker and relative instance offset let a later
    batch reveal that distance directly. The base-length equation guards
    against marker-like bytes elsewhere in the same message.
    """
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
    """Collect every generic length-framed BDO message, used by calibration."""

    def __init__(self, callback: Callable[[BDOFrame], None]) -> None:
        self._callback = callback
        self._buffer = bytearray()
        self._buffer_start_sequence: Optional[int] = None
        self._frame_index = 0

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
        while len(self._buffer) >= 5:
            message_length = int.from_bytes(self._buffer[0:2], "little")
            if not 5 <= message_length <= MAX_TARGET_MESSAGE_LENGTH:
                self._discard_prefix(1)
                continue

            if message_length > len(self._buffer):
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
            complete_candidate: Optional[tuple[int, int, EventSpec]] = None
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
                            complete_candidate is None
                            or message_start < complete_candidate[0]
                        ):
                            complete_candidate = candidate
                    elif (
                        incomplete_candidate is None
                        or message_start < incomplete_candidate[0]
                    ):
                        incomplete_candidate = candidate

            if complete_candidate is None:
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

            message_start, message_length, spec = complete_candidate
            message_end = message_start + message_length
            message = bytes(self._buffer[message_start:message_end])
            stream_sequence = (
                self._buffer_start_sequence + message_start
                if self._buffer_start_sequence is not None
                else None
            )

            source_context_candidate = None
            if spec.source_context_offset is not None:
                source_context_end = (
                    spec.source_context_offset + spec.source_context_length
                )
                source_context_candidate = bytes(
                    message[spec.source_context_offset:source_context_end]
                )

            decoded_events = self._decode_events_from_message(
                spec=spec,
                message=message,
                message_length=message_length,
                source_context_candidate=source_context_candidate,
                context=context,
                stream_sequence=stream_sequence,
            )
            if not decoded_events:
                self._discard_prefix(message_start + 1)
                continue

            for event in decoded_events:
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
    ) -> list[LootEvent]:
        if (
            spec.label == "INVENTORY_TRANSFER"
            and source_context_candidate == CHARACTER_LOAD_CONTEXT
        ):
            return []

        structural_deltas = _structural_record_deltas(spec, message)
        if structural_deltas is not None:
            candidate_deltas = structural_deltas
        else:
            # Structural discovery is deliberately strict. Preserve support
            # for older/synthetic layouts through the calibrated stride, but
            # never accept an off-stride message merely because record 1 fits.
            if not _configured_message_length_matches_spec(spec, message_length):
                return []
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
                required_end = max(required_end, spec.inventory_slot_offset + offset_delta + 1)
            if spec.item_instance_offset is not None:
                required_end = max(required_end, spec.item_instance_offset + offset_delta + 8)
            if spec.storage_instance_offset is not None:
                required_end = max(required_end, spec.storage_instance_offset + offset_delta + 8)
            if required_end > len(message):
                continue
            records.append((offset_delta, item_offset))

        events: list[LootEvent] = []
        for record_index, (offset_delta, item_offset) in enumerate(records, 1):
            quantity_offset = spec.quantity_offset + offset_delta
            item_id = int.from_bytes(message[item_offset : item_offset + 4], "little")
            quantity = int.from_bytes(
                message[quantity_offset : quantity_offset + 4],
                "little",
            )

            if (
                item_id <= 0
                or item_id > MAX_PLAUSIBLE_ITEM_ID
                or quantity <= 0
            ):
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
                )
            )
        return events
