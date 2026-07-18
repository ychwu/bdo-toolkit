"""Midstream-safe generic BDO framing used by Solare structural discovery."""

from __future__ import annotations

from typing import Callable, Optional

from bdo_toolkit._protocol import BDOFrame, PacketContext

from ._constants import (
    BDO_HEADER_SIZE,
    BDO_MAX_FRAME_SIZE,
    DISCOVERY_MAX_FRAME_LENGTH,
    DISCOVERY_MIN_FRAME_LENGTH,
    DISCOVERY_SYNC_BUFFER_LIMIT,
    DISCOVERY_SYNC_HEADERS,
)


def _u16le(data: bytes | bytearray, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 2], "little")


class SolareDiscoveryStreamScanner:
    """Emit generic frames without trusting a known Solare opcode.

    Live capture can attach in the middle of an application message. The
    scanner therefore requires either two equal large-family headers or three
    consecutive generic flag-zero headers before it declares synchronization.
    """

    def __init__(
        self,
        callback: Callable[[BDOFrame], None],
        reset_callback: Optional[Callable[[], None]] = None,
    ) -> None:
        self._callback = callback
        self._reset_callback = reset_callback
        self._buffer = bytearray()
        self._buffer_start_sequence: Optional[int] = None
        self._locked = False
        self._frame_index = 0

    def reset(self) -> None:
        self._buffer.clear()
        self._buffer_start_sequence = None
        self._locked = False
        if self._reset_callback is not None:
            self._reset_callback()

    def feed(self, data: bytes, context: PacketContext) -> None:
        if not data:
            return
        if not self._buffer:
            self._buffer_start_sequence = context.stream_start
        self._buffer.extend(data)
        self._scan(context)

    def scan_standalone(self, data: bytes, context: PacketContext) -> None:
        # FlowManager invokes this for overlap/retransmission bytes already
        # represented in the primary stream. Ignoring them prevents duplicate
        # discovery frames.
        return

    def _discard_prefix(self, byte_count: int) -> None:
        if byte_count <= 0:
            return
        del self._buffer[:byte_count]
        if self._buffer_start_sequence is not None:
            self._buffer_start_sequence += byte_count
        if not self._buffer:
            self._buffer_start_sequence = None

    def _header_length(self, offset: int) -> Optional[int]:
        if offset + BDO_HEADER_SIZE > len(self._buffer):
            return None
        message_length = _u16le(self._buffer, offset)
        if not BDO_HEADER_SIZE <= message_length <= BDO_MAX_FRAME_SIZE:
            return -1
        if self._buffer[offset + 2] != 0:
            return -1
        return message_length

    def _has_sync_chain(self, offset: int) -> Optional[bool]:
        position = offset
        for index in range(DISCOVERY_SYNC_HEADERS):
            message_length = self._header_length(position)
            if message_length is None:
                return None
            if message_length < BDO_HEADER_SIZE:
                return False
            if index == DISCOVERY_SYNC_HEADERS - 1:
                return True
            if position + message_length > len(self._buffer):
                return None
            position += message_length
        return True

    def _find_sync_offset(self) -> Optional[int]:
        final_offset = len(self._buffer) - BDO_HEADER_SIZE
        for offset in range(max(0, final_offset + 1)):
            if self._has_sync_chain(offset) is True:
                return offset
        return None

    def _find_repeated_large_family_offset(self) -> Optional[int]:
        final_offset = len(self._buffer) - BDO_HEADER_SIZE
        for offset in range(max(0, final_offset + 1)):
            message_length = self._header_length(offset)
            if message_length is None or not (
                DISCOVERY_MIN_FRAME_LENGTH
                <= message_length
                <= DISCOVERY_MAX_FRAME_LENGTH
            ):
                continue
            next_offset = offset + message_length
            next_length = self._header_length(next_offset)
            if next_length != message_length:
                continue
            if _u16le(self._buffer, offset + 3) != _u16le(
                self._buffer, next_offset + 3
            ):
                continue
            return offset
        return None

    def _scan(self, context: PacketContext) -> None:
        while True:
            if not self._locked:
                sync_offset = self._find_repeated_large_family_offset()
                if sync_offset is None:
                    sync_offset = self._find_sync_offset()
                if sync_offset is None:
                    if len(self._buffer) > DISCOVERY_SYNC_BUFFER_LIMIT:
                        self._discard_prefix(
                            len(self._buffer) - DISCOVERY_SYNC_BUFFER_LIMIT
                        )
                    return
                if sync_offset:
                    self._discard_prefix(sync_offset)
                self._locked = True

            message_length = self._header_length(0)
            if message_length is None:
                return
            if message_length < BDO_HEADER_SIZE:
                self._locked = False
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
