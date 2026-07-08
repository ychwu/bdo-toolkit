"""Worker/manual origin classification for storage-delta events.

Correlation logic (see docs/PACKET_PROTOCOL_WIKI.md, worker-isolation
sections): a manual deposit removes items from the player's own inventory, so
a source-stack-decrement whose quantity MATCHES the deposited record precedes
the storage delta; a worker's items were never in the player's inventory, so
no matching decrement exists, and the delta is followed by the 0x1558+0x1168
companion pair — observed on every known worker capture in both storage-delta
context modes, never near a manual deposit. The raw context bytes (05/20) do
NOT encode worker-vs-manual and are ignored here.

An ambient, non-matching decrement near a worker deposit is a real occurrence
(7002_qty25 capture), which is why matching is required, not mere presence.

Verdicts are fail-closed: conflicting or absent evidence yields "unknown".
Classification needs a short forward look for the companions, so storage-delta
events are deferred a few frames (or until end of capture) before emission.
"""

from __future__ import annotations

import dataclasses
from collections import deque
from dataclasses import dataclass, field
from typing import Callable, Iterable, Optional

from ._protocol import (
    MAX_TARGET_MESSAGE_LENGTH,
    WORKER_DEPOSIT_COMPANION_OPCODES,
    BDOFrame,
    FlowKey,
)
from .events import BDOEvent

ORIGIN_WORKER = "worker"
ORIGIN_MANUAL = "manual"
ORIGIN_UNKNOWN = "unknown"


@dataclass(frozen=True)
class DecrementSpec:
    """One source-stack-decrement shape to test candidates against.

    With a calibrated ``quantity_offset`` the match is position-exact; without
    one the check falls back to byte containment (weaker, still excludes
    frames carrying the deposited item id, which decrements never do).
    """

    opcode: int
    quantity_offset: Optional[int] = None


@dataclass
class _PendingDeposit:
    event: BDOEvent
    flow: FlowKey
    stream_sequence: Optional[int]
    timestamp: float
    matching_decrement: bool
    companions_seen: set[int] = field(default_factory=set)
    frames_after: int = 0
    # Where the delta frame ends in the stream: the companions are chained
    # immediately after, so this anchors a desync-proof byte-level scan.
    end_sequence: Optional[int] = None
    companions_resolved: Optional[bool] = None


class DepositOriginTracker:
    """Correlate storage-delta events with surrounding frames per flow."""

    LOOKAHEAD_FRAMES = 4
    STALE_SECONDS = 2.0
    BACKWARD_WINDOW = 16
    COMPANION_CHAIN_FRAMES = 4

    def __init__(
        self,
        *,
        decrement_specs: Iterable[DecrementSpec],
        emit: Callable[[BDOEvent], None],
    ) -> None:
        self._decrement_specs: dict[int, DecrementSpec] = {}
        for spec in decrement_specs:
            existing = self._decrement_specs.get(spec.opcode)
            # A calibrated (position-exact) spec beats an offset-less fallback.
            if existing is None or existing.quantity_offset is None:
                self._decrement_specs[spec.opcode] = spec
        self._emit = emit
        self._recent: dict[FlowKey, deque[BDOFrame]] = {}
        self._pending: list[_PendingDeposit] = []

    # --- frame stream ---

    def observe_frame(self, frame: BDOFrame) -> None:
        window = self._recent.setdefault(
            frame.context.flow, deque(maxlen=self.BACKWARD_WINDOW)
        )
        window.append(frame)
        if not self._pending:
            return

        still: list[_PendingDeposit] = []
        for pending in self._pending:
            if pending.flow != frame.context.flow:
                # Traffic on other flows only ages the deposit out.
                if frame.context.timestamp - pending.timestamp > self.STALE_SECONDS:
                    self._finalize(pending)
                else:
                    still.append(pending)
                continue
            if not self._frame_is_after(frame, pending):
                still.append(pending)
                continue
            # New bytes on this flow: retry the anchored companion scan first.
            resolved = self._scan_companions_after(pending)
            if resolved is not None:
                pending.companions_resolved = resolved
                self._finalize(pending)
                continue
            pending.frames_after += 1
            if frame.opcode in WORKER_DEPOSIT_COMPANION_OPCODES:
                pending.companions_seen.add(frame.opcode)
            if (
                set(WORKER_DEPOSIT_COMPANION_OPCODES) <= pending.companions_seen
                or pending.frames_after >= self.LOOKAHEAD_FRAMES
                or frame.context.timestamp - pending.timestamp > self.STALE_SECONDS
            ):
                self._finalize(pending)
            else:
                still.append(pending)
        self._pending = still

    @staticmethod
    def _frame_is_after(frame: BDOFrame, pending: _PendingDeposit) -> bool:
        if pending.stream_sequence is None or frame.stream_sequence is None:
            # Without sequence anchoring, count every later-observed frame.
            return True
        return frame.stream_sequence > pending.stream_sequence

    # --- event stream ---

    def register(self, event: BDOEvent) -> None:
        """Defer a storage-delta event until its forward window resolves."""
        flow = FlowKey(
            source_ip=event.flow.source_ip,
            source_port=event.flow.source_port,
            destination_ip=event.flow.destination_ip,
            destination_port=event.flow.destination_port,
        )
        stream_sequence = event.extra.get("stream_sequence")
        end_sequence = None
        if stream_sequence is not None and event.message_length is not None:
            end_sequence = stream_sequence + event.message_length
        pending = _PendingDeposit(
            event=event,
            flow=flow,
            stream_sequence=stream_sequence,
            timestamp=event.timestamp,
            matching_decrement=self._has_matching_decrement(
                flow, stream_sequence, event
            ),
            end_sequence=end_sequence,
        )
        pending.companions_resolved = self._scan_companions_after(pending)
        if pending.companions_resolved is not None:
            # Anchored byte scan resolved either way: verdict is computable.
            self._finalize(pending)
            return

        # Fallback (no sequence anchoring, or companion bytes not captured
        # yet): the frame tap runs ahead of the event decoder within a TCP
        # segment, so companions delivered in the same segment are already in
        # the window; credit them (and the lookahead) immediately.
        for frame in self._recent.get(flow, ()):
            if not self._frame_is_after(frame, pending):
                continue
            pending.frames_after += 1
            if frame.opcode in WORKER_DEPOSIT_COMPANION_OPCODES:
                pending.companions_seen.add(frame.opcode)

        if (
            set(WORKER_DEPOSIT_COMPANION_OPCODES) <= pending.companions_seen
            or pending.frames_after >= self.LOOKAHEAD_FRAMES
        ):
            self._finalize(pending)
        else:
            self._pending.append(pending)

    # --- anchored companion scan ---

    def _read_span(self, flow: FlowKey, start: int, length: int) -> Optional[bytes]:
        """Read stream bytes [start, start+length) from observed frames.

        Works even when the frame tap has lost framing sync: the tap's
        (stream_sequence, bytes) spans stay correct regardless of how the
        naive length-chained parser grouped them.
        """
        out = bytearray()
        pos = start
        remaining = length
        frames = self._recent.get(flow, ())
        while remaining > 0:
            source = None
            for frame in frames:
                if frame.stream_sequence is None:
                    continue
                offset = pos - frame.stream_sequence
                if 0 <= offset < len(frame.message):
                    source = frame
                    break
            if source is None:
                return None
            offset = pos - source.stream_sequence
            chunk = source.message[offset : offset + remaining]
            out += chunk
            pos += len(chunk)
            remaining -= len(chunk)
        return bytes(out)

    def _scan_companions_after(self, pending: _PendingDeposit) -> Optional[bool]:
        """Walk chained frame headers from the delta frame's end.

        The worker companions are the frames immediately after the storage
        delta, so parsing headers from that known-good stream position is
        immune to frame-tap desync (the failure observed in the
        all_packets_unknown_issue capture, where a desynced tap made a real
        worker deposit classify unknown). Returns True/False once resolved,
        or None while the bytes have not been captured yet.
        """
        if pending.end_sequence is None:
            return None
        position = pending.end_sequence
        seen: set[int] = set()
        for _ in range(self.COMPANION_CHAIN_FRAMES):
            header = self._read_span(pending.flow, position, 5)
            if header is None:
                return None
            length = int.from_bytes(header[0:2], "little")
            if not 5 <= length <= MAX_TARGET_MESSAGE_LENGTH:
                # Chain does not parse as frames here: structurally resolved,
                # no companions follow this delta.
                return False
            opcode = int.from_bytes(header[3:5], "little")
            if opcode in WORKER_DEPOSIT_COMPANION_OPCODES:
                seen.add(opcode)
            if set(WORKER_DEPOSIT_COMPANION_OPCODES) <= seen:
                return True
            position += length
        return False

    def _has_matching_decrement(
        self,
        flow: FlowKey,
        stream_sequence: Optional[int],
        event: BDOEvent,
    ) -> bool:
        quantity_bytes = event.quantity.to_bytes(4, "little")
        item_bytes = event.item_id.to_bytes(4, "little")
        for frame in self._recent.get(flow, ()):
            if (
                stream_sequence is not None
                and frame.stream_sequence is not None
                and frame.stream_sequence >= stream_sequence
            ):
                continue
            spec = self._decrement_specs.get(frame.opcode)
            if spec is None:
                continue
            if spec.quantity_offset is not None:
                end = spec.quantity_offset + 4
                if end <= len(frame.message) and (
                    frame.message[spec.quantity_offset : end] == quantity_bytes
                ):
                    return True
            elif (
                quantity_bytes in frame.message
                and item_bytes not in frame.message
            ):
                return True
        return False

    # --- flushing ---

    def flush_stale(self, now: float) -> None:
        """Finalize deposits whose forward window went quiet (live capture)."""
        still = []
        for pending in self._pending:
            if now - pending.timestamp > self.STALE_SECONDS:
                self._finalize(pending)
            else:
                still.append(pending)
        self._pending = still

    def finalize_all(self) -> None:
        """End of capture: resolve everything still pending, in FIFO order."""
        pending, self._pending = self._pending, []
        for deposit in pending:
            self._finalize(deposit)

    def _finalize(self, pending: _PendingDeposit) -> None:
        if pending.companions_resolved is not None:
            companions = pending.companions_resolved
        else:
            companions = (
                set(WORKER_DEPOSIT_COMPANION_OPCODES) <= pending.companions_seen
            )
        # The two signals are NOT equal strength. The companion pair
        # (0x1558+0x1168) has perfect separation across every capture and is
        # semantically tied to worker/node mechanics. The decrement match is
        # a quantity-only test, which collides for small/common quantities:
        # a real worker batch record of qty=1 (bytes 01000000) spuriously
        # matches a source-stack-decrement in the window (observed 2026-07-08:
        # a 2-record worker batch where the qty=1 record read as
        # companions+decrement while its qty=25 sibling read cleanly worker).
        # So companions win outright; the decrement only speaks when no
        # companions are present. This replaces the earlier
        # companions+decrement => unknown rule, which that false positive
        # showed was penalizing genuine worker deposits.
        if companions:
            origin = ORIGIN_WORKER
        elif pending.matching_decrement:
            origin = ORIGIN_MANUAL
        else:
            origin = ORIGIN_UNKNOWN
        event = dataclasses.replace(
            pending.event,
            extra={
                **pending.event.extra,
                "deposit_origin": origin,
                "deposit_origin_evidence": {
                    "worker_companions": companions,
                    "matching_decrement": pending.matching_decrement,
                },
            },
        )
        self._emit(event)
