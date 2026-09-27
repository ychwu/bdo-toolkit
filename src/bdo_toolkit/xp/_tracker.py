"""One numeric decoder/accounting owner for solo live capture and replay."""
import math
from collections.abc import Callable, Iterable
from typing import NoReturn

from .._capture_backend import validate_server_ports
from .._framing import FrameCollectorScanner
from .._profile_runtime import validate_runtime_profile
from .._protocol import BDOFrame, FlowKey
from .._reassembly import FlowManager
from ..events import Flow
from ..profiles import OpcodeProfile, ProfileError, XPProfileLayout
from .models import XPReading, XPStatus, XPTrackingError


def profile_layout(profile: OpcodeProfile) -> XPProfileLayout:
    if not isinstance(profile, OpcodeProfile):
        raise TypeError("profile must be a loaded OpcodeProfile")
    validate_runtime_profile(profile)
    if profile.xp is None:
        raise ProfileError("Profile has no solo XP layout; fetch a current calibrated profile")
    return profile.xp


class XPTracker:
    def __init__(self, layout: XPProfileLayout, on_reading: Callable[[XPReading], None]):
        self.layout = layout
        self._publish = on_reading
        self.reading: XPReading | None = None
        self._bound: tuple[FlowKey, int] | None = None
        self.reason: str | None = None

    def snapshot(self) -> XPStatus:
        return XPStatus("invalid" if self.reason else "tracking" if self.reading else "waiting",
                        self.reading, self.reason)

    def invalidate(self, reason: str) -> NoReturn:
        self.reason = self.reason or reason
        self.reading = None
        raise XPTrackingError(self.reason)

    def observe(self, frame: BDOFrame) -> None:
        if self.reason:
            raise XPTrackingError(self.reason)
        layout = self.layout
        if frame.opcode != layout.opcode:
            return
        if (frame.flag != layout.flag or frame.length != layout.message_length
                or len(frame.message) != layout.message_length):
            self.invalidate("XP message shape changed; fetch/recalibrate this patch's profile")
        level = frame.message[layout.level_offset]
        current = int.from_bytes(frame.message[layout.current_offset:layout.current_offset + 8], "little")
        required = int.from_bytes(frame.message[layout.required_offset:layout.required_offset + 8], "little")
        if not 1 <= level <= 75 or required == 0 or current >= required or not math.isfinite(frame.context.timestamp):
            self.invalidate("XP fields failed validation; review the profile")
        connection = (frame.context.flow, frame.context.flow_generation)
        if self._bound is not None and self._bound != connection:
            self.invalidate("XP connection/epoch changed; restart after reconnect or character switch")
        self._bound = connection
        old = self.reading
        delta: int | None = None
        net = 0
        if old is not None:
            if level == old.level and required == old.required_xp:
                delta = current - old.current_xp
            elif level == old.level + 1:
                delta = old.required_xp - old.current_xp + current
            else:
                self.invalidate("Unexplained XP level/requirement change; restart tracking")
            net = old.net_xp + delta
        flow = frame.context.flow
        self.reading = XPReading(level, current, required, delta, net, frame.context.timestamp,
                                 Flow(flow.source_ip, flow.source_port, flow.destination_ip, flow.destination_port),
                                 frame.context.flow_generation)
        # Duplicates refresh last-seen status but do not consume the event queue.
        if old is None or (old.level, old.current_xp, old.required_xp) != (level, current, required):
            self._publish(self.reading)

    def close_flow(self, flow: FlowKey) -> None:
        if self._bound is not None and self._bound[0] == flow:
            self.invalidate("XP connection closed; restart after reconnect or character switch")


class XPFlowManager(FlowManager):
    def __init__(self, tracker: XPTracker, ports: Iterable[int], *, live: bool = False):
        self.tracker = tracker
        self.finishing = False
        self.evictions = 0
        super().__init__(server_ports=validate_server_ports(ports),
                         scanner_factory=lambda: FrameCollectorScanner(tracker.observe),
                         track_flow_generations=True, max_flows=64, max_pending_segments=2048,
                         max_pending_bytes=8 * 1024 * 1024, defer_gap_timeouts=live,
                         on_flow_reset=lambda *args: tracker.invalidate("TCP gap detected; XP total is incomplete"),
                         on_flow_close=self._closed, on_flow_eviction=self._evicted)

    def _closed(self, flow: FlowKey) -> None:
        if not self.finishing:
            self.tracker.close_flow(flow)

    def _evicted(self) -> None:
        self.evictions += 1
        self.tracker.invalidate("Capture flow limit reached; XP total is incomplete")

    def finish(self) -> None:
        self.finishing = True
        try:
            super().finish()
        finally:
            self.finishing = False
