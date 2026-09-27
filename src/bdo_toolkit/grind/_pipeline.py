"""One item engine/reassembly owner with optional profile-only frame readers."""
from collections.abc import Callable

from .._protocol import BDOFrame, FlowKey
from ..agris._discovery import AgrisTracker
from ..agris._profile import profile_layout as agris_layout
from ..agris.models import AgrisDetectionError
from ..capture import CaptureIntegrityError, _EventCollector
from ..filters import EventFilter
from ..profiles import OpcodeProfile, ProfileError
from ..xp._tracker import XPTracker, profile_layout as xp_layout
from ..xp.models import XPTrackingError
from .models import GrindEvent, GrindFeatureError, GrindStatus


class GrindPipeline:
    def __init__(self, *, profile: OpcodeProfile, track_xp: bool, track_agris: bool,
                 expected_maximum_points: int | None, ports: tuple[int, ...],
                 publish: Callable[[GrindEvent], None], live: bool = True) -> None:
        if not isinstance(profile, OpcodeProfile):
            raise TypeError("profile must be a loaded OpcodeProfile")
        if type(track_xp) is not bool or type(track_agris) is not bool:
            raise TypeError("track_xp and track_agris must be booleans")
        if track_agris and expected_maximum_points is None:
            raise ValueError("expected_maximum_points is required when track_agris=True")
        if not track_agris and expected_maximum_points is not None:
            raise ValueError("expected_maximum_points requires track_agris=True")
        self._publish = publish
        self._failed: set[str] = set()
        self._finishing = False
        # No tracker construction or discovery work for disabled features.
        self.xp = XPTracker(xp_layout(profile), publish) if track_xp else None
        self.agris = (AgrisTracker(expected_maximum_points=expected_maximum_points,
                        profile_layout=agris_layout(profile), on_balance=publish)
                      if track_agris and expected_maximum_points is not None else None)
        self.collector = _EventCollector(
            server_ports=ports, opcode_profile=profile,
            event_filter=EventFilter(event_types={"item_received"}, sources={"Mob Drop"}),
            on_event=publish,
            _unhinted_frame_observer=self._observe if track_xp or track_agris else None,
            _flow_close_observer=self._close_flow,
            _flow_reset_observer=self._gap,
            _max_pending_segments=2048, _max_pending_bytes=8 * 1024 * 1024,
            _defer_gap_timeouts=live,
        )
        if not any(spec.label == "INVENTORY_TRANSFER" and spec.source_context_offset is not None
                   for spec in self.collector.event_specs):
            raise ProfileError("GrindSession requires an inventory receipt layout with source context")
        self.engine = self.collector.engine

    def snapshot(self) -> GrindStatus:
        return GrindStatus("degraded" if self._failed else "ready",
                           self.xp.snapshot() if self.xp else None,
                           self.agris.snapshot() if self.agris else None)

    def _xp_call(self, action: Callable[[], None]) -> None:
        if "xp" not in self._failed:
            try:
                action()
            except XPTrackingError as exc:
                self._failed.add("xp")
                self._publish(GrindFeatureError("xp", str(exc)))

    def _agris_call(self, action: Callable[[], None]) -> None:
        if "agris" not in self._failed:
            try:
                action()
            except AgrisDetectionError as exc:
                self._failed.add("agris")
                self._publish(GrindFeatureError("agris", str(exc)))

    def _observe(self, frame: BDOFrame) -> None:
        xp, agris = self.xp, self.agris
        if xp is not None:
            self._xp_call(lambda: xp.observe(frame))
        if agris is not None:
            self._agris_call(lambda: agris.observe(frame))

    def _close_flow(self, flow: FlowKey) -> None:
        xp, agris = self.xp, self.agris
        if not self._finishing:
            if xp is not None:
                self._xp_call(lambda: xp.close_flow(flow))
            if agris is not None:
                self._agris_call(lambda: agris.close_flow(flow))

    @staticmethod
    def _gap(flow: FlowKey, generation: int, sequence: int) -> None:
        raise CaptureIntegrityError("Grind capture has a TCP gap; all enabled readings are incomplete")

    @property
    def server_ports(self) -> frozenset[int]:
        return self.engine.server_ports

    @property
    def tcp_gap_resets(self) -> int:
        return self.engine.tcp_gap_resets

    @property
    def evictions(self) -> int:
        return self.engine.flow_state_evictions

    def _check_loss(self) -> None:
        if self.evictions:
            raise CaptureIntegrityError("Grind capture flow limit reached; all enabled readings are incomplete")

    def process_tcp_segment(self, *, source_ip: str, source_port: int, destination_ip: str,
                            destination_port: int, sequence: int, payload: bytes, timestamp: float,
                            syn: bool = False, rst: bool = False, fin: bool = False) -> None:
        self.engine.process_tcp_segment(source_ip=source_ip, source_port=source_port,
            destination_ip=destination_ip, destination_port=destination_port, sequence=sequence,
            payload=payload, timestamp=timestamp, syn=syn, rst=rst, fin=fin)
        self._check_loss()

    def service_gaps(self, now: float) -> int:
        result = self.engine.service_gaps(now)
        self._check_loss()
        return result

    def finish(self) -> None:
        self._finishing = True
        try:
            self.engine.finish()
            self._check_loss()
            self.collector.finalize()
        finally:
            self._finishing = False
