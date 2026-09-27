"""Public single-use solo XP capture with explicit profile authority."""
from dataclasses import replace
from pathlib import Path

from .._capture_backend import make_packet_handler, open_packet_writer
from .._capture_options import LiveCaptureOptions
from .._capture_runtime import LivePacketCapture
from .._observation_session import ObservationSession
from ..profiles import OpcodeProfile
from ._tracker import XPFlowManager, XPTracker, profile_layout
from .models import XPCaptureHealth, XPReading, XPStatus


class LiveXPSession(ObservationSession[XPReading, XPStatus]):
    """Solo-only XP readings from a maintainer-calibrated profile.

    No calibration, implicit fetching, profile writes or player identification.
    Stop before switching characters or entering a party. First reading is the
    baseline (delta None/net zero); no earlier XP gain is inferred. One worker
    owns deadlines even when the app pauses polling. Queue loss fails closed.
    """

    def __init__(self, *, profile: OpcodeProfile,
                 live_options: LiveCaptureOptions | None = None,
                 capture_seconds: float | None = None,
                 save_pcap: str | Path | None = None) -> None:
        layout = profile_layout(profile)
        if live_options is not None and not isinstance(live_options, LiveCaptureOptions):
            raise TypeError("live_options must be LiveCaptureOptions or None")
        options = live_options or LiveCaptureOptions()
        self._tracker = XPTracker(layout, self._publish)
        manager = XPFlowManager(self._tracker, options.ports, live=True)
        self._xp_manager = manager
        super().__init__(label="XP", snapshot=self._tracker.snapshot, manager=manager,
                         refresh=lambda now: None, live_options=options, capture_seconds=capture_seconds,
                         save_pcap=save_pcap, capture_factory=lambda **kw: LivePacketCapture(**kw),
                         handler_factory=lambda manager: make_packet_handler(manager),
                         writer_factory=lambda path: open_packet_writer(path))

    @property
    def status(self) -> XPStatus:
        with self._state_lock:
            status, error = self._status, self._error
        return replace(status, status="invalid", reading=None, reason=str(error)) if error else status

    @property
    def health(self) -> XPCaptureHealth:
        with self._state_lock:
            return XPCaptureHealth(
                packets_processed=self._processed, packets_accepted=self._accepted,
                packet_queue_overflows=self._packet_overflows, event_queue_overflows=self._event_overflows,
                tcp_gap_resets=self._manager.tcp_gap_resets, flow_state_evictions=self._xp_manager.evictions,
                pcap_received=self._stats.received, pcap_dropped=self._stats.dropped,
                pcap_interface_dropped=self._stats.interface_dropped,
                capture_buffer_bytes=self._stats.capture_buffer_bytes,
                cleanup_incomplete=self._cleanup_incomplete)
