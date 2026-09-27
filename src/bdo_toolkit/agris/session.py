"""Single-owner Agris acquisition on the shared observation lifecycle."""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from .._capture_backend import make_packet_handler, open_packet_writer
from .._capture_options import LiveCaptureOptions
from .._capture_runtime import LivePacketCapture
from .._observation_session import ObservationSession
from ..profiles import OpcodeProfile
from ._profile import profile_layout
from ._calibration_models import AgrisCalibrationResult, final_calibration_result
from ._capture import AgrisCaptureHealth, AgrisFlowManager
from ._discovery import AgrisTracker
from .models import AgrisBalance, AgrisDiscoveryOptions, AgrisStatus


class LiveAgrisSession(ObservationSession[AgrisBalance, AgrisStatus]):
    """Single-use, single-consumer Agris balance session; never writes profiles.

    Omit profile for cold discovery or supply one for strict decoding.
    """

    def __init__(self, *, expected_maximum_points: int,
                 live_options: LiveCaptureOptions | None = None,
                 discovery_options: AgrisDiscoveryOptions | None = None,
                 capture_seconds: float | None = None,
                 save_pcap: str | Path | None = None,
                 profile: OpcodeProfile | None = None) -> None:
        if live_options is not None and not isinstance(live_options, LiveCaptureOptions):
            raise TypeError("live_options must be LiveCaptureOptions or None")
        options = live_options or LiveCaptureOptions()
        layout = profile_layout(profile)
        self._detection_mode = "profile" if layout is not None else "discovery"
        self._calibration_result: AgrisCalibrationResult | None = None
        self._tracker = AgrisTracker(expected_maximum_points=expected_maximum_points,
                                    options=discovery_options, on_balance=self._publish, profile_layout=layout)
        manager = AgrisFlowManager(self._tracker, options.ports, live=True)
        self._agris_manager = manager
        super().__init__(label="Agris", snapshot=self._tracker.snapshot, manager=manager,
                         refresh=manager.refresh, live_options=options, capture_seconds=capture_seconds,
                         save_pcap=save_pcap, capture_factory=lambda **kw: LivePacketCapture(**kw),
                         handler_factory=lambda manager: make_packet_handler(manager),
                         writer_factory=lambda path: open_packet_writer(path))

    @property
    def detection_mode(self) -> str:
        return self._detection_mode

    @property
    def calibration_result(self) -> AgrisCalibrationResult | None:
        return self._calibration_result if self.stopped and self.error is None else None

    @property
    def status(self) -> AgrisStatus:
        with self._state_lock:
            status, error = self._status, self._error
        return replace(status, status="invalid", balance=None, reason=str(error)) if error else status

    @property
    def health(self) -> AgrisCaptureHealth:
        with self._state_lock:
            return AgrisCaptureHealth(
                packets_processed=self._processed, packets_accepted=self._accepted,
                packet_queue_overflows=self._packet_overflows, event_queue_overflows=self._event_overflows,
                tcp_gap_resets=self._manager.tcp_gap_resets, flow_state_evictions=self._agris_manager.evictions,
                pcap_received=self._stats.received, pcap_dropped=self._stats.dropped,
                pcap_interface_dropped=self._stats.interface_dropped,
                capture_buffer_bytes=self._stats.capture_buffer_bytes,
                cleanup_incomplete=self._cleanup_incomplete)

    def _on_clean_stop(self) -> None:
        if self._detection_mode == "discovery":
            self._calibration_result = final_calibration_result(self.status, self.health)
