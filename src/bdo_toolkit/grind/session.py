"""Profile-based grind observations on one passive capture pipeline."""
from pathlib import Path

from .._capture_backend import make_packet_handler, open_packet_writer
from .._capture_options import LiveCaptureOptions
from .._capture_runtime import LivePacketCapture
from .._observation_session import ObservationSession
from ..profiles import OpcodeProfile
from ._pipeline import GrindPipeline
from .models import GrindCaptureHealth, GrindEvent, GrindStatus


class GrindSession(ObservationSession[GrindEvent, GrindStatus]):
    """Confirmed mob receipts plus optional profile-based Agris and solo XP.

    One capture, TCP reassembly owner and bounded event stream. Disabled readers
    are not constructed. No discovery, implicit fetch, writes, kill attribution,
    or automatic character switching. Existing standalone sessions are separate;
    do not start them alongside this session for the same features.
    """

    def __init__(self, *, profile: OpcodeProfile, track_xp: bool = False,
                 track_agris: bool = False, expected_maximum_points: int | None = None,
                 live_options: LiveCaptureOptions | None = None,
                 capture_seconds: float | None = None, save_pcap: str | Path | None = None) -> None:
        if live_options is not None and not isinstance(live_options, LiveCaptureOptions):
            raise TypeError("live_options must be LiveCaptureOptions or None")
        options = live_options or LiveCaptureOptions()
        pipeline = GrindPipeline(profile=profile, track_xp=track_xp, track_agris=track_agris,
            expected_maximum_points=expected_maximum_points, ports=options.ports, publish=self._publish)
        self._pipeline = pipeline
        super().__init__(label="Grind", snapshot=pipeline.snapshot, manager=pipeline,
            refresh=lambda now: None, live_options=options, capture_seconds=capture_seconds,
            save_pcap=save_pcap, capture_factory=lambda **kw: LivePacketCapture(**kw),
            handler_factory=lambda manager: make_packet_handler(manager),
            writer_factory=lambda path: open_packet_writer(path))

    @property
    def status(self) -> GrindStatus:
        with self._state_lock:
            status, error = self._status, self._error
        return status.invalidated(str(error)) if error is not None else status

    @property
    def health(self) -> GrindCaptureHealth:
        with self._state_lock:
            return GrindCaptureHealth(
                packets_processed=self._processed, packets_accepted=self._accepted,
                packet_queue_overflows=self._packet_overflows, event_queue_overflows=self._event_overflows,
                tcp_gap_resets=self._pipeline.tcp_gap_resets, flow_state_evictions=self._pipeline.evictions,
                pcap_received=self._stats.received, pcap_dropped=self._stats.dropped,
                pcap_interface_dropped=self._stats.interface_dropped,
                capture_buffer_bytes=self._stats.capture_buffer_bytes,
                cleanup_incomplete=self._cleanup_incomplete)
