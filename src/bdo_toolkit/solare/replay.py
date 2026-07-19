"""Public offline replay API for Arena of Solare leaderboard captures."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from bdo_toolkit._capture_backend import iter_pcap_file
from bdo_toolkit._protocol import DEFAULT_SERVER_PORTS

from ._live_tracker import LiveSolareDiscoveryTracker
from ._replay_capture import SolareFrameCollector
from ._result import build_solare_result
from ._validation import validate_retain_raw_extensions
from .models import SolareCaptureResult


def replay_solare(
    path: str | Path,
    *,
    ports: Iterable[int] = DEFAULT_SERVER_PORTS,
    retain_raw_extensions: bool = False,
) -> SolareCaptureResult:
    """Replay a pcap/pcapng file and discover one Solare leaderboard snapshot.

    Classification is based on the relationships among ranked, class-balanced,
    and overall tables.  Opcode values are retained only as diagnostic evidence
    and are never supplied as classifier inputs.
    """

    retain_raw_extensions = validate_retain_raw_extensions(
        retain_raw_extensions
    )
    tracker = LiveSolareDiscoveryTracker(lambda _update: None)
    collector = SolareFrameCollector(
        ports,
        on_frame=tracker.observe,
        retain_frames=False,
    )
    saved_packets = 0
    for _ in iter_pcap_file(Path(path), collector):
        saved_packets += 1
    collector.finish()
    tracker.refresh()
    frames = tracker.confirmed_frames or tracker.retained_frames
    return build_solare_result(
        frames,
        collector.health(
            saved_packets=saved_packets,
            retained_large_messages=tracker.observed_frame_count,
            candidate_messages_observed=tracker.observed_frame_count,
            candidate_frames_retained=tracker.retained_frame_count,
            candidate_bytes_retained=tracker.retained_bytes,
            peak_candidate_frames=tracker.peak_retained_frame_count,
            peak_candidate_bytes=tracker.peak_retained_bytes,
            candidate_frames_evicted=tracker.evicted_frame_count,
            candidate_bytes_evicted=tracker.evicted_bytes,
            candidate_history_rolled_over=tracker.history_rolled_over,
        ),
        retain_raw_extensions=retain_raw_extensions,
        _discovery=tracker.result,
    )
