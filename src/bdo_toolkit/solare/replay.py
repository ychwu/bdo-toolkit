"""Public offline replay API for Arena of Solare leaderboard captures."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from bdo_toolkit._capture_backend import iter_pcap_file
from bdo_toolkit._protocol import DEFAULT_SERVER_PORTS

from ._replay_capture import SolareFrameCollector
from ._result import build_solare_result
from .models import SolareCaptureResult


def replay_solare(
    path: str | Path,
    *,
    ports: Iterable[int] = DEFAULT_SERVER_PORTS,
) -> SolareCaptureResult:
    """Replay a pcap/pcapng file and discover one Solare leaderboard snapshot.

    Classification is based on the relationships among ranked, class-balanced,
    and overall tables.  Opcode values are retained only as diagnostic evidence
    and are never supplied as classifier inputs.
    """

    collector = SolareFrameCollector(ports)
    saved_packets = 0
    for _ in iter_pcap_file(Path(path), collector):
        saved_packets += 1
    collector.finish()
    return build_solare_result(
        collector.frames,
        collector.health(saved_packets=saved_packets),
    )
