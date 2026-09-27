"""Immutable solo XP observations; numeric readings do not establish identity."""
from dataclasses import asdict, dataclass
from typing import Literal

from ..events import Flow


SOLO_WARNING = ("Experimental solo XP tracking. Party/group play is unsupported and may produce "
                "incorrect XP readings. The tracker does not detect whether you are solo.")


class XPTrackingError(RuntimeError):
    """XP authority was lost; stop using current readings and session totals."""


@dataclass(frozen=True)
class XPReading:
    """Observed state and net change since the first packet, not session launch.

    First delta is None: the gain that produced the baseline is unknowable.
    Subsequent deltas include losses. Required XP is the whole-level threshold.
    """

    level: int
    current_xp: int
    required_xp: int
    delta_xp: int | None
    net_xp: int
    observed_at: float
    flow: Flow
    connection_epoch: int

    @property
    def percentage(self) -> float:
        return 100 * self.current_xp / self.required_xp

    def to_dict(self) -> dict[str, object]:
        return {**asdict(self), "schema_version": 1, "event_type": "xp_reading",
                "scope": "solo-unverified", "percentage": self.percentage}


@dataclass(frozen=True)
class XPStatus:
    """Latest authority; invalid readings and totals are unavailable."""

    status: Literal["waiting", "tracking", "invalid"]
    reading: XPReading | None
    reason: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {"status": self.status, "reading": self.reading.to_dict() if self.reading else None,
                "reason": self.reason, "scope": "solo-unverified"}


@dataclass(frozen=True)
class XPCaptureHealth:
    packets_processed: int = 0
    packets_accepted: int = 0
    packet_queue_overflows: int = 0
    event_queue_overflows: int = 0
    tcp_gap_resets: int = 0
    flow_state_evictions: int = 0
    pcap_received: int | None = None
    pcap_dropped: int | None = None
    pcap_interface_dropped: int | None = None
    capture_buffer_bytes: int | None = None
    cleanup_incomplete: bool = False

    @property
    def capture_is_clean(self) -> bool:
        """No known loss/cleanup failure; None native counters remain unknown."""
        return not (self.packet_queue_overflows or self.event_queue_overflows or self.tcp_gap_resets
                    or self.flow_state_evictions or self.pcap_dropped or self.pcap_interface_dropped
                    or self.cleanup_incomplete)

    def to_dict(self) -> dict[str, object]:
        return {**asdict(self), "capture_is_clean": self.capture_is_clean}
