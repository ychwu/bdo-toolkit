"""Combined observations, not inferred kills or per-kill attribution."""
from dataclasses import asdict, dataclass, replace
from typing import Literal

from ..agris.models import AgrisBalance, AgrisStatus
from ..events import BDOEvent
from ..xp.models import XPReading, XPStatus


@dataclass(frozen=True)
class GrindFeatureError:
    """One optional reader stopped; other readers may continue."""

    feature: Literal["xp", "agris"]
    reason: str

    def to_dict(self) -> dict[str, object]:
        return {"schema_version": 1, "event_type": "grind_feature_error", **asdict(self)}


type GrindEvent = BDOEvent | XPReading | AgrisBalance | GrindFeatureError


@dataclass(frozen=True)
class GrindStatus:
    """None means disabled. Waiting/searching means enabled, not yet observed.

    ready means the pipeline has no known failure, not proof of mob-drop activity
    or a valid profile for today's patch. Degraded retains unaffected readers.
    """

    status: Literal["ready", "degraded", "invalid"]
    xp: XPStatus | None
    agris: AgrisStatus | None
    reason: str | None = None

    def invalidated(self, reason: str) -> "GrindStatus":
        return GrindStatus("invalid",
            replace(self.xp, status="invalid", reading=None, reason=reason) if self.xp else None,
            replace(self.agris, status="invalid", balance=None, reason=reason) if self.agris else None,
            reason)

    def to_dict(self) -> dict[str, object]:
        return {"status": self.status, "reason": self.reason,
                "xp": self.xp.to_dict() if self.xp else None,
                "agris": self.agris.to_dict() if self.agris else None}


@dataclass(frozen=True)
class GrindCaptureHealth:
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
        """No known loss/cleanup failure, not a certificate of decoder validity."""
        return not (self.packet_queue_overflows or self.event_queue_overflows or self.tcp_gap_resets
                    or self.flow_state_evictions or self.pcap_dropped or self.pcap_interface_dropped
                    or self.cleanup_incomplete)

    def to_dict(self) -> dict[str, object]:
        return {**asdict(self), "capture_is_clean": self.capture_is_clean}
