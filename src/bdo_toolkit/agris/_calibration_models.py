"""Final Agris calibration evidence and explicit profile-write outcomes."""
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from ..profiles import AgrisProfileLayout
from ._capture import AgrisCaptureHealth
from ._validation import validate_expected_maximum_points
from .models import AgrisDetectionError, AgrisStatus


class AgrisCalibrationError(AgrisDetectionError):
    """No final, clean discovered layout is available for persistence."""


@dataclass(frozen=True)
class AgrisCalibrationResult:
    layout: AgrisProfileLayout
    expected_maximum_points: int
    observed_frames: int
    health: AgrisCaptureHealth
    completed_at: str

    def __post_init__(self) -> None:
        if not isinstance(self.layout, AgrisProfileLayout):
            raise TypeError("layout must be AgrisProfileLayout")
        self.layout.__post_init__()
        validate_expected_maximum_points(self.expected_maximum_points)
        if type(self.observed_frames) is not int or self.observed_frames < 3:
            raise AgrisCalibrationError("Calibration requires at least three observed frames")
        if not isinstance(self.health, AgrisCaptureHealth) or not self.health.capture_is_clean or self.health.cleanup_incomplete:
            raise AgrisCalibrationError("Calibration requires clean, completed capture")
        if not isinstance(self.completed_at, str):
            raise TypeError("completed_at must be an ISO timestamp")
        try:
            if datetime.fromisoformat(self.completed_at).tzinfo is None:
                raise ValueError
        except ValueError as exc:
            raise ValueError("completed_at must be a timezone-aware ISO timestamp") from exc

    def to_dict(self) -> dict[str, object]:
        return {"layout": self.layout.to_dict(), "expected_maximum_points": self.expected_maximum_points,
                "observed_frames": self.observed_frames, "health": self.health.to_dict(),
                "completed_at": self.completed_at}


@dataclass(frozen=True)
class AgrisProfileUpdate:
    path: Path
    written: bool
    backup_path: Path | None
    layout: AgrisProfileLayout

    def to_dict(self) -> dict[str, object]:
        return {"path": str(self.path), "written": self.written,
                "backup_path": str(self.backup_path) if self.backup_path else None,
                "layout": self.layout.to_dict()}


def final_calibration_result(status: AgrisStatus, health: AgrisCaptureHealth) -> AgrisCalibrationResult | None:
    if status.status != "tracking" or status.balance is None or len(status.candidates) != 1:
        return None
    if not health.capture_is_clean or health.cleanup_incomplete:
        return None
    candidate = status.candidates[0]
    layout = AgrisProfileLayout(opcode=candidate.opcode, message_length=candidate.message_length,
                               remaining_offset=candidate.remaining_offset, maximum_offset=candidate.maximum_offset,
                               observed_date=datetime.fromtimestamp(status.balance.observed_at, UTC).date().isoformat())
    return AgrisCalibrationResult(layout, status.expected_maximum_points, status.observed_frames,
                                  health, datetime.now(UTC).isoformat())
