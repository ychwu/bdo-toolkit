"""Private calibration workflow implementation."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Optional
from .._capture_options import PacketCaptureOptions
from .._protocol import DEFAULT_SERVER_PORTS
from ._constants import (
    DEFAULT_CALIBRATION_MAX_RETAINED_BYTES,
    DEFAULT_CALIBRATION_MAX_RETAINED_FRAMES,
)
from .capture import calibrate_live, calibrate_pcap
from .models import CalibrationResult, ProfileUpdate
from .persistence import update_profile
from .validation import _validate_profile_replacement_options


def calibrate_and_update(
    profile_path: str | Path,
    *,
    item_id: int,
    pcap: Optional[str | Path] = None,
    capture_seconds: Optional[float] = None,
    quantity: Optional[int] = None,
    action: str = "auto",
    capture_options: Optional[PacketCaptureOptions] = None,
    pcap_ports: Optional[tuple[int, ...]] = None,
    context_frames: int = 5,
    min_confidence: float = 0.80,
    max_retained_frames: int = DEFAULT_CALIBRATION_MAX_RETAINED_FRAMES,
    max_retained_bytes: int = DEFAULT_CALIBRATION_MAX_RETAINED_BYTES,
    replace: bool = True,
    replace_entire_action: bool = False,
    backup: bool = True,
) -> tuple[CalibrationResult, Optional[ProfileUpdate]]:
    """Calibrate and persist in one call — a facade over the two-step API.

    With ``pcap`` set the capture is replayed from disk; otherwise a live
    capture runs (``capture_seconds`` timer, or Ctrl+C to stop, exactly like
    :func:`calibrate_live`). ``pcap_ports`` applies only to the recording;
    ``capture_options`` applies only to live packet acquisition. If calibration
    promoted specs, they replace the applicable scope in ``profile_path`` by
    default and both objects come back; if it found nothing the profile file
    is left untouched and the update slot is ``None``::

        result, update = calibrate_and_update(
            "opcodes.local",
            item_id=15156,
            quantity=1,
        )
        print(result.summary())
        if update is not None:
            print(update.summary())

    Replacement is also the default on :func:`update_profile`: normal
    post-patch recalibration supersedes stale entries for the event families
    actually found. Pass ``replace_entire_action=True`` for an explicit reset
    of every family owned by ``action``. Pass ``replace=False`` only for an
    intentional reviewed merge, or use the two-step API when specs must be
    inspected or filtered before persistence.
    """
    _validate_profile_replacement_options(replace, replace_entire_action)
    if pcap is not None:
        for name, value in (
            ("capture_seconds", capture_seconds),
            ("capture_options", capture_options),
        ):
            if value is not None:
                raise ValueError(
                    f"{name} applies to live calibration only; omit it with pcap"
                )
        for name, value, default in (
            (
                "max_retained_frames",
                max_retained_frames,
                DEFAULT_CALIBRATION_MAX_RETAINED_FRAMES,
            ),
            (
                "max_retained_bytes",
                max_retained_bytes,
                DEFAULT_CALIBRATION_MAX_RETAINED_BYTES,
            ),
        ):
            if value != default:
                raise ValueError(
                    f"{name} applies to live calibration only; omit it with pcap"
                )
        result = calibrate_pcap(
            pcap,
            item_id=item_id,
            quantity=quantity,
            action=action,
            ports=DEFAULT_SERVER_PORTS if pcap_ports is None else pcap_ports,
            context_frames=context_frames,
            min_confidence=min_confidence,
        )
    else:
        if pcap_ports is not None:
            raise ValueError(
                "pcap_ports applies to offline calibration only; omit it "
                "without pcap"
            )
        result = calibrate_live(
            item_id=item_id,
            capture_seconds=capture_seconds,
            quantity=quantity,
            action=action,
            capture_options=capture_options,
            context_frames=context_frames,
            min_confidence=min_confidence,
            max_retained_frames=max_retained_frames,
            max_retained_bytes=max_retained_bytes,
        )

    if not result.specs:
        return result, None

    update = update_profile(
        result,
        profile_path,
        action=action,
        replace=replace,
        replace_entire_action=replace_entire_action,
        backup=backup,
    )
    return result, update
