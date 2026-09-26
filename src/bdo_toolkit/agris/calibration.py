"""Explicit cold calibration and isolated Agris profile updates.

Live sessions never write profiles. Callers can drive a discovery session in
their own UI, stop it, and pass its final calibration_result to the writer.
"""
from __future__ import annotations

from collections.abc import Callable
import hashlib
import json
from pathlib import Path
import shutil

from .._capture_options import LiveCaptureOptions
from .._profile_io import atomic_write_text, next_backup_path
from .._profile_runtime import validate_runtime_profile
from ..profiles import _opcode_profile_from_data, load_opcode_profile, ProfileError
from ._calibration_models import AgrisCalibrationError, AgrisCalibrationResult, AgrisProfileUpdate
from .models import AgrisDiscoveryOptions, AgrisStatus
from .session import LiveAgrisSession


def calibrate_agris_live(*, expected_maximum_points: int,
                         live_options: LiveCaptureOptions | None = None,
                         discovery_options: AgrisDiscoveryOptions | None = None,
                         capture_seconds: float | None = None,
                         save_pcap: str | Path | None = None,
                         on_update: Callable[[AgrisStatus], None] | None = None) -> AgrisCalibrationResult:
    """Discover, stop, finalize and return clean evidence; never write a file.

    Runs until unique discovery qualifies or the optional capture deadline.
    Callback execution is on the calling thread, not the packet callback.
    For cancellable UI ownership use LiveAgrisSession or AsyncLiveAgrisSession
    without a profile, then read calibration_result after a successful stop.
    """
    if on_update is not None and not callable(on_update):
        raise TypeError("on_update must be callable or None")
    session = LiveAgrisSession(expected_maximum_points=expected_maximum_points,
                               live_options=live_options, discovery_options=discovery_options,
                               capture_seconds=capture_seconds, save_pcap=save_pcap)
    previous = None
    with session:
        while True:
            session.poll(timeout=0.1)
            status = session.status
            if on_update is not None and status != previous:
                on_update(status)
                previous = status
            if status.status == "tracking" or session.stopped:
                break
    if on_update is not None:
        on_update(session.status)
    result = session.calibration_result
    if result is None:
        raise AgrisCalibrationError("No final clean, unique Agris layout; no profile was written")
    return result


def update_agris_profile(result: AgrisCalibrationResult, path: str | Path, *,
                         backup: bool = True,
                         expected_profile_sha256: str | None = None) -> AgrisProfileUpdate:
    """Update only Agris in an existing active profile, with backup and atomic replace.

    Unchanged geometry (including provenance) is a no-op. Refuse invalid evidence,
    invalid existing/proposed profiles or a supplied digest mismatch. This is a
    single-writer operation, not a concurrent-writer merge or patch verifier.
    """
    if not isinstance(result, AgrisCalibrationResult):
        raise TypeError("result must be a final AgrisCalibrationResult")
    result.__post_init__()
    if not isinstance(backup, bool):
        raise TypeError("backup must be bool")
    if expected_profile_sha256 is not None and (
        not isinstance(expected_profile_sha256, str) or len(expected_profile_sha256) != 64
        or any(c not in "0123456789abcdef" for c in expected_profile_sha256)
    ):
        raise ValueError("expected_profile_sha256 must be a lowercase SHA256 hex digest")
    profile_path = Path(path)
    original = profile_path.read_bytes()
    digest = hashlib.sha256(original).hexdigest()
    if expected_profile_sha256 is not None and digest != expected_profile_sha256:
        raise ProfileError("Profile changed during Agris calibration; no profile was written")
    data = json.loads(original.decode("utf-8-sig"))
    existing = _opcode_profile_from_data(data, profile_path)
    validate_runtime_profile(existing)
    if existing.agris == result.layout:
        return AgrisProfileUpdate(profile_path, False, None, result.layout)
    data["agris"] = result.layout.to_dict()
    # Preserve item metadata and unknown top-level extension fields exactly in value.
    validate_runtime_profile(_opcode_profile_from_data(data, profile_path))
    if profile_path.read_bytes() != original:
        raise ProfileError("Profile changed before Agris save; no profile was written")
    backup_path = next_backup_path(profile_path) if backup else None
    if backup_path is not None:
        shutil.copy2(profile_path, backup_path)
    atomic_write_text(profile_path, json.dumps(data, indent=2, sort_keys=True) + "\n")
    return AgrisProfileUpdate(profile_path, True, backup_path, result.layout)


def calibrate_agris_and_update(path: str | Path, *, expected_maximum_points: int,
                               live_options: LiveCaptureOptions | None = None,
                               discovery_options: AgrisDiscoveryOptions | None = None,
                               capture_seconds: float | None = None,
                               save_pcap: str | Path | None = None,
                               on_update: Callable[[AgrisStatus], None] | None = None,
                               backup: bool = True) -> AgrisProfileUpdate:
    """Explicit automatic calibration/save workflow; never reuse existing Agris geometry."""
    if not isinstance(backup, bool):
        raise TypeError("backup must be bool")
    profile_path = Path(path)
    digest = hashlib.sha256(profile_path.read_bytes()).hexdigest()
    validate_runtime_profile(load_opcode_profile(profile_path))
    result = calibrate_agris_live(expected_maximum_points=expected_maximum_points,
                                  live_options=live_options, discovery_options=discovery_options,
                                  capture_seconds=capture_seconds, save_pcap=save_pcap, on_update=on_update)
    return update_agris_profile(result, profile_path, backup=backup, expected_profile_sha256=digest)
