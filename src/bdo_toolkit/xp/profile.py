"""Explicit installation of reviewed XP geometry into a combined opcode profile."""
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import shutil

from .._profile_io import atomic_write_text, next_backup_path
from .._profile_runtime import validate_runtime_profile
from ..profiles import XPProfileLayout, ProfileError, _opcode_profile_from_data


@dataclass(frozen=True)
class XPProfileUpdate:
    path: Path
    written: bool
    backup_path: Path | None
    layout: XPProfileLayout


def update_xp_profile(layout: XPProfileLayout, path: str | Path, *,
                      expected_profile_sha256: str | None = None) -> XPProfileUpdate:
    """Merge explicitly reviewed geometry into an existing active profile.

    This is a maintainer action, NOT discovery or evidence verification. Pass
    the XP layout from a successfully calibrated/tested profile. Preserve all
    unrelated fields, validate the whole result, back up, then atomically save.
    Unchanged geometry is a no-op. Single writer only; optional digest protects
    against changes since the caller's calibration/review started.
    """
    if not isinstance(layout, XPProfileLayout):
        raise TypeError("layout must be a reviewed XPProfileLayout")
    layout.__post_init__()
    if expected_profile_sha256 is not None and (not isinstance(expected_profile_sha256, str)
            or len(expected_profile_sha256) != 64
            or any(c not in "0123456789abcdef" for c in expected_profile_sha256)):
        raise ValueError("expected_profile_sha256 must be a lowercase SHA256 digest")
    path = Path(path)
    original = path.read_bytes()
    if expected_profile_sha256 is not None and hashlib.sha256(original).hexdigest() != expected_profile_sha256:
        raise ProfileError("Profile changed during XP calibration/review; nothing written")
    data = json.loads(original.decode("utf-8-sig"))
    existing = _opcode_profile_from_data(data, path)
    validate_runtime_profile(existing)
    if existing.xp == layout:
        return XPProfileUpdate(path, False, None, layout)
    data["xp"] = layout.to_dict()
    validate_runtime_profile(_opcode_profile_from_data(data, path))
    if path.read_bytes() != original:
        raise ProfileError("Profile changed before XP save; nothing written")
    backup = next_backup_path(path)
    shutil.copy2(path, backup)
    atomic_write_text(path, json.dumps(data, indent=2, sort_keys=True) + "\n")
    return XPProfileUpdate(path, True, backup, layout)
