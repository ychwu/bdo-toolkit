"""Opcode profile calibration.

After a game patch shifts opcodes or byte offsets, developers can rebuild a
local opcode profile from a capture of a known in-game action:

    from bdo_toolkit.calibration import calibrate_pcap, update_profile

    result = calibrate_pcap(
        "unstackable_1_in_4_in_5_out.pcapng",
        item_id=15156,         # replace with the unstackable item used
        quantity=1,            # each serialized unstackable record has qty 1
        action="auto",
    )
    update_profile(result, "opcodes.json")

Then point the decoding APIs at the local profile:

    replay_pcap("session.pcapng", opcode_profile="opcodes.json")

Storage calibration requires two distinct validated record counts so a moving
wrapper flag cannot be mistaken for the authoritative count column. Capture,
for example, a deposit of one matching unstackable followed by a deposit of
four, then one withdrawal of all five in the same automatic session. The
single deposit also anchors manual-origin evidence, while the multi deposit and
withdrawal prove repeated geometry in both directions. The calibration
session only observes these user-performed actions: ``quantity=1`` remains the
expected value in every serialized record and is not changed to the action's
batch size. The calibration heuristics score every frame containing the watched
item ID and promote only structurally proven layouts.

The batch sizes are observed evidence, not API arguments or hard-coded values;
another valid sequence is deposit one, deposit six, then withdraw seven.
Repeating the same deposit count does not establish storage count authority.
``action="auto"`` covers transfer directions only. Loot preview requires a
separate ``action="loot-preview"`` capture; when its quantity is random, watch
the known item ID and leave ``quantity=None``.
"""

from pathlib import Path
from typing import Any, Literal, Optional
from .profiles import ProfileError
from ._calibration.models import (
    CalibrationAuthorityError,
    CalibrationResult,
    CalibrationRetention,
    DirectionEvidence,
    DirectionMismatchError,
    MessageSpec,
    ProfileUpdate,
)
from ._calibration.analysis import calibrate_frames, detect_transfer_family
from ._calibration.progress import CalibrationProgress
from ._calibration.capture import (
    CalibrationSession,
    calibrate_live,
    calibrate_pcap,
    collect_frames_pcap,
)
from ._calibration.persistence import reset_profile, update_profile
from ._calibration.workflow import calibrate_and_update
from ._calibration._constants import (
    CALIBRATION_ACTIONS,
    DEFAULT_CALIBRATION_MAX_RETAINED_BYTES,
    DEFAULT_CALIBRATION_MAX_RETAINED_FRAMES,
    OPCODE_PROFILE_EVENTS,
)

__all__ = [
    'CALIBRATION_ACTIONS',
    'DEFAULT_CALIBRATION_MAX_RETAINED_BYTES',
    'DEFAULT_CALIBRATION_MAX_RETAINED_FRAMES',
    'CalibrationAuthorityError',
    'CalibrationResult',
    'CalibrationRetention',
    'CalibrationSession',
    'CalibrationProgress',
    'DirectionEvidence',
    'DirectionMismatchError',
    'MessageSpec',
    'ProfileError',
    'ProfileUpdate',
    'calibrate_and_update',
    'calibrate_frames',
    'calibrate_live',
    'calibrate_pcap',
    'collect_frames_pcap',
    'detect_transfer_family',
    'reset_profile',
    'update_profile',
]

# Preserve public class annotations and pickle paths after extraction.
for _name in __all__:
    _object = globals()[_name]
    if getattr(_object, "__module__", "").startswith("bdo_toolkit._calibration."):
        _object.__module__ = __name__
del _name, _object
