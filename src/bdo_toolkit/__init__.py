"""Public API for the passive BDO Toolkit."""

from importlib.metadata import PackageNotFoundError, version

from .capture import capture_live, replay_pcap
from .events import BDOEvent, Flow
from .filters import EventFilter
from .profiles import (
    OpcodeProfile,
    OriginCompanionFamily,
    ProfileError,
    default_profile_path,
    load_opcode_profile,
)
from .origin_learning import (
    CompanionObservation,
    OriginCompanionCandidate,
    OriginLearner,
    OriginPromotion,
    promote_origin_candidates,
)
from .writers import ConsoleEventWriter, JsonlEventWriter

try:
    __version__ = version("bdo-toolkit")
except PackageNotFoundError:  # source tree without installed metadata
    __version__ = "0.1.0"

__all__ = [
    "BDOEvent",
    "ConsoleEventWriter",
    "EventFilter",
    "Flow",
    "JsonlEventWriter",
    "OpcodeProfile",
    "OriginCompanionFamily",
    "CompanionObservation",
    "OriginCompanionCandidate",
    "OriginLearner",
    "OriginPromotion",
    "ProfileError",
    "__version__",
    "capture_live",
    "default_profile_path",
    "load_opcode_profile",
    "promote_origin_candidates",
    "replay_pcap",
]

