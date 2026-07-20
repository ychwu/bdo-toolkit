"""Public API for the passive BDO Toolkit."""

from importlib.metadata import PackageNotFoundError, version

from ._async_sessions import AsyncCalibrationSession, AsyncLiveCaptureSession
from ._capture_options import LiveCaptureOptions, PacketCaptureOptions
from ._capture_runtime import CaptureEndpoint
from .capture import (
    CaptureIntegrityError,
    LiveCaptureHealth,
    LiveCaptureSession,
    capture_live,
    replay_pcap,
)
from .events import BDOEvent, Flow
from .filters import EventFilter
from .profiles import (
    OpcodeProfile,
    OriginCompanionFamily,
    ProfileError,
    default_profile_path,
    load_opcode_profile,
)
from ._protocol import StorageLocation, storage_location
from .origin_learning import (
    CompanionObservation,
    DEFAULT_ORIGIN_LEARNING_MAX_CANDIDATES,
    DEFAULT_ORIGIN_LEARNING_MAX_OBSERVATIONS,
    OriginCompanionCandidate,
    OriginLearner,
    OriginLearningLimitError,
    OriginPromotion,
    promote_origin_candidates,
)
from .writers import ConsoleEventWriter, JsonlEventWriter
from . import solare

try:
    __version__ = version("bdo-toolkit")
except PackageNotFoundError:  # source tree without installed metadata
    __version__ = "0.1.0"

__all__ = [
    "AsyncCalibrationSession",
    "AsyncLiveCaptureSession",
    "BDOEvent",
    "CaptureEndpoint",
    "CaptureIntegrityError",
    "ConsoleEventWriter",
    "EventFilter",
    "Flow",
    "JsonlEventWriter",
    "LiveCaptureOptions",
    "LiveCaptureHealth",
    "LiveCaptureSession",
    "PacketCaptureOptions",
    "OpcodeProfile",
    "OriginCompanionFamily",
    "CompanionObservation",
    "DEFAULT_ORIGIN_LEARNING_MAX_CANDIDATES",
    "DEFAULT_ORIGIN_LEARNING_MAX_OBSERVATIONS",
    "OriginCompanionCandidate",
    "OriginLearner",
    "OriginLearningLimitError",
    "OriginPromotion",
    "ProfileError",
    "StorageLocation",
    "__version__",
    "capture_live",
    "default_profile_path",
    "load_opcode_profile",
    "promote_origin_candidates",
    "replay_pcap",
    "storage_location",
    "solare",
]
