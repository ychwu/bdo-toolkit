"""Public API for the passive bdo-toolkit."""

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
from .diagnostics import DecoderDiagnostic, DecoderHealth
from .filters import EventFilter
from .profiles import (
    OPCODE_PROFILE_SCHEMA_VERSION,
    OpcodeProfile,
    OriginCompanionFamily,
    ProfileError,
    load_opcode_profile,
)
from .remote_profiles import (
    DEFAULT_REMOTE_PROFILE_MAX_BYTES,
    DEFAULT_REMOTE_PROFILE_TIMEOUT_SECONDS,
    ProfileFetchResult,
    REMOTE_PROFILE_ENVELOPE_VERSION,
    RemoteProfileError,
    fetch_opcode_profile,
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
from ._version import __version__

__all__ = [
    "AsyncCalibrationSession",
    "AsyncLiveCaptureSession",
    "BDOEvent",
    "CaptureEndpoint",
    "CaptureIntegrityError",
    "ConsoleEventWriter",
    "DecoderDiagnostic",
    "DecoderHealth",
    "EventFilter",
    "Flow",
    "JsonlEventWriter",
    "LiveCaptureOptions",
    "LiveCaptureHealth",
    "LiveCaptureSession",
    "OPCODE_PROFILE_SCHEMA_VERSION",
    "PacketCaptureOptions",
    "OpcodeProfile",
    "OriginCompanionFamily",
    "CompanionObservation",
    "DEFAULT_ORIGIN_LEARNING_MAX_CANDIDATES",
    "DEFAULT_ORIGIN_LEARNING_MAX_OBSERVATIONS",
    "DEFAULT_REMOTE_PROFILE_MAX_BYTES",
    "DEFAULT_REMOTE_PROFILE_TIMEOUT_SECONDS",
    "OriginCompanionCandidate",
    "OriginLearner",
    "OriginLearningLimitError",
    "OriginPromotion",
    "ProfileError",
    "ProfileFetchResult",
    "REMOTE_PROFILE_ENVELOPE_VERSION",
    "RemoteProfileError",
    "StorageLocation",
    "__version__",
    "capture_live",
    "fetch_opcode_profile",
    "load_opcode_profile",
    "promote_origin_candidates",
    "replay_pcap",
    "storage_location",
    "solare",
]
