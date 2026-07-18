"""Public Arena of Solare leaderboard API.

This domain shares the toolkit's passive packet acquisition and TCP
reassembly, but intentionally does not emit :class:`bdo_toolkit.BDOEvent`.
Solare is a finite snapshot protocol with structured discovery progress, so it
uses its own result models and sessions.
"""

from .async_session import AsyncLiveSolareSession
from .models import (
    SolareCaptureEndpoint,
    SolareCaptureHealth,
    SolareCaptureResult,
    SolareClass,
    SolareClassPerformance,
    SolareDetectionStatus,
    SolareEvidence,
    SolareFamilyLayout,
    SolareLeaderboardSnapshot,
    SolarePlayer,
    SolareRawSection,
    SolareSpecialization,
    SolareUpdate,
    SolareUpdateKind,
)
from .replay import replay_solare
from .session import LiveSolareSession, capture_solare_snapshot

__all__ = [
    "AsyncLiveSolareSession",
    "LiveSolareSession",
    "SolareCaptureEndpoint",
    "SolareCaptureHealth",
    "SolareCaptureResult",
    "SolareClass",
    "SolareClassPerformance",
    "SolareDetectionStatus",
    "SolareEvidence",
    "SolareFamilyLayout",
    "SolareLeaderboardSnapshot",
    "SolarePlayer",
    "SolareRawSection",
    "SolareSpecialization",
    "SolareUpdate",
    "SolareUpdateKind",
    "capture_solare_snapshot",
    "replay_solare",
]
