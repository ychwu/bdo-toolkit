"""Experimental solo XP telemetry from explicit maintainer-calibrated profiles.

Party/group play is unsupported. No automatic identity or character switching.
"""
from ..profiles import XPProfileLayout
from .models import SOLO_WARNING, XPCaptureHealth, XPReading, XPStatus, XPTrackingError
from .profile import XPProfileUpdate, update_xp_profile
from .replay import XPReplay, replay_xp
from .session import LiveXPSession

__all__ = ["LiveXPSession", "SOLO_WARNING", "XPCaptureHealth", "XPReading", "XPStatus",
           "XPTrackingError", "XPProfileLayout", "XPProfileUpdate", "update_xp_profile",
           "XPReplay", "replay_xp"]
