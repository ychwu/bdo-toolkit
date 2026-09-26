"""Explicit Agris profile preflight; never fetch or fall back silently."""
from ..profiles import AgrisProfileLayout, OpcodeProfile, OPCODE_PROFILE_SCHEMA_VERSION, ProfileError


def profile_layout(profile: OpcodeProfile | None) -> AgrisProfileLayout | None:
    if profile is None:
        return None
    if not isinstance(profile, OpcodeProfile):
        raise TypeError("profile must be a loaded OpcodeProfile or None")
    if type(profile.version) is not int or profile.version != OPCODE_PROFILE_SCHEMA_VERSION:
        raise ProfileError("Unsupported Agris profile version")
    if profile.active is not True:
        raise ProfileError("Agris profile is inactive")
    if not isinstance(profile.agris, AgrisProfileLayout):
        raise ProfileError("Opcode profile has no Agris layout; calibrate Agris first")
    profile.agris.__post_init__()
    return profile.agris
