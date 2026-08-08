"""Arena of Solare protocol constants that are not opcode authorities."""

from __future__ import annotations

from typing import Optional


BDO_HEADER_SIZE = 5
BDO_MAX_FRAME_SIZE = 0xFFFF

EMPTY_CLASS_CODE = 101
EMPTY_SPEC_CODE = 3

DISCOVERY_MIN_FRAME_LENGTH = 8 * 1024
DISCOVERY_MAX_FRAME_LENGTH = 32 * 1024
DISCOVERY_MIN_FAMILY_FRAMES = 10
DISCOVERY_MIN_RICH_RECORDS = 20 * 20
DISCOVERY_MIN_PARTIAL_OVERALL_RECORDS = 20
DISCOVERY_MAX_CLASS_GROUPS = 64
DISCOVERY_NAME_PAIR_TOLERANCE = 512
DISCOVERY_FIELD_SCAN_LIMIT = 512
DISCOVERY_MAX_FAMILY_DISTANCE = 1024 * 1024
DISCOVERY_SYNC_HEADERS = 3
DISCOVERY_SYNC_BUFFER_LIMIT = (BDO_MAX_FRAME_SIZE * 2) + BDO_HEADER_SIZE
LIVE_CAPTURE_BUFFER_BYTES = 64 * 1024 * 1024
SOLARE_DEFAULT_CAPTURE_SECONDS = 120.0
# An exact trailing 50-frame family remains provisional while another Solare-
# sized frame could still extend it into a rich-table prefix. Ordinary small
# game traffic must not keep that candidate boundary open indefinitely.
LIVE_CANDIDATE_IDLE_SECONDS = 1.5
DISCOVERY_RETENTION_MAX_FRAMES = 768
DISCOVERY_RETENTION_MAX_BYTES = 16 * 1024 * 1024
LIVE_PACKET_QUEUE_MAX = 4096
LIVE_UPDATE_QUEUE_MAX = 64
SOLARE_MAX_ACTIVE_FLOWS = 64
# Windows/Npcap can deliver one lossless receive burst hundreds of TCP
# callbacks out of sequence. Solare permits a larger per-flow reorder count
# than the generic item route, while an explicit byte ceiling preserves the
# existing bounded-memory posture.
SOLARE_MAX_PENDING_SEGMENTS = 2048
SOLARE_MAX_PENDING_BYTES = 8 * 1024 * 1024

PLAYER_NAME_BYTES = frozenset(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
)

CLASS_NAMES: dict[int, str] = {
    0: "Warrior",
    1: "Hashashin",
    2: "Sage",
    3: "Wukong",
    4: "Ranger",
    5: "Guardian",
    6: "Scholar",
    7: "Drakania",
    8: "Sorceress",
    9: "Nova",
    10: "Corsair",
    11: "Lahn",
    12: "Berserker",
    15: "Maegu",
    16: "Tamer",
    17: "Shai",
    19: "Striker",
    20: "Musa",
    21: "Maehwa",
    23: "Mystic",
    24: "Valkyrie",
    25: "Kunoichi",
    26: "Ninja",
    27: "Dark Knight",
    28: "Wizard",
    29: "Archer",
    30: "Woosa",
    31: "Witch",
    32: "Seraph",
    33: "Dosa",
    34: "Deadeye",
}

ADVANCED_SPEC_BY_CLASS: dict[int, str] = {
    3: "Ascension",
    6: "Ascension",
    17: "Talent",
    29: "Ascension",
    32: "Ascension",
    34: "Ascension",
}


def class_name(code: int) -> Optional[str]:
    if code == EMPTY_CLASS_CODE:
        return None
    return CLASS_NAMES.get(code)
