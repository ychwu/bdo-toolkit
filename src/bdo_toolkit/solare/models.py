"""Immutable public models for Arena of Solare leaderboard snapshots."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable, Optional


class SolareDetectionStatus(str, Enum):
    """Final or best-known structural classification for one capture window."""

    COMPLETE = "complete"
    DETECTED_INCOMPLETE = "detected-incomplete"
    RICH_CANDIDATE = "rich-candidate"
    RANKED_PARTIAL = "ranked-partial"
    MENU_CONTEXT = "menu-context"
    INCONCLUSIVE = "inconclusive"
    NO_TRAFFIC = "no-traffic"


class SolareUpdateKind(str, Enum):
    """Structured live progress stages; display wording is intentionally separate."""

    CAPTURE_READY = "capture-ready"
    TRAFFIC = "traffic"
    MENU_CONTEXT = "menu-context"
    RANKED_PROGRESS = "ranked-progress"
    RICH_CANDIDATE = "rich-candidate"
    CROSS_CHECK = "cross-check"
    SNAPSHOT_CONFIRMED = "snapshot-confirmed"
    WARNING = "warning"
    FINISHED = "finished"


@dataclass(frozen=True)
class SolareClass:
    """Numeric BDO class code plus a best-effort display name."""

    code: int
    name: Optional[str]

    def to_dict(self) -> dict[str, object]:
        return {"code": self.code, "name": self.name}


@dataclass(frozen=True)
class SolareSpecialization:
    """Observed class-aware specialization code."""

    code: int
    branch: str
    name: Optional[str]

    def to_dict(self) -> dict[str, object]:
        return {"code": self.code, "branch": self.branch, "name": self.name}


@dataclass(frozen=True)
class SolareRawSection:
    """Opaque bytes retained at a record-relative offset.

    The Python API exposes literal ``bytes`` through :attr:`data`. JSON uses
    lowercase hexadecimal so round-tripping is deterministic and does not
    imply that the section's internal fields are understood.
    """

    offset: int
    data: bytes

    @property
    def length(self) -> int:
        return len(self.data)

    def to_dict(self) -> dict[str, object]:
        return {
            "offset": self.offset,
            "length": self.length,
            "encoding": "hex",
            "data": self.data.hex(),
        }


@dataclass(frozen=True)
class SolareClassPerformance:
    """One occupied class slot from a rich leaderboard record.

    Performance fields are optional because rank/name/class discovery can be
    structurally confirmed even when a patch changes the deeper record layout.
    Missing means unavailable, never zero.
    """

    slot: int
    primary: bool
    player_class: SolareClass
    specialization: Optional[SolareSpecialization] = None
    matches: Optional[int] = None
    wins: Optional[int] = None
    draws: Optional[int] = None
    losses: Optional[int] = None
    recent_results_raw: tuple[int, ...] = ()
    recent_results_wire_text: Optional[str] = None
    gear_loadout_raw: Optional[SolareRawSection] = None
    skill_addons_raw: Optional[SolareRawSection] = None

    @property
    def win_rate(self) -> Optional[float]:
        if self.matches is None or self.wins is None or self.matches <= 0:
            return None
        return round((self.wins / self.matches) * 100, 2)

    @property
    def record_is_balanced(self) -> Optional[bool]:
        values = (self.matches, self.wins, self.draws, self.losses)
        if any(value is None for value in values):
            return None
        assert self.matches is not None
        assert self.wins is not None
        assert self.draws is not None
        assert self.losses is not None
        return self.wins + self.draws + self.losses == self.matches

    def to_dict(self, *, include_raw: bool = False) -> dict[str, Any]:
        output: dict[str, Any] = {
            "slot": self.slot,
            "primary": self.primary,
            "class": self.player_class.to_dict(),
        }
        if self.specialization is not None:
            output["specialization"] = self.specialization.to_dict()
        for key in ("matches", "wins", "draws", "losses"):
            value = getattr(self, key)
            if value is not None:
                output[key] = value
        if self.win_rate is not None:
            output["win_rate"] = self.win_rate
        if self.recent_results_raw:
            output["recent_results_raw"] = list(self.recent_results_raw)
        if self.recent_results_wire_text is not None:
            output["recent_results_wire_text"] = self.recent_results_wire_text
        if include_raw:
            if self.gear_loadout_raw is not None:
                output["gear_loadout_raw"] = self.gear_loadout_raw.to_dict()
            if self.skill_addons_raw is not None:
                output["skill_addons_raw"] = self.skill_addons_raw.to_dict()
        return output


@dataclass(frozen=True)
class SolarePlayer:
    """One player carried by the rich Solare leaderboard table."""

    name: str
    global_rank: int
    primary_class: SolareClass
    player_uid_raw: Optional[bytes] = None
    elo: Optional[int] = None
    classes_played: tuple[SolareClassPerformance, ...] = ()

    @property
    def player_uid_bytes_le(self) -> Optional[str]:
        if self.player_uid_raw is None:
            return None
        return self.player_uid_raw.hex()

    @property
    def player_uid_value(self) -> Optional[str]:
        if self.player_uid_raw is None or len(self.player_uid_raw) != 8:
            return None
        return f"0x{int.from_bytes(self.player_uid_raw, 'little'):016x}"

    def to_dict(self, *, include_raw: bool = False) -> dict[str, Any]:
        output: dict[str, Any] = {
            "name": self.name,
            "global_rank": self.global_rank,
            "primary_class": self.primary_class.to_dict(),
            "classes_played": [
                item.to_dict(include_raw=include_raw)
                for item in self.classes_played
            ],
        }
        if self.player_uid_raw is not None:
            output["player_uid_raw"] = self.player_uid_value
            output["player_uid_bytes_le"] = self.player_uid_bytes_le
        if self.elo is not None:
            output["elo"] = self.elo
        return output


@dataclass(frozen=True)
class SolareFamilyLayout:
    """Discovered message geometry; opcode is diagnostic, not trusted input."""

    role: str
    opcode: int
    message_length: int
    message_count: int
    record_stride: int
    name_offset: int
    rank_offset: int
    class_offset: Optional[int] = None
    detail_layout_id: Optional[str] = None

    def to_dict(self) -> dict[str, object]:
        output: dict[str, object] = {
            "role": self.role,
            "opcode": f"0x{self.opcode:04X}",
            "message_length": self.message_length,
            "message_count": self.message_count,
            "record_stride": self.record_stride,
            "name_offset": self.name_offset,
            "rank_offset": self.rank_offset,
        }
        if self.class_offset is not None:
            output["class_offset"] = self.class_offset
        if self.detail_layout_id is not None:
            output["detail_layout_id"] = self.detail_layout_id
        return output


@dataclass(frozen=True)
class SolareCaptureEndpoint:
    """Resolved network-capture target used by a live Solare session."""

    interface: Optional[str]
    local_ip: Optional[str]
    bpf_filter: Optional[str]

    def to_dict(self) -> dict[str, Optional[str]]:
        return {
            "interface": self.interface,
            "local_ip": self.local_ip,
            "bpf_filter": self.bpf_filter,
        }


@dataclass(frozen=True)
class SolareCaptureHealth:
    """Capture-integrity diagnostics retained with every result."""

    payload_segments: int = 0
    payload_bytes: int = 0
    synchronized_messages: int = 0
    retained_large_messages: int = 0
    tcp_gap_resets: int = 0
    pcap_received: Optional[int] = None
    pcap_dropped: Optional[int] = None
    pcap_interface_dropped: Optional[int] = None
    capture_buffer_bytes: Optional[int] = None
    saved_packets: int = 0

    @property
    def capture_is_clean(self) -> bool:
        return (
            self.tcp_gap_resets == 0
            and (self.pcap_dropped in (None, 0))
            and (self.pcap_interface_dropped in (None, 0))
        )

    def to_dict(self) -> dict[str, object]:
        output: dict[str, object] = {
            "payload_segments": self.payload_segments,
            "payload_bytes": self.payload_bytes,
            "synchronized_messages": self.synchronized_messages,
            "retained_large_messages": self.retained_large_messages,
            "tcp_gap_resets": self.tcp_gap_resets,
            "saved_packets": self.saved_packets,
            "capture_is_clean": self.capture_is_clean,
        }
        optional = {
            "pcap_received": self.pcap_received,
            "pcap_dropped": self.pcap_dropped,
            "pcap_interface_dropped": self.pcap_interface_dropped,
            "capture_buffer_bytes": self.capture_buffer_bytes,
        }
        output.update({key: value for key, value in optional.items() if value is not None})
        return output


@dataclass(frozen=True)
class SolareEvidence:
    """Structural and capture evidence supporting a result."""

    scanned_messages: int = 0
    candidate_families: tuple[tuple[int, int, int], ...] = ()
    ranked_players: int = 0
    class_group_counts: tuple[tuple[int, int], ...] = ()
    overall_players: int = 0
    exact_cross_check: int = 0
    rich_layout: Optional[SolareFamilyLayout] = None
    overall_layout: Optional[SolareFamilyLayout] = None
    health: SolareCaptureHealth = SolareCaptureHealth()

    def to_dict(self) -> dict[str, Any]:
        output: dict[str, Any] = {
            "scanned_messages": self.scanned_messages,
            "candidate_families": [
                {
                    "opcode": f"0x{opcode:04X}",
                    "message_length": length,
                    "message_count": count,
                }
                for opcode, length, count in self.candidate_families
            ],
            "ranked_players": self.ranked_players,
            "class_group_counts": {
                str(code): count for code, count in self.class_group_counts
            },
            "overall_players": self.overall_players,
            "exact_cross_check": self.exact_cross_check,
            "capture_health": self.health.to_dict(),
        }
        if self.rich_layout is not None:
            output["rich_layout"] = self.rich_layout.to_dict()
        if self.overall_layout is not None:
            output["overall_layout"] = self.overall_layout.to_dict()
        return output


@dataclass(frozen=True)
class SolareLeaderboardSnapshot:
    """Atomic, structurally confirmed Arena of Solare leaderboard snapshot."""

    snapshot_id: str
    observed_at: float
    players: tuple[SolarePlayer, ...]
    evidence: SolareEvidence
    capabilities: frozenset[str] = frozenset({"rankings"})
    schema_version: int = 1

    @property
    def observed_at_iso(self) -> str:
        return (
            dt.datetime.fromtimestamp(self.observed_at, tz=dt.timezone.utc)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z")
        )

    @property
    def top_100(self) -> tuple[SolarePlayer, ...]:
        return tuple(sorted(self.players, key=lambda item: item.global_rank)[:100])

    def class_leaderboard(self, class_code: int) -> tuple[SolarePlayer, ...]:
        return tuple(
            player
            for player in sorted(self.players, key=lambda item: item.global_rank)
            if player.primary_class.code == class_code
        )

    def get_player(self, name: str) -> Optional[SolarePlayer]:
        return next((player for player in self.players if player.name == name), None)

    def to_dict(self, *, include_raw: bool = False) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "snapshot_id": self.snapshot_id,
            "observed_at": self.observed_at,
            "observed_at_iso": self.observed_at_iso,
            "capabilities": sorted(self.capabilities),
            "complete": True,
            "record_count": len(self.players),
            "players": [
                player.to_dict(include_raw=include_raw) for player in self.players
            ],
            "evidence": self.evidence.to_dict(),
        }

    def to_json(self, *, include_raw: bool = False, indent: Optional[int] = 2) -> str:
        return json.dumps(
            self.to_dict(include_raw=include_raw),
            ensure_ascii=False,
            indent=indent,
            sort_keys=True,
        )


@dataclass(frozen=True)
class SolareCaptureResult:
    """Final capture/replay outcome; only ``complete`` carries a snapshot."""

    status: SolareDetectionStatus
    evidence: SolareEvidence
    snapshot: Optional[SolareLeaderboardSnapshot] = None
    message: Optional[str] = None
    schema_version: int = 1

    def __post_init__(self) -> None:
        if self.status is SolareDetectionStatus.COMPLETE and self.snapshot is None:
            raise ValueError("a complete Solare result requires a snapshot")
        if self.status is not SolareDetectionStatus.COMPLETE and self.snapshot is not None:
            raise ValueError("only a complete Solare result may contain a snapshot")

    @property
    def complete(self) -> bool:
        return self.status is SolareDetectionStatus.COMPLETE

    def to_dict(self, *, include_raw: bool = False) -> dict[str, Any]:
        output: dict[str, Any] = {
            "schema_version": self.schema_version,
            "status": self.status.value,
            "complete": self.complete,
            "evidence": self.evidence.to_dict(),
        }
        if self.message is not None:
            output["message"] = self.message
        if self.snapshot is not None:
            output["snapshot"] = self.snapshot.to_dict(include_raw=include_raw)
        return output

    def to_json(self, *, include_raw: bool = False, indent: Optional[int] = 2) -> str:
        return json.dumps(
            self.to_dict(include_raw=include_raw),
            ensure_ascii=False,
            indent=indent,
            sort_keys=True,
        )


@dataclass(frozen=True)
class SolareUpdate:
    """One structured live-capture progress update."""

    kind: SolareUpdateKind
    message: str
    ranked_players: int = 0
    overall_players: int = 0
    exact_cross_check: int = 0
    result: Optional[SolareCaptureResult] = None

    def to_dict(self, *, include_raw: bool = False) -> dict[str, Any]:
        output: dict[str, Any] = {
            "kind": self.kind.value,
            "message": self.message,
            "ranked_players": self.ranked_players,
            "overall_players": self.overall_players,
            "exact_cross_check": self.exact_cross_check,
        }
        if self.result is not None:
            output["result"] = self.result.to_dict(include_raw=include_raw)
        return output


def solare_snapshot_id(players: Iterable[SolarePlayer]) -> str:
    """Return a deterministic semantic identifier, excluding opaque raw blobs."""

    rows = []
    for player in sorted(players, key=lambda item: (item.global_rank, item.name)):
        rows.append(
            {
                "name": player.name,
                "rank": player.global_rank,
                "class": player.primary_class.code,
                "uid": player.player_uid_bytes_le,
                "elo": player.elo,
                "classes": [
                    {
                        "slot": item.slot,
                        "class": item.player_class.code,
                        "spec": item.specialization.code if item.specialization else None,
                        "matches": item.matches,
                        "wins": item.wins,
                        "draws": item.draws,
                        "losses": item.losses,
                        "history": list(item.recent_results_raw),
                    }
                    for item in player.classes_played
                ],
            }
        )
    payload = json.dumps(rows, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()
