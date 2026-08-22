"""Immutable public models for Arena of Solare leaderboard snapshots."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, ClassVar, Iterable, Optional

_SOLARE_SCHEMA_VERSION = 2


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
    """One occupied class slot from a validated Solare player record.

    Performance fields are optional because rank/name/class discovery can be
    structurally confirmed even when a patch changes the deeper record layout.
    Missing means unavailable, never zero.  The containing ``SolarePlayer`` or
    ``SolareOverallEntry`` establishes whether the slot came from the class or
    overall leaderboard response.
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
    elo: Optional[int] = field(default=None, kw_only=True)
    classes_played: tuple[SolareClassPerformance, ...] = field(
        default=(),
        kw_only=True,
    )

    def to_dict(self, *, include_raw: bool = False) -> dict[str, Any]:
        output: dict[str, Any] = {
            "name": self.name,
            "global_rank": self.global_rank,
            "primary_class": self.primary_class.to_dict(),
            "classes_played": [
                item.to_dict(include_raw=include_raw) for item in self.classes_played
            ],
        }
        if self.elo is not None:
            output["elo"] = self.elo
        return output


@dataclass(frozen=True)
class SolareOverallEntry:
    """One independently decoded row from the overall top-100 table.

    Aggregate wins, draws, and losses are independently decoded overall-record
    values. ``total_matches`` is their arithmetic sum, not a separately
    decoded wire field.
    """

    name: str
    global_rank: int
    elo: Optional[int] = field(default=None, kw_only=True)
    classes_played: tuple[SolareClassPerformance, ...] = field(
        default=(),
        kw_only=True,
    )
    total_wins: Optional[int] = field(default=None, kw_only=True)
    total_draws: Optional[int] = field(default=None, kw_only=True)
    total_losses: Optional[int] = field(default=None, kw_only=True)

    @property
    def total_matches(self) -> Optional[int]:
        """Return aggregate W+D+L when the complete overall tuple is available."""

        values = (self.total_wins, self.total_draws, self.total_losses)
        if any(value is None for value in values):
            return None
        assert self.total_wins is not None
        assert self.total_draws is not None
        assert self.total_losses is not None
        return self.total_wins + self.total_draws + self.total_losses

    @property
    def total_win_rate(self) -> Optional[float]:
        """Return the aggregate win percentage when total matches is positive."""

        matches = self.total_matches
        if matches is None or matches <= 0:
            return None
        assert self.total_wins is not None
        return round((self.total_wins / matches) * 100, 2)

    @property
    def primary_class(self) -> Optional[SolareClass]:
        """Return the class from the row's validated primary class slot."""

        performance = next(
            (item for item in self.classes_played if item.primary),
            None,
        )
        return performance.player_class if performance is not None else None

    def to_dict(self, *, include_raw: bool = False) -> dict[str, Any]:
        output: dict[str, Any] = {
            "name": self.name,
            "global_rank": self.global_rank,
            "classes_played": [
                item.to_dict(include_raw=include_raw) for item in self.classes_played
            ],
        }
        if self.primary_class is not None:
            output["primary_class"] = self.primary_class.to_dict()
        if self.elo is not None:
            output["elo"] = self.elo
        if self.total_matches is not None:
            output["total_matches"] = self.total_matches
            output["total_wins"] = self.total_wins
            output["total_draws"] = self.total_draws
            output["total_losses"] = self.total_losses
            if self.total_win_rate is not None:
                output["total_win_rate"] = self.total_win_rate
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
    candidate_messages_observed: int = 0
    candidate_frames_retained: int = 0
    candidate_bytes_retained: int = 0
    peak_candidate_frames: int = 0
    peak_candidate_bytes: int = 0
    candidate_frames_evicted: int = 0
    candidate_bytes_evicted: int = 0
    candidate_history_rolled_over: bool = False
    packet_queue_peak: int = 0
    packet_queue_overflows: int = 0
    flow_state_evictions: int = 0

    @property
    def capture_is_clean(self) -> bool:
        return (
            self.tcp_gap_resets == 0
            and (self.pcap_dropped in (None, 0))
            and (self.pcap_interface_dropped in (None, 0))
            and self.packet_queue_overflows == 0
            and self.flow_state_evictions == 0
        )

    def to_dict(self) -> dict[str, object]:
        output: dict[str, object] = {
            "payload_segments": self.payload_segments,
            "payload_bytes": self.payload_bytes,
            "synchronized_messages": self.synchronized_messages,
            "retained_large_messages": self.retained_large_messages,
            "tcp_gap_resets": self.tcp_gap_resets,
            "saved_packets": self.saved_packets,
            "candidate_messages_observed": self.candidate_messages_observed,
            "candidate_frames_retained": self.candidate_frames_retained,
            "candidate_bytes_retained": self.candidate_bytes_retained,
            "peak_candidate_frames": self.peak_candidate_frames,
            "peak_candidate_bytes": self.peak_candidate_bytes,
            "candidate_frames_evicted": self.candidate_frames_evicted,
            "candidate_bytes_evicted": self.candidate_bytes_evicted,
            "candidate_history_rolled_over": self.candidate_history_rolled_over,
            "packet_queue_peak": self.packet_queue_peak,
            "packet_queue_overflows": self.packet_queue_overflows,
            "flow_state_evictions": self.flow_state_evictions,
            "capture_is_clean": self.capture_is_clean,
        }
        optional = {
            "pcap_received": self.pcap_received,
            "pcap_dropped": self.pcap_dropped,
            "pcap_interface_dropped": self.pcap_interface_dropped,
            "capture_buffer_bytes": self.capture_buffer_bytes,
        }
        output.update(
            {key: value for key, value in optional.items() if value is not None}
        )
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
    overall_top_100: tuple[SolareOverallEntry, ...] = field(
        default=(),
        kw_only=True,
    )
    class_table_capabilities: frozenset[str] = field(
        default=frozenset({"rankings"}),
        kw_only=True,
    )
    overall_capabilities: frozenset[str] = field(
        default=frozenset({"rankings"}),
        kw_only=True,
    )
    schema_version: ClassVar[int] = _SOLARE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        # Preserve deep immutability even when a caller supplies an ordinary
        # set to the public constructor despite the frozenset annotation.
        object.__setattr__(
            self,
            "class_table_capabilities",
            frozenset(self.class_table_capabilities),
        )
        object.__setattr__(
            self,
            "overall_capabilities",
            frozenset(self.overall_capabilities),
        )

    @property
    def capabilities(self) -> frozenset[str]:
        """Return capabilities guaranteed independently by both tables."""

        return self.class_table_capabilities & self.overall_capabilities

    @property
    def observed_at_iso(self) -> str:
        return (
            dt.datetime.fromtimestamp(self.observed_at, tz=dt.timezone.utc)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z")
        )

    @property
    def top_100(self) -> tuple[SolarePlayer, ...]:
        """Return rich-table detail records whose global rank is in 1..100.

        This compatibility view remains a tuple of :class:`SolarePlayer` and
        is unchanged for the historical exact-overlap captures.  It can be
        shorter than 100 when the authoritative overall table contains a
        player outside the per-class top-20 tables; use :attr:`overall_top_100`
        when all authoritative overall rows are required.
        """

        return tuple(
            player
            for player in sorted(self.players, key=lambda item: item.global_rank)
            if 1 <= player.global_rank <= 100
        )

    def class_leaderboard(self, class_code: int) -> tuple[SolarePlayer, ...]:
        return tuple(
            player
            for player in sorted(self.players, key=lambda item: item.global_rank)
            if player.primary_class.code == class_code
        )

    def get_player(self, name: str) -> Optional[SolarePlayer]:
        return next((player for player in self.players if player.name == name), None)

    def get_overall_entry(self, name: str) -> Optional[SolareOverallEntry]:
        """Return the first exact, case-sensitive overall-table name match."""

        return next(
            (entry for entry in self.overall_top_100 if entry.name == name),
            None,
        )

    def to_dict(self, *, include_raw: bool = False) -> dict[str, Any]:
        return {
            "schema_version": _SOLARE_SCHEMA_VERSION,
            "snapshot_id": self.snapshot_id,
            "observed_at": self.observed_at,
            "observed_at_iso": self.observed_at_iso,
            "capabilities": sorted(self.capabilities),
            "class_table_capabilities": sorted(self.class_table_capabilities),
            "overall_capabilities": sorted(self.overall_capabilities),
            "complete": True,
            "record_count": len(self.players),
            "players": [
                player.to_dict(include_raw=include_raw) for player in self.players
            ],
            "overall_record_count": len(self.overall_top_100),
            "overall_top_100": [
                entry.to_dict(include_raw=include_raw) for entry in self.overall_top_100
            ],
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
    """Final outcome and sole evidence owner; only ``complete`` has a snapshot."""

    status: SolareDetectionStatus
    evidence: SolareEvidence
    snapshot: Optional[SolareLeaderboardSnapshot] = None
    message: Optional[str] = None
    schema_version: ClassVar[int] = _SOLARE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.status is SolareDetectionStatus.COMPLETE and self.snapshot is None:
            raise ValueError("a complete Solare result requires a snapshot")
        if (
            self.status is not SolareDetectionStatus.COMPLETE
            and self.snapshot is not None
        ):
            raise ValueError("only a complete Solare result may contain a snapshot")

    @property
    def complete(self) -> bool:
        return self.status is SolareDetectionStatus.COMPLETE

    def to_dict(self, *, include_raw: bool = False) -> dict[str, Any]:
        output: dict[str, Any] = {
            "schema_version": _SOLARE_SCHEMA_VERSION,
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


def solare_snapshot_id(
    players: Iterable[SolarePlayer],
    *,
    overall_top_100: Iterable[SolareOverallEntry] = (),
) -> str:
    """Return a deterministic semantic identifier, excluding opaque raw blobs.

    Exact-overlap snapshots retain the original rich-row-only digest only when
    every available comparable overall-table detail agrees with its independent
    class-table row.  A genuinely divergent overall table uses a versioned
    envelope containing both table identities and their non-raw semantics.
    """

    player_rows = tuple(players)
    rows = []
    for player in sorted(
        player_rows,
        key=lambda item: (item.global_rank, item.name),
    ):
        rows.append(
            {
                "name": player.name,
                "rank": player.global_rank,
                "class": player.primary_class.code,
                "elo": player.elo,
                "classes": [
                    {
                        "slot": item.slot,
                        "class": item.player_class.code,
                        "spec": (
                            item.specialization.code if item.specialization else None
                        ),
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
    overall_entries = tuple(
        sorted(
            overall_top_100,
            key=lambda item: (item.global_rank, item.name),
        )
    )
    overall_rows = [
        {
            "name": entry.name,
            "rank": entry.global_rank,
            "class": (
                entry.primary_class.code if entry.primary_class is not None else None
            ),
            "elo": entry.elo,
            "total_matches": entry.total_matches,
            "total_wins": entry.total_wins,
            "total_draws": entry.total_draws,
            "total_losses": entry.total_losses,
            "classes": [
                _class_performance_semantics(item, include_primary=True)
                for item in entry.classes_played
            ],
        }
        for entry in overall_entries
    ]
    rich_overall_players = tuple(
        sorted(
            (player for player in player_rows if 1 <= player.global_rank <= 100),
            key=lambda item: (item.global_rank, item.name),
        )
    )
    exact_semantic_overlap = len(overall_entries) == len(rich_overall_players) and all(
        entry.global_rank == player.global_rank
        and entry.name == player.name
        and _available_overall_details_agree(entry, player)
        for entry, player in zip(overall_entries, rich_overall_players)
    )
    if not overall_rows or exact_semantic_overlap:
        semantic_payload: object = rows
    else:
        semantic_payload = {
            "format": "solare-snapshot-v4-independent-overall-aggregates",
            "overall_top_100": overall_rows,
            "players": rows,
        }
    payload = json.dumps(
        semantic_payload,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _class_performance_semantics(
    performance: SolareClassPerformance,
    *,
    include_primary: bool = False,
) -> dict[str, object]:
    """Return non-opaque class-slot semantics used by snapshot identity."""

    output: dict[str, object] = {
        "slot": performance.slot,
        "class": performance.player_class.code,
        "spec": (
            performance.specialization.code
            if performance.specialization is not None
            else None
        ),
        "matches": performance.matches,
        "wins": performance.wins,
        "draws": performance.draws,
        "losses": performance.losses,
        "history": list(performance.recent_results_raw),
    }
    if include_primary:
        output["primary"] = performance.primary
    if performance.recent_results_wire_text is not None:
        output["history_wire_text"] = performance.recent_results_wire_text
    return output


def _available_overall_details_agree(
    overall: SolareOverallEntry,
    class_player: SolarePlayer,
) -> bool:
    """Compare only non-raw details actually available on an overall row."""

    if overall.elo is not None and overall.elo != class_player.elo:
        return False
    if not _available_overall_totals_agree(overall, class_player):
        return False
    if not overall.classes_played:
        return True
    if len(overall.classes_played) != len(class_player.classes_played):
        return False
    if (
        overall.primary_class is not None
        and overall.primary_class.code != class_player.primary_class.code
    ):
        return False

    for overall_slot, class_slot in zip(
        overall.classes_played,
        class_player.classes_played,
    ):
        if (
            overall_slot.slot != class_slot.slot
            or overall_slot.primary != class_slot.primary
            or overall_slot.player_class.code != class_slot.player_class.code
        ):
            return False
        if overall_slot.specialization is not None and (
            class_slot.specialization is None
            or overall_slot.specialization.code != class_slot.specialization.code
        ):
            return False
        for field_name in ("matches", "wins", "draws", "losses"):
            overall_value = getattr(overall_slot, field_name)
            if overall_value is not None and overall_value != getattr(
                class_slot, field_name
            ):
                return False
        if (
            overall_slot.recent_results_raw
            and overall_slot.recent_results_raw != class_slot.recent_results_raw
        ):
            return False
        if (
            overall_slot.recent_results_wire_text is not None
            and overall_slot.recent_results_wire_text
            != class_slot.recent_results_wire_text
        ):
            return False
    return True


def _available_overall_totals_agree(
    overall: SolareOverallEntry,
    class_player: SolarePlayer,
) -> bool:
    """Compare available overall aggregates with complete class-slot sums."""

    overall_values = (
        overall.total_wins,
        overall.total_draws,
        overall.total_losses,
    )
    if not any(value is not None for value in overall_values):
        return True
    if not class_player.classes_played:
        return False

    for field_name, overall_value in zip(
        ("wins", "draws", "losses"),
        overall_values,
    ):
        if overall_value is None:
            continue
        class_values = tuple(
            getattr(performance, field_name)
            for performance in class_player.classes_played
        )
        if any(value is None for value in class_values):
            return False
        if sum(value for value in class_values if value is not None) != overall_value:
            return False

    if overall.total_matches is not None:
        class_matches = tuple(
            performance.matches for performance in class_player.classes_played
        )
        if any(value is None for value in class_matches):
            return False
        if (
            sum(value for value in class_matches if value is not None)
            != overall.total_matches
        ):
            return False
    return True
