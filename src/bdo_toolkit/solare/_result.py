"""Turn opcode-agnostic structural discovery into immutable public models."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Optional

from bdo_toolkit._protocol import BDOFrame

from ._constants import class_name
from ._details import decode_solare_details
from ._discovery import (
    DiscoveredSolareFamily,
    SolareDiscoveryResult,
    discover_solare,
    family_frames,
)
from .models import (
    SolareCaptureHealth,
    SolareCaptureResult,
    SolareClass,
    SolareDetectionStatus,
    SolareEvidence,
    SolareFamilyLayout,
    SolareLeaderboardSnapshot,
    SolarePlayer,
    solare_snapshot_id,
)


def _family_layout(
    family: Optional[DiscoveredSolareFamily],
    *,
    detail_layout_id: Optional[str] = None,
) -> Optional[SolareFamilyLayout]:
    if family is None:
        return None
    return SolareFamilyLayout(
        role=family.role,
        opcode=family.opcode,
        message_length=family.frame_length,
        message_count=family.frame_count,
        record_stride=family.record_stride,
        name_offset=family.name_offset,
        rank_offset=family.rank_offset,
        class_offset=family.class_offset,
        detail_layout_id=detail_layout_id,
    )


def _ranking_players(rich: DiscoveredSolareFamily) -> tuple[SolarePlayer, ...]:
    players = (
        SolarePlayer(
            name=name,
            global_rank=rank,
            primary_class=SolareClass(code=class_code, name=class_name(class_code)),
        )
        for name, rank, class_code in zip(
            rich.names,
            rich.ranks,
            rich.class_codes,
        )
    )
    return tuple(sorted(players, key=lambda player: player.global_rank))


def _details_match_discovery(
    players: tuple[SolarePlayer, ...],
    rich: DiscoveredSolareFamily,
) -> bool:
    discovered = tuple(
        sorted(
            zip(rich.ranks, rich.names, rich.class_codes),
            key=lambda row: row[0],
        )
    )
    decoded = tuple(
        (player.global_rank, player.name, player.primary_class.code)
        for player in sorted(players, key=lambda player: player.global_rank)
    )
    return decoded == discovered


def _message_for_status(status: SolareDetectionStatus) -> str:
    messages = {
        SolareDetectionStatus.COMPLETE: (
            "structurally confirmed Solare leaderboard without a known opcode"
        ),
        SolareDetectionStatus.DETECTED_INCOMPLETE: (
            "leaderboard traffic was recognized, but the complete snapshot "
            "was not captured"
        ),
        SolareDetectionStatus.RICH_CANDIDATE: (
            "a complete class-balanced ranked table was found, but the "
            "independent overall top-100 cross-check was not captured"
        ),
        SolareDetectionStatus.RANKED_PARTIAL: (
            "ranked leaderboard structure was found, but the class-balanced "
            "table and overall cross-check were incomplete"
        ),
        SolareDetectionStatus.MENU_CONTEXT: (
            "Solare menu/history-like traffic was found, not a leaderboard"
        ),
        SolareDetectionStatus.INCONCLUSIVE: (
            "no complete structural Solare signature was found"
        ),
        SolareDetectionStatus.NO_TRAFFIC: (
            "no inbound payload from the selected game-server ports was found"
        ),
    }
    return messages[status]


def _evidence(
    discovery: SolareDiscoveryResult,
    health: SolareCaptureHealth,
    *,
    detail_layout_id: Optional[str] = None,
) -> SolareEvidence:
    ranked = discovery.ranked_candidate
    overall = discovery.overall or discovery.partial_overall
    rich = discovery.rich
    return SolareEvidence(
        scanned_messages=discovery.scanned_frames,
        candidate_families=discovery.candidate_families,
        ranked_players=ranked.record_count if ranked is not None else 0,
        class_group_counts=rich.class_counts if rich is not None else (),
        overall_players=overall.record_count if overall is not None else 0,
        exact_cross_check=overall.record_count if overall is not None else 0,
        rich_layout=_family_layout(
            rich,
            detail_layout_id=detail_layout_id,
        ),
        overall_layout=_family_layout(overall),
        health=health,
    )


def build_solare_result(
    frames: Iterable[BDOFrame],
    health: SolareCaptureHealth,
) -> SolareCaptureResult:
    """Classify collected generic frames and construct a fail-closed result.

    A snapshot is returned only after the rich 620-player table and an
    independent 100-player overall table agree exactly.  Deeper performance
    decoding is optional: an unfamiliar detail geometry still yields the
    confirmed ranking snapshot, while omitting unsupported capabilities.
    """

    frame_tuple = tuple(frames)
    discovery = discover_solare(frame_tuple)
    # A recording can contain a complete refresh followed by the beginning of
    # another refresh on the same flow. Aggregating those same-family messages
    # makes ranks restart and correctly invalidates the aggregate, but must not
    # erase the first already-complete atomic snapshot. The common one-refresh
    # path stays single-pass; only overlong candidate families trigger the
    # incremental first-window recovery used by live progress tracking.
    rich_identity = (
        (discovery.rich.opcode, discovery.rich.frame_length)
        if discovery.rich is not None
        else None
    )
    overlong_family = any(
        count > 310
        or (
            rich_identity is not None
            and (opcode, length) != rich_identity
            and count > 50
        )
        for opcode, length, count in discovery.candidate_families
    )
    if not discovery.confirmed and overlong_family:
        from ._live_tracker import LiveSolareDiscoveryTracker

        tracker = LiveSolareDiscoveryTracker(lambda _update: None)
        for frame in frame_tuple:
            tracker.observe(frame)
            if tracker.complete:
                assert tracker.confirmed_frames is not None
                frame_tuple = tracker.confirmed_frames
                discovery = discover_solare(frame_tuple)
                break
    integrity_rejected = discovery.confirmed and not health.capture_is_clean
    if not frame_tuple and health.payload_segments == 0:
        status = SolareDetectionStatus.NO_TRAFFIC
    elif integrity_rejected:
        status = SolareDetectionStatus.DETECTED_INCOMPLETE
    else:
        status = SolareDetectionStatus(discovery.status)

    if status is not SolareDetectionStatus.COMPLETE:
        evidence = _evidence(discovery, health)
        message = _message_for_status(status)
        if integrity_rejected:
            message = (
                "the structural tables matched, but capture gaps or reported "
                "packet drops made acquisition integrity uncertain; snapshot "
                "publication was withheld"
            )
        return SolareCaptureResult(
            status=status,
            evidence=evidence,
            message=message,
        )

    rich = discovery.rich
    overall = discovery.overall
    assert rich is not None
    assert overall is not None

    players = _ranking_players(rich)
    capabilities = {"rankings"}
    detail_layout_id: Optional[str] = None
    rich_frames = family_frames(frame_tuple, rich)
    overall_frames = family_frames(frame_tuple, overall)
    details = decode_solare_details(
        rich_frames,
        rich,
        overall_frames=overall_frames,
        overall=overall,
    )
    if details is not None and _details_match_discovery(details.players, rich):
        players = tuple(
            sorted(details.players, key=lambda player: player.global_rank)
        )
        detail_layout_id = details.layout_id
        capabilities.update({"performance", "raw_extensions"})

    evidence = _evidence(
        discovery,
        health,
        detail_layout_id=detail_layout_id,
    )
    snapshot = SolareLeaderboardSnapshot(
        snapshot_id=solare_snapshot_id(players),
        observed_at=max(
            frame.context.timestamp for frame in (*rich_frames, *overall_frames)
        ),
        players=players,
        evidence=evidence,
        capabilities=frozenset(capabilities),
    )
    return SolareCaptureResult(
        status=status,
        evidence=evidence,
        snapshot=snapshot,
        message=_message_for_status(status),
    )
