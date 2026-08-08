"""Turn opcode-agnostic structural discovery into immutable public models."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Optional

from bdo_toolkit._protocol import BDOFrame

from ._constants import class_name
from ._detail_learning import learn_unknown_solare_details
from ._details import (
    _overall_layout_for,
    _rich_layout_for,
    decode_solare_details,
    decode_solare_overall_details,
)
from ._discovery import (
    DiscoveredSolareFamily,
    SolareDiscoveryResult,
    discover_solare,
    family_frames,
)
from ._validation import validate_retain_raw_extensions
from .models import (
    SolareCaptureHealth,
    SolareCaptureResult,
    SolareClass,
    SolareDetectionStatus,
    SolareEvidence,
    SolareFamilyLayout,
    SolareLeaderboardSnapshot,
    SolareOverallEntry,
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


def _overall_entries(
    overall: DiscoveredSolareFamily,
) -> tuple[SolareOverallEntry, ...]:
    return tuple(
        SolareOverallEntry(
            name=name,
            global_rank=rank,
        )
        for name, rank in zip(overall.names, overall.ranks)
    )


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


def _overall_details_match_discovery(
    entries: tuple[SolareOverallEntry, ...],
    overall: DiscoveredSolareFamily,
) -> bool:
    discovered = tuple(
        sorted(
            zip(overall.ranks, overall.names),
            key=lambda row: row[0],
        )
    )
    decoded = tuple(
        (entry.global_rank, entry.name)
        for entry in sorted(entries, key=lambda entry: entry.global_rank)
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


def _resource_loss_summary(health: SolareCaptureHealth) -> Optional[str]:
    """Describe bounded live-pipeline losses that invalidate acquisition.

    This deliberately covers only losses introduced by the toolkit's bounded
    packet/reassembly pipeline.  Pcap drops and TCP gaps keep their broader
    capture-integrity wording below.
    """

    losses: list[str] = []
    if health.packet_queue_overflows:
        count = health.packet_queue_overflows
        losses.append(
            "packet queue overflow discarded "
            f"{count} captured packet{'s' if count != 1 else ''} before decoding"
        )
    if health.flow_state_evictions:
        count = health.flow_state_evictions
        losses.append(
            "forced flow-state eviction removed "
            f"{count} active TCP reassembly state{'s' if count != 1 else ''}"
        )
    if not losses:
        return None
    if len(losses) == 1:
        return losses[0]
    return f"{losses[0]} and {losses[1]}"


def _capture_loss_summary(health: SolareCaptureHealth) -> Optional[str]:
    """Name every observed acquisition loss, including pre-confirmation gaps."""

    losses: list[str] = []
    resource_loss = _resource_loss_summary(health)
    if resource_loss is not None:
        losses.append(resource_loss)
    if health.tcp_gap_resets:
        count = health.tcp_gap_resets
        losses.append(
            "TCP reassembly reset "
            f"{count} time{'s' if count != 1 else ''} after an unresolved "
            "sequence gap"
        )
    if health.pcap_dropped not in (None, 0):
        backend_drop_count = health.pcap_dropped
        assert backend_drop_count is not None
        losses.append(
            "the capture backend reported "
            f"{backend_drop_count} dropped "
            f"packet{'s' if backend_drop_count != 1 else ''}"
        )
    if health.pcap_interface_dropped not in (None, 0):
        interface_drop_count = health.pcap_interface_dropped
        assert interface_drop_count is not None
        losses.append(
            "the capture interface reported "
            f"{interface_drop_count} dropped "
            f"packet{'s' if interface_drop_count != 1 else ''}"
        )
    if not losses:
        return None
    if len(losses) == 1:
        return losses[0]
    return "; ".join(losses[:-1]) + f"; and {losses[-1]}"


def _noncomplete_message(
    status: SolareDetectionStatus,
    health: SolareCaptureHealth,
    *,
    integrity_rejected: bool,
) -> str:
    capture_loss = _capture_loss_summary(health)
    if capture_loss is not None:
        retry = (
            "Retry after reducing capture load"
            if _resource_loss_summary(health) is not None
            else "Retry with a fresh capture"
        )
        if integrity_rejected:
            return (
                "the structural tables matched, but acquisition integrity was "
                f"lost because {capture_loss}; snapshot publication was "
                f"withheld. {retry}"
            )
        return (
            f"{_message_for_status(status)}; acquisition integrity was lost "
            f"because {capture_loss}. {retry}"
        )

    if integrity_rejected:
        return (
            "the structural tables matched, but capture gaps or reported "
            "packet drops made acquisition integrity uncertain; snapshot "
            "publication was withheld"
        )

    message = _message_for_status(status)
    if health.candidate_history_rolled_over and health.capture_is_clean:
        return (
            f"{message}; the bounded candidate history rolled over after older "
            "frames were evaluated and discarded. Retry while opening the "
            "leaderboard promptly"
        )
    return message


def _evidence(
    discovery: SolareDiscoveryResult,
    health: SolareCaptureHealth,
    *,
    class_detail_layout_id: Optional[str] = None,
    overall_detail_layout_id: Optional[str] = None,
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
        exact_cross_check=discovery.exact_cross_check,
        rich_layout=_family_layout(
            rich,
            detail_layout_id=class_detail_layout_id,
        ),
        overall_layout=_family_layout(
            overall,
            detail_layout_id=overall_detail_layout_id,
        ),
        health=health,
    )


def build_solare_result(
    frames: Iterable[BDOFrame],
    health: SolareCaptureHealth,
    *,
    retain_raw_extensions: bool = False,
    _discovery: Optional[SolareDiscoveryResult] = None,
) -> SolareCaptureResult:
    """Classify collected generic frames and construct a fail-closed result.

    A snapshot is returned only after the rich 620-player class table and an
    independent complete overall top 100 agree on every shared rank and name.
    Deeper detail decoding is optional: an unfamiliar geometry may use bounded
    ephemeral inference after confirmation, while every unsupported or
    ambiguous capability is still omitted from the ranking snapshot.
    """

    retain_raw_extensions = validate_retain_raw_extensions(
        retain_raw_extensions
    )
    frame_tuple = tuple(frames)
    discovery = _discovery or discover_solare(frame_tuple)
    integrity_rejected = discovery.confirmed and not health.capture_is_clean
    if not frame_tuple and health.payload_segments == 0:
        status = SolareDetectionStatus.NO_TRAFFIC
    elif integrity_rejected:
        status = SolareDetectionStatus.DETECTED_INCOMPLETE
    else:
        status = SolareDetectionStatus(discovery.status)

    if status is not SolareDetectionStatus.COMPLETE:
        evidence = _evidence(discovery, health)
        message = _noncomplete_message(
            status,
            health,
            integrity_rejected=integrity_rejected,
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
    overall_entries = _overall_entries(overall)
    class_table_capabilities = {"rankings"}
    overall_capabilities = {"rankings"}
    class_detail_layout_id: Optional[str] = None
    overall_detail_layout_id: Optional[str] = None
    rich_frames = family_frames(frame_tuple, rich)
    overall_frames = family_frames(frame_tuple, overall)
    class_details = decode_solare_details(
        rich_frames,
        rich,
        retain_raw_extensions=retain_raw_extensions,
    )
    overall_details = decode_solare_overall_details(
        overall_frames,
        overall,
        retain_raw_extensions=retain_raw_extensions,
    )
    learn_rich = _rich_layout_for(rich) is None
    learn_overall = _overall_layout_for(overall) is None
    if learn_rich or learn_overall:
        known_rich_elos: Optional[dict[str, int]] = None
        if (
            not learn_rich
            and class_details is not None
            and "elo" in class_details.capabilities
            and all(player.elo is not None for player in class_details.players)
        ):
            known_rich_elos = {
                player.name: player.elo
                for player in class_details.players
                if player.elo is not None
            }
        known_overall_elos: Optional[dict[str, int]] = None
        if (
            not learn_overall
            and overall_details is not None
            and "elo" in overall_details.capabilities
            and all(entry.elo is not None for entry in overall_details.entries)
        ):
            known_overall_elos = {
                entry.name: entry.elo
                for entry in overall_details.entries
                if entry.elo is not None
            }
        learned_class, learned_overall = learn_unknown_solare_details(
            rich_frames,
            rich,
            overall_frames,
            overall,
            learn_rich=learn_rich,
            learn_overall=learn_overall,
            retain_raw_extensions=retain_raw_extensions,
            known_rich_elos=known_rich_elos,
            known_overall_elos=known_overall_elos,
        )
        if class_details is None and learn_rich:
            class_details = learned_class
        if overall_details is None and learn_overall:
            overall_details = learned_overall

    if class_details is not None and _details_match_discovery(
        class_details.players,
        rich,
    ):
        players = tuple(
            sorted(class_details.players, key=lambda player: player.global_rank)
        )
        class_detail_layout_id = class_details.layout_id
        class_table_capabilities.update(class_details.capabilities)

    if overall_details is not None and _overall_details_match_discovery(
        overall_details.entries,
        overall,
    ):
        overall_entries = tuple(
            sorted(
                overall_details.entries,
                key=lambda entry: entry.global_rank,
            )
        )
        overall_detail_layout_id = overall_details.layout_id
        overall_capabilities.update(overall_details.capabilities)

    evidence = _evidence(
        discovery,
        health,
        class_detail_layout_id=class_detail_layout_id,
        overall_detail_layout_id=overall_detail_layout_id,
    )
    snapshot = SolareLeaderboardSnapshot(
        snapshot_id=solare_snapshot_id(
            players,
            overall_top_100=overall_entries,
        ),
        observed_at=max(
            frame.context.timestamp for frame in (*rich_frames, *overall_frames)
        ),
        players=players,
        overall_top_100=overall_entries,
        evidence=evidence,
        class_table_capabilities=frozenset(class_table_capabilities),
        overall_capabilities=frozenset(overall_capabilities),
    )
    return SolareCaptureResult(
        status=status,
        evidence=evidence,
        snapshot=snapshot,
        message=_message_for_status(status),
    )
