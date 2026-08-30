"""Capture one Arena of Solare leaderboard load and optionally save it."""

from __future__ import annotations

import argparse
import math
import time
from pathlib import Path

from bdo_toolkit.solare import (
    LiveSolareSession,
    SolareUpdate,
    SolareUpdateKind,
)

parser = argparse.ArgumentParser()
deadline_group = parser.add_mutually_exclusive_group()
deadline_group.add_argument(
    "--capture-seconds",
    type=float,
    help="capture deadline in seconds (default: 120)",
)
deadline_group.add_argument(
    "--wait-forever",
    action="store_true",
    help="wait without a deadline until completion or Ctrl+C",
)
parser.add_argument(
    "--save-pcap",
    type=Path,
    help="optionally save accepted packets for deterministic replay",
)
parser.add_argument(
    "--include-raw",
    action="store_true",
    help="also retain validated opaque gear/addon sections in the snapshot",
)
args = parser.parse_args()
if args.capture_seconds is not None and (
    not math.isfinite(args.capture_seconds) or args.capture_seconds < 0
):
    parser.error("--capture-seconds must be finite and non-negative")
capture_seconds = (
    None
    if args.wait_forever
    else (120.0 if args.capture_seconds is None else args.capture_seconds)
)
save_pcap = args.save_pcap


def show_progress(update: SolareUpdate) -> None:
    if update.kind is not SolareUpdateKind.FINISHED:
        print(f"[{update.kind.value}] {update.message}", flush=True)


# This explicit session loop makes a quiet network interval visible. The
# capture still stops automatically as soon as one complete snapshot is
# confirmed. Solare structural discovery and unknown-layout learning do not
# use item calibration or an opcode profile.
session = LiveSolareSession(
    save_pcap=save_pcap,
    retain_raw_extensions=args.include_raw,
)
session.start()
started_at = time.monotonic()
deadline = (
    None if capture_seconds is None else started_at + capture_seconds
)
deadline_text = (
    "no deadline; use Ctrl+C to stop"
    if capture_seconds is None
    else f"{capture_seconds:g}-second deadline"
)
print(
    "[capture-policy] auto-stop on a complete snapshot; "
    f"{deadline_text}; "
    + (
        "recording disabled; "
        if save_pcap is None
        else f"recording {save_pcap}; "
    )
    + "status heartbeat every 10 seconds",
    flush=True,
)
next_heartbeat = started_at + 10.0
ranked_players = 0
overall_players = 0
exact_cross_check = 0
result = None
termination = "complete-snapshot"

try:
    while result is None:
        now = time.monotonic()
        if deadline is not None and now >= deadline:
            termination = "deadline"
            print(
                "[stopping] capture deadline reached; draining queued packets "
                "and finalizing the best fail-closed result",
                flush=True,
            )
            result = session.stop()
            break

        poll_seconds = 1.0
        if deadline is not None:
            poll_seconds = min(poll_seconds, max(0.0, deadline - now))
        update = session.poll(timeout=poll_seconds)
        if update is not None:
            ranked_players = max(ranked_players, update.ranked_players)
            overall_players = max(overall_players, update.overall_players)
            exact_cross_check = max(
                exact_cross_check,
                update.exact_cross_check,
            )
            show_progress(update)
            if update.kind is SolareUpdateKind.FINISHED:
                # FINISHED is queued before the worker publishes its final
                # stop reason and terminal error state. Settle the bounded
                # worker cleanup before trusting either.
                if not session.stopped:
                    print(
                        "[stopping] terminal update received; finishing "
                        "capture cleanup",
                        flush=True,
                    )
                result = session.stop()
                termination = session.stop_reason or termination
                break

        now = time.monotonic()
        if session.running and now >= next_heartbeat:
            elapsed = now - started_at
            remaining = (
                "no deadline"
                if deadline is None
                else f"{max(0.0, deadline - now):.0f}s remaining"
            )
            print(
                "[waiting] "
                f"{elapsed:.0f}s elapsed, {remaining}; "
                f"ranked players={ranked_players}/620, "
                f"overall rows={overall_players}/100, "
                f"exact cross-check={exact_cross_check}/100. "
                "Still listening. If the Leaderboard was opened before "
                "capture started, restart the game before retrying.",
                flush=True,
            )
            while next_heartbeat <= now:
                next_heartbeat += 10.0

        if update is None and session.stopped:
            result = session.result
            termination = session.stop_reason or termination
            break
except KeyboardInterrupt:
    termination = "Ctrl+C"
    print(
        "\n[stopping] Ctrl+C received; draining queued packets and "
        "finalizing the best fail-closed result",
        flush=True,
    )
    result = session.stop()
finally:
    if result is None and session.running:
        print(
            "[stopping] draining queued packets and finalizing capture",
            flush=True,
        )
        result = session.stop()

if result is None:
    raise RuntimeError("live Solare session ended without a result")

print(f"[capture-finished] stop reason: {termination}", flush=True)
if save_pcap is not None:
    print(f"[saved-capture] {save_pcap.resolve()}", flush=True)
if not result.complete or result.snapshot is None:
    evidence = result.evidence
    health = evidence.health
    print(
        f"No complete snapshot: {result.status.value} ({result.message})\n"
        f"  structural evidence: ranked players="
        f"{evidence.ranked_players}/620, "
        f"overall rows={evidence.overall_players}/100, "
        f"exact cross-check={evidence.exact_cross_check}/100\n"
        f"  capture health: TCP gap resets={health.tcp_gap_resets}, "
        f"Npcap drops={health.pcap_dropped}, "
        f"interface drops={health.pcap_interface_dropped}, "
        f"queue overflows={health.packet_queue_overflows}, "
        f"flow evictions={health.flow_state_evictions}, "
        f"candidate history rolled over="
        f"{health.candidate_history_rolled_over}",
        flush=True,
    )
    raise SystemExit(1)

snapshot = result.snapshot
print(
    f"\nclass rows={len(snapshot.players)}; "
    f"class capabilities={sorted(snapshot.class_table_capabilities)}; "
    f"overall capabilities={sorted(snapshot.overall_capabilities)}"
)
if args.include_raw:
    performances = tuple(
        performance
        for player in snapshot.players
        for performance in player.classes_played
    ) + tuple(
        performance
        for player in snapshot.overall_top_100
        for performance in player.classes_played
    )
    gear_sections = tuple(
        performance.gear_loadout_raw
        for performance in performances
        if performance.gear_loadout_raw is not None
    )
    addon_sections = tuple(
        performance.skill_addons_raw
        for performance in performances
        if performance.skill_addons_raw is not None
    )
    raw_bytes = sum(
        section.length for section in (*gear_sections, *addon_sections)
    )
    print(
        "[raw-retention] "
        f"{len(gear_sections)} gear sections and "
        f"{len(addon_sections)} addon sections retained "
        f"({raw_bytes} opaque bytes; contents not printed)"
    )
for entry in snapshot.overall_top_100[:10]:
    # These totals are separate scalars from the overall response. They are
    # never copied from, or calculated by summing, classes_played.
    aggregate = "overall aggregate unavailable"
    if (
        "aggregate_performance" in snapshot.overall_capabilities
        and entry.total_matches is not None
        and entry.total_wins is not None
        and entry.total_draws is not None
        and entry.total_losses is not None
    ):
        aggregate = (
            f"overall {entry.total_wins}W/{entry.total_draws}D/"
            f"{entry.total_losses}L ({entry.total_matches} derived matches)"
        )
    elo = entry.elo if entry.elo is not None else "unavailable"
    print(
        f"{entry.global_rank:3}. {entry.name:<24} "
        f"Elo {elo}; {aggregate}"
    )

    # classes_played is a separate, capped collection of detailed per-class
    # records. A player can have activity outside its one-to-three exposed
    # slots, and even matching totals can use different W/L bookkeeping.
    for performance in entry.classes_played:
        class_label = performance.player_class.name or str(
            performance.player_class.code
        )
        if (
            performance.matches is None
            or performance.wins is None
            or performance.draws is None
            or performance.losses is None
        ):
            class_record = "per-class stats unavailable"
        else:
            class_record = (
                f"{performance.wins}W/{performance.draws}D/"
                f"{performance.losses}L ({performance.matches} matches)"
            )
        print(f"     class slot {performance.slot}: {class_label}; {class_record}")

# Class leaderboards are decoded independently from the separate 31 x top-20
# response. Query them directly rather than treating overall rows as their
# data source.
example_class = snapshot.players[0].primary_class
class_rows = snapshot.class_leaderboard(example_class.code)
print(
    f"\n{example_class.name or example_class.code} class table: "
    f"{len(class_rows)} rows; leader={class_rows[0].name}"
)
