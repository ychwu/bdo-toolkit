"""Replay a saved Solare capture using only the public toolkit API."""

from __future__ import annotations

import argparse
from pathlib import Path

from bdo_toolkit.solare import replay_solare

parser = argparse.ArgumentParser()
parser.add_argument("pcap", type=Path)
parser.add_argument(
    "--json",
    type=Path,
    help="optionally write the terminal result as JSON",
)
parser.add_argument(
    "--include-raw",
    action="store_true",
    help=(
        "retain opaque gear/addon buffers during replay and include them "
        "in --json output"
    ),
)
args = parser.parse_args()

if args.json is not None:
    capture_path = args.pcap.expanduser()
    json_path = args.json.expanduser()
    same_path = capture_path.resolve() == json_path.resolve()
    try:
        same_path = same_path or (
            capture_path.exists()
            and json_path.exists()
            and capture_path.samefile(json_path)
        )
    except OSError:
        pass
    if same_path:
        parser.error("--json must not overwrite the input capture")

# No Solare opcode or calibration profile is supplied. Unregistered geometries
# are learned ephemerally only after the complete tables are confirmed.
result = replay_solare(
    args.pcap,
    retain_raw_extensions=args.include_raw,
)

if args.json is not None:
    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_text(
        result.to_json(include_raw=args.include_raw) + "\n",
        encoding="utf-8",
    )

print(f"status={result.status.value}: {result.message}")
snapshot = result.snapshot
if not result.complete or snapshot is None:
    evidence = result.evidence
    health = evidence.health
    print(
        "evidence="
        f"ranked_players={evidence.ranked_players}/620 "
        f"overall_rows={evidence.overall_players}/100 "
        f"exact_cross_check={evidence.exact_cross_check}/100 "
        f"tcp_gap_resets={health.tcp_gap_resets} "
        f"pcap_dropped={health.pcap_dropped} "
        f"interface_dropped={health.pcap_interface_dropped} "
        f"queue_overflows={health.packet_queue_overflows} "
        f"candidate_history_rolled_over="
        f"{health.candidate_history_rolled_over}"
    )
    raise SystemExit(1)

print(
    f"snapshot={snapshot.snapshot_id} "
    f"players={len(snapshot.players)} "
    f"overall={len(snapshot.overall_top_100)} "
    f"class_capabilities={sorted(snapshot.class_table_capabilities)} "
    f"overall_capabilities={sorted(snapshot.overall_capabilities)}"
)
first = snapshot.overall_top_100[0]
# Every available value on this object comes directly from the overall
# response, even if this name is absent from the class tables.
elo_text = (
    f" Elo={first.elo}"
    if "elo" in snapshot.overall_capabilities
    else ""
)
print(f"overall_player={first.global_rank}. {first.name}{elo_text}")

# total_matches is derived from the three direct overall W/D/L totals. It
# is not the first class slot and is not a sum of the exposed class slots.
if "aggregate_performance" in snapshot.overall_capabilities:
    print(
        "overall_record="
        f"{first.total_wins}W/{first.total_draws}D/{first.total_losses}L "
        f"({first.total_matches} derived matches)"
    )
for performance in first.classes_played:
    print(
        "per_class_record="
        f"{performance.player_class.name or performance.player_class.code} "
        f"{performance.wins}W/{performance.draws}D/{performance.losses}L "
        f"({performance.matches} matches)"
    )

# The separate class-table response remains available through its own
# query model.
example_class = snapshot.players[0].primary_class
class_rows = snapshot.class_leaderboard(example_class.code)
print(
    f"class_table={example_class.name or example_class.code} "
    f"rows={len(class_rows)} leader={class_rows[0].name}"
)
