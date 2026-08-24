"""Print aggregate and per-class statistics from one overall Solare row."""

from __future__ import annotations

import argparse
from pathlib import Path

from bdo_toolkit.solare import replay_solare

parser = argparse.ArgumentParser()
parser.add_argument("pcap", type=Path, help="saved leaderboard load")
parser.add_argument("name", help="exact, case-sensitive player name")
args = parser.parse_args()

result = replay_solare(args.pcap)
if not result.complete or result.snapshot is None:
    raise SystemExit(f"{result.status.value}: {result.message}")

snapshot = result.snapshot
entry = snapshot.get_overall_entry(args.name)
if entry is None:
    raise SystemExit(f"{args.name!r} is not in the overall top 100")

required = {"elo", "aggregate_performance", "performance"}
missing = required - snapshot.overall_capabilities
if missing:
    raise SystemExit(f"overall details unavailable: {sorted(missing)}")

wins = entry.total_wins
draws = entry.total_draws
losses = entry.total_losses
matches = entry.total_matches
if None in (entry.elo, wins, draws, losses, matches):
    raise SystemExit("validated overall statistics are unexpectedly missing")

print(f"{entry.global_rank}. {entry.name} | Elo {entry.elo}")
print(f"overall: {wins}W/{draws}D/{losses}L ({matches} matches)")

for performance in entry.classes_played:
    class_name = performance.player_class.name or performance.player_class.code
    specialization = performance.specialization
    specialization_name = (
        "unavailable"
        if specialization is None
        else (specialization.name or specialization.branch)
    )
    print(
        f"{class_name} ({specialization_name}): "
        f"{performance.wins}W/{performance.draws}D/"
        f"{performance.losses}L ({performance.matches} matches)"
    )
