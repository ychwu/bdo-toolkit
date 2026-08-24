"""Print one Arena of Solare class leaderboard from a saved load."""

from __future__ import annotations

import argparse
from pathlib import Path

from bdo_toolkit.solare import replay_solare

parser = argparse.ArgumentParser()
parser.add_argument("pcap", type=Path, help="saved leaderboard load")
parser.add_argument("class_code", type=int, help="BDO class code")
args = parser.parse_args()

result = replay_solare(args.pcap)
if not result.complete or result.snapshot is None:
    raise SystemExit(f"{result.status.value}: {result.message}")

snapshot = result.snapshot
players = snapshot.class_leaderboard(args.class_code)
if not players:
    raise SystemExit(f"no class-table rows for class code {args.class_code}")

class_name = players[0].primary_class.name or f"class {args.class_code}"
has_elo = "elo" in snapshot.class_table_capabilities

print(f"{class_name.upper()} TOP 20")
for player in players:
    elo = player.elo if has_elo else "unavailable"
    print(f"{player.global_rank:3}. {player.name} | Elo {elo}")
