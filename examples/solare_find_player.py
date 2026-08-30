"""Search both Arena of Solare leaderboard collections by exact name."""

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
overall = snapshot.get_overall_entry(args.name)
class_row = snapshot.get_player(args.name)

if overall is None and class_row is None:
    raise SystemExit(f"{args.name!r} was not found")

if overall is None:
    print("overall top 100: not found")
else:
    print(f"overall top 100: rank {overall.global_rank}")

if class_row is None:
    print("class tables: not found")
else:
    class_name = class_row.primary_class.name or class_row.primary_class.code
    print(f"class tables: rank {class_row.global_rank}, {class_name}")
