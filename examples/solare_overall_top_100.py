"""Print the authoritative Arena of Solare overall top 100."""

from __future__ import annotations

import argparse
from pathlib import Path

from bdo_toolkit.solare import replay_solare

parser = argparse.ArgumentParser()
parser.add_argument("pcap", type=Path, help="saved leaderboard load")
args = parser.parse_args()

result = replay_solare(args.pcap)
if not result.complete or result.snapshot is None:
    raise SystemExit(f"{result.status.value}: {result.message}")

snapshot = result.snapshot
has_elo = "elo" in snapshot.overall_capabilities

print("OVERALL TOP 100")
for entry in snapshot.overall_top_100:
    elo = entry.elo if has_elo else "unavailable"
    print(f"{entry.global_rank:3}. {entry.name} | Elo {elo}")
