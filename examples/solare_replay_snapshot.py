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
print(f"status={result.status.value}: {result.message}")
if result.snapshot is not None:
    print(
        f"snapshot={result.snapshot.snapshot_id} "
        f"players={len(result.snapshot.players)} "
        f"overall={len(result.snapshot.overall_top_100)} "
        f"class_capabilities="
        f"{sorted(result.snapshot.class_table_capabilities)} "
        f"overall_capabilities={sorted(result.snapshot.overall_capabilities)}"
    )
    first = result.snapshot.overall_top_100[0]
    # Every available value on this object comes directly from the overall
    # response, even if this name is absent from the class tables.
    print(first.to_dict())

    # total_matches is derived from the three direct overall W/D/L totals. It
    # is not the first class slot and is not a sum of the exposed class slots.
    if "aggregate_performance" in result.snapshot.overall_capabilities:
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
    example_class = result.snapshot.players[0].primary_class
    class_rows = result.snapshot.class_leaderboard(example_class.code)
    print(
        f"class_table={example_class.name or example_class.code} "
        f"rows={len(class_rows)} leader={class_rows[0].name}"
    )

if args.json is not None:
    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_text(
        result.to_json(include_raw=args.include_raw) + "\n",
        encoding="utf-8",
    )
