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
        f"capabilities={sorted(result.snapshot.capabilities)}"
    )
    first = result.snapshot.overall_top_100[0]
    print(first.to_dict())

if args.json is not None:
    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_text(
        result.to_json(include_raw=args.include_raw) + "\n",
        encoding="utf-8",
    )
