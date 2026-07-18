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
    help="optionally write JSON, including opaque raw gear/addon buffers",
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

result = replay_solare(args.pcap)
print(f"status={result.status.value}: {result.message}")
if result.snapshot is not None:
    print(
        f"snapshot={result.snapshot.snapshot_id} "
        f"players={len(result.snapshot.players)} "
        f"capabilities={sorted(result.snapshot.capabilities)}"
    )
    first = result.snapshot.players[0]
    print(first.to_dict(include_raw=False))

if args.json is not None:
    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_text(
        result.to_json(include_raw=True) + "\n",
        encoding="utf-8",
    )
