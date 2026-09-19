"""Observe saved balances: python examples/agris_replay.py FILE --cap MAXIMUM."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from bdo_toolkit.agris import replay_agris


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", type=Path)
    parser.add_argument("--cap", type=int, required=True)
    args = parser.parse_args()
    with replay_agris(args.pcap, expected_maximum_points=args.cap) as replay:
        for balance in replay:
            print(json.dumps(balance.to_dict()))
    print(replay.status.to_dict(), file=sys.stderr)
    print(replay.health.to_dict(), file=sys.stderr)


if __name__ == "__main__":
    main()
