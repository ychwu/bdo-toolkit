"""Tiny example: count mob-drop items in a pcap.

Usage: python examples/grind_loot_counter.py path/to/session.pcapng
       python examples/grind_loot_counter.py old.pcapng --profile old-opcodes.json
"""

from __future__ import annotations

import argparse
from collections import Counter
from pathlib import Path

from bdo_toolkit import EventFilter, replay_pcap


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", type=Path, help="capture file to count")
    parser.add_argument(
        "--profile",
        type=Path,
        help="opcode profile matching this capture's game patch",
    )
    args = parser.parse_args()
    totals: Counter[int] = Counter()
    for event in replay_pcap(
        args.pcap,
        opcode_profile=args.profile,
        event_filter=EventFilter(
            event_types={"item_received"},
            sources={"Mob Drop"},
        ),
    ):
        totals[event.item_id] += event.quantity

    for item_id, quantity in totals.items():
        print(f"item_id={item_id} quantity={quantity}")


if __name__ == "__main__":
    main()
