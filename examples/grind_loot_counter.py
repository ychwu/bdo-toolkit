"""Tiny example: count mob-drop items in a pcap.

Usage: python examples/grind_loot_counter.py [path/to/session.pcapng]
"""

from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path

from bdo_toolkit import replay_pcap


DEFAULT_PCAP = (
    Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "44291_qty1_127.pcapng"
)


def main() -> None:
    pcap = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_PCAP
    totals: Counter[int] = Counter()
    for event in replay_pcap(
        pcap,
        include_legacy_opcodes=True,
        event_types={"item_received"},
        sources={"Mob Drop"},
    ):
        totals[event.item_id] += event.quantity

    for item_id, quantity in totals.items():
        print(f"item_id={item_id} quantity={quantity}")


if __name__ == "__main__":
    main()
