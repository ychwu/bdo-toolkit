"""Tiny example: count mob-drop items in a pcap."""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from bdo_toolkit import replay_pcap


ROOT = Path(__file__).resolve().parents[2]


def main() -> None:
    totals: Counter[int] = Counter()
    fixture = ROOT / "captures" / "fixtures" / "44291_qty1_127.pcapng"
    for event in replay_pcap(
        fixture,
        include_legacy_opcodes=True,
        event_types={"item_received"},
        sources={"Mob Drop"},
    ):
        totals[event.item_id] += event.quantity

    for item_id, quantity in totals.items():
        print(f"item_id={item_id} quantity={quantity}")


if __name__ == "__main__":
    main()

