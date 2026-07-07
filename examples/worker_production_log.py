"""Tiny example: print passive worker storage deposits."""

from __future__ import annotations

from pathlib import Path

from bdo_toolkit import JsonlEventWriter, replay_pcap


ROOT = Path(__file__).resolve().parents[2]


def main() -> None:
    writer = JsonlEventWriter()
    fixture = ROOT / "captures" / "fixtures" / "5960_qty1_and_4015_qty1_multi.pcapng"
    for event in replay_pcap(
        fixture,
        event_types={"storage_delta"},
        sources={"Worker Deposit"},
    ):
        writer.write(event)


if __name__ == "__main__":
    main()

