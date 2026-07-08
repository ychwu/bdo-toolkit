"""Tiny example: print passive worker storage deposits.

Usage: python examples/worker_production_log.py [path/to/session.pcapng]
"""

from __future__ import annotations

import sys
from pathlib import Path

from bdo_toolkit import JsonlEventWriter, replay_pcap


DEFAULT_PCAP = (
    Path(__file__).resolve().parents[1]
    / "tests"
    / "fixtures"
    / "5960_qty1_and_4015_qty1_multi.pcapng"
)


def main() -> None:
    pcap = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_PCAP
    writer = JsonlEventWriter()
    for event in replay_pcap(
        pcap,
        event_types={"storage_delta"},
        sources={"Worker Deposit"},
    ):
        writer.write(event)


if __name__ == "__main__":
    main()
