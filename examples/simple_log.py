"""Print every decoded event from a pcap as a human-readable log.

Usage: python examples/simple_log.py path/to/session.pcapng
"""

from __future__ import annotations

import argparse
from pathlib import Path

from bdo_toolkit import ConsoleEventWriter, replay_pcap


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", type=Path, help="capture file to decode")
    args = parser.parse_args()
    writer = ConsoleEventWriter()
    for event in replay_pcap(args.pcap):
        writer.write(event)


if __name__ == "__main__":
    main()
