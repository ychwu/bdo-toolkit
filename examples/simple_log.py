"""Print every decoded event from a pcap as a human-readable log.

Usage: python examples/simple_log.py [path/to/session.pcapng]
"""

from __future__ import annotations

import sys
from pathlib import Path

from bdo_toolkit import ConsoleEventWriter, replay_pcap


DEFAULT_PCAP = (
    Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "new_potato.pcapng"
)


def main() -> None:
    pcap = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_PCAP
    writer = ConsoleEventWriter()
    for event in replay_pcap(pcap):
        writer.write(event)


if __name__ == "__main__":
    main()
