"""Print every decoded event from a pcap as a human-readable log."""

from __future__ import annotations

from pathlib import Path

from bdo_toolkit import ConsoleEventWriter, replay_pcap


ROOT = Path(__file__).resolve().parents[2]


def main() -> None:
    writer = ConsoleEventWriter()
    fixture = ROOT / "captures" / "fixtures" / "new_potato.pcapng"
    for event in replay_pcap(fixture):
        writer.write(event)


if __name__ == "__main__":
    main()

