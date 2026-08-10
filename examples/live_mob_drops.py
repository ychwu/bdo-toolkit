"""Tiny example: start live capture and print only mob-drop item receipts."""

from __future__ import annotations

from pathlib import Path

from bdo_toolkit import ConsoleEventWriter, EventFilter, capture_live


PROFILE = Path(__file__).resolve().parents[1] / "opcodes.local"


def main() -> None:
    if not PROFILE.is_file():
        raise FileNotFoundError(f"calibrated opcode profile not found: {PROFILE}")

    writer = ConsoleEventWriter()
    for event in capture_live(
        opcode_profile=PROFILE,
        event_filter=EventFilter(
            event_types={"item_received"},
            sources={"Mob Drop"},
        ),
    ):
        writer.write(event)


if __name__ == "__main__":
    main()

