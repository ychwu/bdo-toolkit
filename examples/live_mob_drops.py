"""Tiny example: start live capture and print only mob-drop item receipts."""

from __future__ import annotations

from bdo_toolkit import ConsoleEventWriter, capture_live


def main() -> None:
    writer = ConsoleEventWriter()
    for event in capture_live(
        event_types={"item_received"},
        sources={"Mob Drop"},
    ):
        writer.write(event)


if __name__ == "__main__":
    main()

