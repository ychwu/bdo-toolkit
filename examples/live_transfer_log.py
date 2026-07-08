"""Live listener: print every detected item transfer/storage action."""

from __future__ import annotations

from bdo_toolkit import ConsoleEventWriter, capture_live


def main() -> None:
    writer = ConsoleEventWriter()
    for event in capture_live(event_types={"item_received", "storage_delta"}):
        writer.write(event)


if __name__ == "__main__":
    main()
