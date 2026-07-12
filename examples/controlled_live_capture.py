"""Start live transfer logging and stop it from a separate control thread.

Press Enter to stand in for an application's Stop button.
"""

from __future__ import annotations

from threading import Thread

from bdo_toolkit import EventFilter, LiveCaptureSession


def main() -> None:
    session = LiveCaptureSession(
        event_filter=EventFilter(event_types={"item_received", "storage_delta"}),
    )
    failures: list[Exception] = []

    def pump_events() -> None:
        try:
            for event in session.events():
                print(event.format_human())
        except Exception as exc:
            failures.append(exc)

    session.start()
    worker = Thread(target=pump_events, daemon=True)
    worker.start()

    try:
        input("Live transfer logging started. Press Enter to stop.\n")
    finally:
        session.stop()
        worker.join()

    if failures:
        raise failures[0]


if __name__ == "__main__":
    main()
