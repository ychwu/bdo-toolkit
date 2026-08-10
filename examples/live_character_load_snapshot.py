"""Capture the next character load and print its aggregate item-state snapshot."""

from __future__ import annotations

from pathlib import Path

from bdo_toolkit.item_state import CharacterLoadSession, format_item_state


DEFAULT_PROFILE = Path(__file__).resolve().parents[1] / "opcodes.local"


def main() -> None:
    if not DEFAULT_PROFILE.is_file():
        raise FileNotFoundError(
            f"calibrated opcode profile not found: {DEFAULT_PROFILE}"
        )

    # Construct a new session after calibration finishes so it loads the newly
    # written profile. A running session does not hot-reload profile changes.
    session = CharacterLoadSession(opcode_profile=DEFAULT_PROFILE)
    print(f"Using opcode profile: {DEFAULT_PROFILE}", flush=True)
    session.start()

    try:
        input(
            "Capture started. Open the game or switch characters, wait until "
            "the playable world has settled, then press Enter to summarize.\n"
        )
    except KeyboardInterrupt:
        print("\nStopping capture and summarizing collected state...")
    finally:
        snapshot = session.stop()

    print(format_item_state(snapshot))


if __name__ == "__main__":
    main()
