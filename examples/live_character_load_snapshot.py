"""Capture the next character load and print its aggregate item-state snapshot."""

from __future__ import annotations

from pathlib import Path

from bdo_toolkit.item_state import CharacterLoadSession, format_item_state


PROFILE = Path(__file__).resolve().parents[1] / "opcodes.local"


def main() -> None:
    if not PROFILE.is_file():
        raise FileNotFoundError(
            f"opcode profile not found: {PROFILE}; fetch or calibrate it first"
        )

    # Construct a new session after calibration finishes so it loads the newly
    # written profile. A running session does not hot-reload profile changes.
    session = CharacterLoadSession(opcode_profile=PROFILE)
    print(f"Using opcode profile: {PROFILE}", flush=True)
    session.start()

    try:
        input(
            "Capture started. For storage, enter the world for the first time "
            "after a fresh game launch; a later character switch captures "
            "inventory only. Press Enter after the world has settled.\n"
        )
    except KeyboardInterrupt:
        print("\nStopping capture and summarizing collected state...")
    finally:
        snapshot = session.stop()

    print(format_item_state(snapshot))


if __name__ == "__main__":
    main()
