"""Live listener: print every detected item transfer/storage action."""

from __future__ import annotations

from pathlib import Path

from bdo_toolkit import ConsoleEventWriter, capture_live


def main() -> None:
    writer = ConsoleEventWriter()
    local_profile = Path(__file__).resolve().parents[1] / "opcodes.local"
    if not local_profile.is_file():
        raise FileNotFoundError(f"calibrated opcode profile not found: {local_profile}")
    print(f"Using opcode profile: {local_profile}", flush=True)
    for event in capture_live(
        opcode_profile=local_profile,
        event_types={"item_received", "storage_delta"},
    ):
        writer.write(event)


if __name__ == "__main__":
    main()
