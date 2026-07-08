"""Calibrate a local opcode profile from a known pcap fixture."""

from __future__ import annotations

from pathlib import Path

from bdo_toolkit.calibration import calibrate_pcap, update_profile


ROOT = Path(__file__).resolve().parents[1]
PCAP = ROOT / "tests" / "fixtures" / "new_potato_3_tostorage.pcapng"
PROFILE = ROOT / "opcodes.local"


def main() -> None:
    result = calibrate_pcap(
        PCAP,
        item_id=7003,
        quantity=3,
        action="inventory-to-storage",
    )

    print(f"scanned {result.frames_scanned} frames")
    if not result.specs:
        raise SystemExit("no opcode specs discovered")

    for spec in result.specs:
        fields = spec.to_json_dict()
        print(
            f"{fields['event']} "
            f"opcode={fields['opcode']} "
            f"length={fields['length']}"
        )

    update = update_profile(
        result,
        PROFILE,
        action="inventory-to-storage",
        replace=True,
        backup=False,
    )
    print(f"wrote {update.path}")
    print('use it with: replay_pcap("session.pcapng", opcode_profile="opcodes.local")')


if __name__ == "__main__":
    main()
