"""Calibrate a local opcode profile from a known pcap fixture.

Uses the one-call facade: calibrate and persist in a single step. For the
two-step flow (inspect or filter specs before writing), see
live_calibrate_profile.py.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from bdo_toolkit.calibration import calibrate_and_update


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", type=Path, help="capture of the known action")
    parser.add_argument(
        "--profile",
        type=Path,
        default=Path("opcodes.local"),
        help="profile to update (default: opcodes.local)",
    )
    parser.add_argument("--item-id", type=int, required=True)
    parser.add_argument("--quantity", type=int, required=True)
    parser.add_argument(
        "--action",
        choices=("auto", "storage-to-inventory", "inventory-to-storage", "loot-preview"),
        default="auto",
    )
    args = parser.parse_args()

    result, update = calibrate_and_update(
        args.profile,
        pcap=args.pcap,
        item_id=args.item_id,
        quantity=args.quantity,
        action=args.action,
        backup=False,
    )

    print(result.summary())
    if update is None:
        raise SystemExit(1)  # nothing promoted; profile left untouched

    print(update.summary())
    print(f'use it with: replay_pcap("session.pcapng", opcode_profile="{args.profile}")')


if __name__ == "__main__":
    main()
