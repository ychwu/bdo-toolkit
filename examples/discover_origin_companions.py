"""Passively discover worker companion families from pcaps or live traffic.

Examples:
    python examples/discover_origin_companions.py --profile opcodes.local capture.pcapng
    python examples/discover_origin_companions.py --profile opcodes.local
"""

from __future__ import annotations

import argparse
from pathlib import Path

from bdo_toolkit import OriginLearner, capture_live, replay_pcap


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcaps", type=Path, nargs="*", help="captures to inspect")
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument(
        "--candidates",
        type=Path,
        default=Path("opcodes.origin-candidates.json"),
    )
    parser.add_argument("--min-observations", type=int, default=2)
    args = parser.parse_args()

    learner = OriginLearner.load(
        args.candidates,
        min_observations=args.min_observations,
    )
    if args.pcaps:
        for pcap in args.pcaps:
            list(
                replay_pcap(
                    pcap,
                    opcode_profile=args.profile,
                    origin_observer=learner.observe,
                )
            )
    else:
        try:
            for _ in capture_live(
                opcode_profile=args.profile,
                origin_observer=learner.observe,
            ):
                pass
        except KeyboardInterrupt:
            pass

    learner.save(args.candidates)
    for candidate in learner.candidates:
        pair = " -> ".join(
            f"0x{opcode:04X}" for opcode in candidate.companion_opcodes
        )
        status = (
            "confirmed"
            if candidate.confirmed(learner.min_observations)
            else "candidate"
        )
        print(
            f"{status}: delta=0x{candidate.delta_opcode:04X} "
            f"companions={pair} observations={candidate.observations}"
        )


if __name__ == "__main__":
    main()
