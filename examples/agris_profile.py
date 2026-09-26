"""Explicitly calibrate or track Agris using an existing opcode profile."""
import argparse

from bdo_toolkit import load_opcode_profile
from bdo_toolkit.agris import LiveAgrisSession, calibrate_agris_and_update


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("profile", help="Existing active local opcode profile")
    parser.add_argument("--cap", required=True, type=int)
    parser.add_argument("--calibrate", action="store_true",
                        help="Discover and save Agris, preserving item fields with backup")
    args = parser.parse_args()
    if args.calibrate:
        print(calibrate_agris_and_update(args.profile, expected_maximum_points=args.cap).to_dict())
        return
    profile = load_opcode_profile(args.profile)
    # A missing Agris section is an error, never an implicit discovery fallback.
    with LiveAgrisSession(profile=profile, expected_maximum_points=args.cap) as session:
        for balance in session.events():
            print(balance.to_dict())


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
