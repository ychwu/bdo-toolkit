"""Regenerate the recorded regression baselines from the current engine.

Run this ONLY after an intentional behavior change (new profile knowledge,
new event field, deliberate decoding fix), then review the diff carefully:

    python scripts/regenerate_baselines.py
    git diff tests/baselines/

An unexplained diff means the change altered decoding in a way you did not
intend.
"""

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from bdo_toolkit import replay_pcap  # noqa: E402

FIXTURE_DIR = REPO_ROOT / "tests" / "fixtures"
BASELINE_DIR = REPO_ROOT / "tests" / "baselines"


def main() -> int:
    BASELINE_DIR.mkdir(parents=True, exist_ok=True)
    total = 0
    fixtures = sorted(FIXTURE_DIR.rglob("*.pcapng"))
    for pcap in fixtures:
        events = list(replay_pcap(pcap))
        out = (BASELINE_DIR / pcap.relative_to(FIXTURE_DIR)).with_suffix(".jsonl")
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("w", encoding="utf-8", newline="\n") as fh:
            for event in events:
                fh.write(json.dumps(event.to_dict(), sort_keys=True) + "\n")
        total += len(events)
        print(f"{pcap.relative_to(FIXTURE_DIR)}: {len(events)} events")
    print(f"regenerated {total} events across {len(fixtures)} fixtures")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
