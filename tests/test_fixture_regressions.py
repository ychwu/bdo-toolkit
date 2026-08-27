"""Regression tests for approved current-contract fixture outputs.

Each private fixture is decoded with its recorded profile authority and
compared with its reviewed baseline. Any diff means the current TCP
reassembly, frame-scanning, or event-decoding contract changed.

The pcap fixtures are personal captures kept out of the public repository;
these tests skip automatically when they are not present locally.
"""

import json
from pathlib import Path

import pytest

from fixture_paths import (
    all_fixture_pcaps,
    baseline_path_for_fixture,
    opcode_profile_for_fixture,
)
from bdo_toolkit import replay_pcap

SEMANTIC_EVENT_FIELDS = (
    "event_type",
    "timestamp",
    "flow",
    "item_id",
    "quantity",
    "source",
    "raw_context",
    "opcode",
    "message_length",
    "base_item_id",
    "enhancement_level",
    "enhancement",
    "inventory_slot",
    "item_instance",
    "storage_instance",
    "storage_id",
    "storage_name",
    "storage_name_confidence",
    "record_index",
    "record_count",
    "record_offset",
    "confidence",
)


def _has_reviewed_positive_baseline(pcap: Path) -> bool:
    baseline = baseline_path_for_fixture(pcap)
    return baseline.is_file() and bool(baseline.read_text(encoding="utf-8").strip())


def _semantic_event(payload: dict[str, object]) -> dict[str, object]:
    return {
        field: payload[field]
        for field in SEMANTIC_EVENT_FIELDS
        if field in payload
    }


# Empty historical baselines do not prove that silence is correct, especially
# when their capture has no matching profile sidecar. Only reviewed positive
# outputs participate in this broad matrix; focused tests own fail-closed and
# intentionally silent scenarios.
FIXTURES = [
    pcap for pcap in all_fixture_pcaps() if _has_reviewed_positive_baseline(pcap)
]

pytestmark = pytest.mark.skipif(
    not FIXTURES,
    reason="local pcap fixtures not present (private captures)",
)


@pytest.mark.parametrize("pcap", FIXTURES, ids=lambda path: path.stem)
def test_fixture_matches_baseline(pcap: Path):
    baseline_path = baseline_path_for_fixture(pcap)
    assert baseline_path.exists(), f"missing baseline for {pcap.name}"

    expected = [
        _semantic_event(json.loads(line))
        for line in baseline_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    # Historical fixtures default to the July 6 authority. Newer patches can
    # pin an adjacent ``.profile.json`` sidecar without combining generations.
    actual = [
        _semantic_event(event.to_dict())
        for event in replay_pcap(
            pcap,
            opcode_profile=opcode_profile_for_fixture(pcap),
        )
    ]

    assert actual == expected
