"""Regression tests: every fixture pcap must decode to its recorded baseline.

The baselines under ``tests/baselines/`` were generated from the original
prototype parser (``home_internet_analyzer.py``) before the native migration
and verified byte-identical against the native engine. Any diff here means a
behavior change in TCP reassembly, frame scanning, or event decoding.

The pcap fixtures are personal captures kept out of the public repository;
these tests skip automatically when they are not present locally.
"""

import json
from pathlib import Path

import pytest

from fixture_paths import (
    BASELINE_DIR,
    FIXTURE_DIR,
    all_baseline_jsonl,
    all_fixture_pcaps,
    baseline_path_for_fixture,
)
from bdo_toolkit import replay_pcap

FIXTURES = all_fixture_pcaps()

pytestmark = pytest.mark.skipif(
    not FIXTURES,
    reason="local pcap fixtures not present (private captures)",
)


@pytest.mark.parametrize("pcap", FIXTURES, ids=lambda path: path.stem)
def test_fixture_matches_baseline(pcap: Path):
    baseline_path = baseline_path_for_fixture(pcap)
    assert baseline_path.exists(), f"missing baseline for {pcap.name}"

    expected = [
        json.loads(line)
        for line in baseline_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    actual = [event.to_dict() for event in replay_pcap(pcap)]

    assert actual == expected


def test_all_baselines_have_fixtures():
    fixture_paths = {
        path.relative_to(FIXTURE_DIR).with_suffix(".jsonl") for path in FIXTURES
    }
    baseline_paths = {
        path.relative_to(BASELINE_DIR) for path in all_baseline_jsonl()
    }
    assert baseline_paths <= fixture_paths
