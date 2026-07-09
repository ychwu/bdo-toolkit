"""Structural origin-family learning, persistence, and promotion."""

from __future__ import annotations

import json

import pytest

from fixture_paths import fixture_path, has_fixture_pcaps
from bdo_toolkit import (
    OriginLearner,
    load_opcode_profile,
    promote_origin_candidates,
    replay_pcap,
)
from bdo_toolkit._protocol import FlowKey
from bdo_toolkit.origin_learning import CompanionObservation


FLOW = FlowKey("203.0.113.1", 8889, "198.51.100.2", 50000)
requires_fixtures = pytest.mark.skipif(
    not has_fixture_pcaps(),
    reason="local pcap fixtures not present (private captures)",
)


def _observation(*, sequence: int, timestamp: float, token: str) -> CompanionObservation:
    return CompanionObservation(
        timestamp=timestamp,
        flow=FLOW,
        stream_sequence=sequence,
        delta_opcode=0x0D7E,
        delta_length=258 if sequence == 1000 else 479,
        companion_opcodes=(0x0F7E, 0x0DE1),
        companion_lengths=(60, 23),
        token_digest=token,
        token_offsets=(16, 47, 5),
    )


def test_learner_deduplicates_replay_and_confirms_independent_observations(tmp_path):
    learner = OriginLearner(min_observations=2)
    first = _observation(sequence=1000, timestamp=1000.0, token="a" * 16)
    second = _observation(sequence=2000, timestamp=2000.0, token="b" * 16)

    assert learner.observe(first).observations == 1
    assert learner.observe(first).observations == 1
    candidate = learner.observe(second)

    assert candidate.observations == 2
    assert candidate.distinct_tokens == 2
    assert candidate.delta_lengths == (258, 479)
    assert candidate.confirmed(2)

    path = learner.save(tmp_path / "origin-candidates.json")
    loaded = OriginLearner.load(path)
    assert loaded.candidates == learner.candidates
    assert len(loaded.confirmed_candidates) == 1


def test_promotion_is_explicit_validated_and_idempotent(tmp_path):
    learner = OriginLearner(min_observations=2)
    learner.observe(_observation(sequence=1000, timestamp=1000.0, token="a" * 16))
    learner.observe(_observation(sequence=2000, timestamp=2000.0, token="b" * 16))
    candidates = learner.save(tmp_path / "origin-candidates.json")
    profile = tmp_path / "opcodes.local"
    profile.write_text(
        json.dumps(
            {
                "version": 1,
                "profile_active": True,
                "specs": {},
            }
        ),
        encoding="utf-8",
    )

    result = promote_origin_candidates(candidates, profile)

    assert result.written
    assert len(result.added) == 1
    assert result.backup_path is not None and result.backup_path.exists()
    loaded = load_opcode_profile(profile)
    (family,) = loaded.origin_companion_families
    assert family.delta_opcode == 0x0D7E
    assert family.companion_opcodes == (0x0F7E, 0x0DE1)
    assert family.companion_lengths == (60, 23)
    assert family.observations == 2

    second = promote_origin_candidates(candidates, profile)
    assert not second.written
    assert second.added == ()
    assert second.backup_path is None


@requires_fixtures
def test_new_patch_family_is_discovered_without_being_known(tmp_path):
    profile = tmp_path / "opcodes.json"
    profile.write_text(
        json.dumps(
            {
                "version": 1,
                "profile_active": True,
                "specs": {
                    "STORAGE_ITEM_DELTA": [
                        {
                            "event": "STORAGE_ITEM_DELTA",
                            "opcode": "0x0D7E",
                            "length": 258,
                            "item_id_offset": 37,
                            "quantity_added_offset": 41,
                            "destination_instance_offset": 72,
                            "context_offset": 25,
                            "repeat_stride": 221,
                        }
                    ]
                },
            }
        ),
        encoding="utf-8",
    )
    assert load_opcode_profile(profile).origin_companion_families == ()
    learner = OriginLearner(min_observations=2)
    events = []
    for name in (
        "5004_qty6_4604_qty25_multi.pcapng",
        "7003_qty15_single_hit1.pcapng",
    ):
        events.extend(
            replay_pcap(
                fixture_path(name),
                opcode_profile=profile,
                origin_observer=learner.observe,
            )
        )

    assert [(event.item_id, event.deposit_origin) for event in events] == [
        (5004, "worker"),
        (4604, "worker"),
        (7003, "worker"),
    ]
    (candidate,) = learner.confirmed_candidates
    assert candidate.companion_opcodes == (0x0F7E, 0x0DE1)
    assert candidate.companion_lengths == (60, 23)
    assert candidate.observations == 2
    assert all(
        event.extra["deposit_origin_evidence"]["companion_chain"]["known_family"]
        is False
        for event in events
    )
