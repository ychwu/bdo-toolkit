"""Structural origin-family learning, persistence, and promotion."""

from __future__ import annotations

import json
from dataclasses import replace

import pytest

from fixture_paths import fixture_path, has_fixture_pcaps
from bdo_toolkit import (
    OriginLearner,
    OriginLearningLimitError,
    load_opcode_profile,
    promote_origin_candidates,
    replay_pcap,
)
from bdo_toolkit._protocol import FlowKey
from bdo_toolkit.origin_learning import (
    CompanionObservation,
    discover_companion_observation,
)

FLOW = FlowKey("203.0.113.1", 8889, "198.51.100.2", 50000)
requires_fixtures = pytest.mark.skipif(
    not has_fixture_pcaps(),
    reason="local pcap fixtures not present (private captures)",
)


def _observation(
    *, sequence: int, timestamp: float, token: str
) -> CompanionObservation:
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


def _message(opcode, length, token=None, token_offset=7):
    message = bytearray(length)
    message[0:2] = length.to_bytes(2, "little")
    message[3:5] = opcode.to_bytes(2, "little")
    if token is not None:
        message[token_offset : token_offset + 8] = token
    return bytes(message)


def _discover(delta, first, second, prefix_end=37):
    return discover_companion_observation(
        delta_message=delta,
        first_message=first,
        second_message=second,
        timestamp=1000.0,
        flow=FLOW,
        stream_sequence=1000,
        delta_prefix_end=prefix_end,
    )


def test_discovery_only_accepts_high_entropy_tokens_before_first_record():
    informative = bytes.fromhex("07feabbfc91b8e00")
    low_diversity = bytes.fromhex("0001020304000102")
    first = _message(0x1A59, 64, informative, 20)
    second = _message(0x155E, 30, informative, 5)

    assert _discover(_message(0x126D, 80, informative, 7), first, second)
    assert not _discover(
        _message(0x126D, 80, low_diversity, 7),
        _message(0x1A59, 64, low_diversity, 20),
        _message(0x155E, 30, low_diversity, 5),
    )
    assert not _discover(_message(0x126D, 80, informative, 45), first, second)


def test_discovery_rejects_storage_and_repeated_opcode_companions():
    token = bytes.fromhex("07feabbfc91b8e00")
    delta = _message(0x126D, 80, token, 7)

    assert not _discover(
        delta,
        _message(0x126D, 64, token, 20),
        _message(0x155E, 30, token, 5),
    )
    assert not _discover(
        delta,
        _message(0x17E8, 42, token, 20),
        _message(0x17E8, 42, token, 20),
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


def test_learner_summary_reports_empty_and_confirmed_families():
    learner = OriginLearner(min_observations=2)

    empty = learner.summary()
    assert "observed 0 origin companion family/families" in empty
    assert "no origin companion families observed" in empty

    learner.observe(_observation(sequence=1000, timestamp=1000.0, token="a" * 16))
    learner.observe(_observation(sequence=2000, timestamp=2000.0, token="b" * 16))

    text = learner.summary()
    assert "1 confirmed for promotion" in text
    assert "threshold: 2 observation(s)" in text
    assert "confirmed: delta=0x0D7E" in text
    assert "companions=0x0F7E -> 0x0DE1" in text
    assert "lengths=(60, 23)" in text
    assert "observations=2" in text
    assert "distinct_tokens=2" in text


def test_learner_observation_limit_fails_before_retaining_excess():
    learner = OriginLearner(max_observations=1)
    first = _observation(sequence=1000, timestamp=1000.0, token="a" * 16)
    second = _observation(sequence=2000, timestamp=2000.0, token="b" * 16)

    assert learner.observe(first).observations == 1
    # Replaying retained evidence remains an idempotent no-op at the limit.
    assert learner.observe(first).observations == 1
    with pytest.raises(OriginLearningLimitError, match="observation limit"):
        learner.observe(second)

    (candidate,) = learner.candidates
    assert candidate.observations == 1


def test_learner_candidate_limit_bounds_distinct_families():
    learner = OriginLearner(max_candidates=1)
    first = _observation(sequence=1000, timestamp=1000.0, token="a" * 16)
    second_family = replace(
        _observation(sequence=2000, timestamp=2000.0, token="b" * 16),
        companion_opcodes=(0x2222, 0x3333),
    )

    learner.observe(first)
    with pytest.raises(OriginLearningLimitError, match="candidate-family limit"):
        learner.observe(second_family)

    assert len(learner.candidates) == 1


def test_learner_persists_limits_and_rejects_smaller_load_budget(tmp_path):
    learner = OriginLearner(max_candidates=3, max_observations=2)
    learner.observe(_observation(sequence=1000, timestamp=1000.0, token="a" * 16))
    learner.observe(_observation(sequence=2000, timestamp=2000.0, token="b" * 16))
    path = learner.save(tmp_path / "origin-candidates.json")

    loaded = OriginLearner.load(path)
    assert loaded.max_candidates == 3
    assert loaded.max_observations == 2
    with pytest.raises(OriginLearningLimitError, match="observation limit"):
        OriginLearner.load(path, max_observations=1)


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
                                "record_count_offset": 35,
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
        'storage--worker-multi-item-deposit--5b8dec558b',
        'storage--worker-deposit-first--44e39f0531',
    ):
        events.extend(
            replay_pcap(
                fixture_path(name),
                opcode_profile=profile,
                origin_observer=learner.observe,
            )
        )

    assert [(event.item_id, event.source) for event in events] == [
        (5004, "Worker Production"),
        (4604, "Worker Production"),
        (7003, "Worker Production"),
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
