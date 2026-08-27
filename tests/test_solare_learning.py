"""Real-capture regressions for ephemeral Solare detail-layout learning."""

from __future__ import annotations

import re
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import cast
from unittest.mock import patch

import pytest

import bdo_toolkit.solare._details as details_module
import bdo_toolkit.solare._detail_learning as learning_module
import bdo_toolkit.solare._result as result_module
from bdo_toolkit.solare import (
    SolareCaptureResult,
    SolareDetectionStatus,
    replay_solare,
)
from bdo_toolkit.solare._discovery import DiscoveredSolareFamily


ROOT = Path(__file__).resolve().parents[1]

# These are the complete real captures installed in the repository/workspace.
# Private exploration captures remain optional so a clean checkout still runs
# the tracked June and July 21 cases.
_COMPLETE_CAPTURE_PATHS = (
    ROOT
    / "docs/captures/fixtures/solare/"
    "leaderboard_full_stream_2026-06-24.pcapng",
    ROOT
    / "tools/solare/captures/"
    "solare_discovery_retry_20260714_3.pcapng",
    ROOT
    / "tools/solare/captures/"
    "solare_live_20260714_145323.pcapng",
    ROOT
    / "tools/solare/captures/"
    "solare_post_patch_20260717_1.pcapng",
    ROOT / "tests/fixtures/solare/leaderboard721.pcapng",
)

_SAME_GEOMETRY_CAPTURE_PAIRS = (
    (
        ROOT
        / "tools/solare/captures/"
        "solare_discovery_retry_20260714_3.pcapng",
        ROOT
        / "tools/solare/captures/"
        "solare_live_20260714_145323.pcapng",
    ),
    (
        ROOT
        / "tools/solare/captures/"
        "solare_post_patch_20260717_1.pcapng",
        ROOT / "tests/fixtures/solare/leaderboard721.pcapng",
    ),
)

_JULY_30_UNKNOWN_LAYOUT_CAPTURE = (
    ROOT
    / "tools/solare/captures/"
    "solare_post_patch_20260725.pcapng"
)

_LEARNED_CAPABILITIES = frozenset(
    {"rankings", "elo", "performance", "raw_extensions"}
)
_LEARNED_OVERALL_CAPABILITIES = (
    _LEARNED_CAPABILITIES | {"aggregate_performance"}
)


@dataclass(frozen=True)
class _ReplayPair:
    registered: SolareCaptureResult
    learned: SolareCaptureResult


def test_july_30_unknown_layout_learns_complete_snapshot() -> None:
    """An installed unseen-geometry capture learns every supported detail."""

    path = _JULY_30_UNKNOWN_LAYOUT_CAPTURE
    if not path.is_file():
        pytest.skip("private July 30 Solare capture is not installed")

    result = replay_solare(path, retain_raw_extensions=True)

    assert result.status is SolareDetectionStatus.COMPLETE
    assert result.snapshot is not None
    snapshot = result.snapshot
    assert len(snapshot.players) == 620
    assert len(snapshot.overall_top_100) == 100
    assert result.evidence.exact_cross_check == 100
    assert result.evidence.candidate_families == (
        (0x0D54, 15_904, 310),
        (0x11CF, 16_127, 50),
    )
    assert result.evidence.health.tcp_gap_resets == 0
    assert result.evidence.health.capture_is_clean
    assert snapshot.class_table_capabilities == _LEARNED_CAPABILITIES
    assert snapshot.overall_capabilities == _LEARNED_OVERALL_CAPABILITIES

    first = snapshot.overall_top_100[0]
    assert first.global_rank == 1
    assert first.name
    assert first.elo is not None and first.elo > 0
    assert first.total_wins is not None
    assert first.total_draws is not None
    assert first.total_losses is not None
    assert first.total_matches == (
        first.total_wins + first.total_draws + first.total_losses
    )
    assert first.total_matches > 0
    assert first.classes_played
    assert all(
        performance.record_is_balanced
        for performance in first.classes_played
    )
    assert result.evidence.rich_layout is not None
    assert result.evidence.rich_layout.detail_layout_id is not None
    assert result.evidence.rich_layout.detail_layout_id.startswith(
        "solare-rich-ephemeral-v1-"
    )
    assert result.evidence.overall_layout is not None
    assert result.evidence.overall_layout.detail_layout_id is not None
    assert result.evidence.overall_layout.detail_layout_id.startswith(
        "solare-overall-ephemeral-v1-"
    )


def _unexpected_learner_call(*_args: object, **_kwargs: object) -> object:
    raise AssertionError("the detail learner must not run on this replay")


def _elo_record_table(
    values: tuple[int, ...],
) -> learning_module._RecordTable:
    family = cast(
        DiscoveredSolareFamily,
        SimpleNamespace(frame_length=8, record_stride=4),
    )
    names = tuple(f"Player{ordinal}" for ordinal in range(len(values)))
    return learning_module._RecordTable(
        family=family,
        rows=tuple(value.to_bytes(4, "little") for value in values),
        names=names,
        ranks=tuple(range(1, len(values) + 1)),
    )


def test_elo_learning_requires_cross_table_value_agreement() -> None:
    rich = _elo_record_table(tuple(range(50_000, 49_900, -1)))
    overall = _elo_record_table(tuple(range(40_000, 39_900, -1)))

    assert learning_module._choose_elo_offsets(rich, overall) == (None, None)

    matching = _elo_record_table(tuple(range(50_000, 49_900, -1)))
    assert learning_module._choose_elo_offsets(rich, matching) == (0, 0)


@pytest.fixture(scope="module")
def profile_hidden_replays() -> dict[Path, _ReplayPair]:
    """Replay installed complete captures with and without registered layouts."""

    installed = tuple(path for path in _COMPLETE_CAPTURE_PATHS if path.is_file())
    if not installed:
        pytest.skip("no complete Solare captures are installed")

    # All listed geometries have registered profiles. Prove the ordinary fast
    # path does not pay for, or accidentally depend upon, the learner.
    registered: dict[Path, SolareCaptureResult] = {}
    with patch.object(
        result_module,
        "learn_unknown_solare_details",
        side_effect=_unexpected_learner_call,
    ) as learner:
        for path in installed:
            registered[path] = replay_solare(
                path,
                retain_raw_extensions=True,
            )
        assert learner.call_count == 0

    # Hide both lookups used by result construction and by the registered
    # decoders. This preserves structural discovery while forcing the exact
    # real packets through the unknown-geometry learner.
    learned: dict[Path, SolareCaptureResult] = {}
    with ExitStack() as stack:
        stack.enter_context(
            patch.object(result_module, "_rich_layout_for", return_value=None)
        )
        stack.enter_context(
            patch.object(result_module, "_overall_layout_for", return_value=None)
        )
        stack.enter_context(
            patch.object(details_module, "_rich_layout_for", return_value=None)
        )
        stack.enter_context(
            patch.object(details_module, "_overall_layout_for", return_value=None)
        )
        for path in installed:
            learned[path] = replay_solare(
                path,
                retain_raw_extensions=True,
            )

    return {
        path: _ReplayPair(registered[path], learned[path])
        for path in installed
    }


@pytest.mark.parametrize(
    "path",
    (_COMPLETE_CAPTURE_PATHS[-1],),
    ids=lambda path: path.stem,
)
def test_profile_hidden_replay_matches_public_fields_and_raw_bytes(
    path: Path,
    profile_hidden_replays: dict[Path, _ReplayPair],
) -> None:
    if path not in profile_hidden_replays:
        pytest.skip("private Solare capture is not installed")

    registered_result = profile_hidden_replays[path].registered
    learned_result = profile_hidden_replays[path].learned
    assert registered_result.status is SolareDetectionStatus.COMPLETE
    assert learned_result.status is SolareDetectionStatus.COMPLETE
    assert registered_result.snapshot is not None
    assert learned_result.snapshot is not None
    registered = registered_result.snapshot
    learned = learned_result.snapshot

    assert registered.observed_at == learned.observed_at
    assert len(registered.players) == len(learned.players) == 620
    assert len(registered.overall_top_100) == len(learned.overall_top_100) == 100

    # Registered fast-path and unknown-layout learning are public-data
    # equivalent, including every opted-in opaque byte.
    assert tuple(
        item.to_dict(include_raw=True) for item in learned.players
    ) == tuple(
        item.to_dict(include_raw=True) for item in registered.players
    )
    assert tuple(
        item.to_dict(include_raw=True) for item in learned.overall_top_100
    ) == tuple(
        item.to_dict(include_raw=True) for item in registered.overall_top_100
    )
    assert learned.snapshot_id == registered.snapshot_id
    assert learned.class_table_capabilities == (
        registered.class_table_capabilities
    )
    assert learned.overall_capabilities == registered.overall_capabilities
    assert learned.class_table_capabilities == _LEARNED_CAPABILITIES
    assert learned.overall_capabilities == _LEARNED_OVERALL_CAPABILITIES
    assert learned.capabilities == _LEARNED_CAPABILITIES


def test_learned_layout_ids_are_geometry_stable_and_content_independent(
    profile_hidden_replays: dict[Path, _ReplayPair],
) -> None:
    compared = 0
    pattern_by_role = {
        "rich": re.compile(r"solare-rich-ephemeral-v1-[0-9a-f]{16}"),
        "overall": re.compile(r"solare-overall-ephemeral-v1-[0-9a-f]{16}"),
    }

    for first_path, second_path in _SAME_GEOMETRY_CAPTURE_PAIRS:
        if (
            first_path not in profile_hidden_replays
            or second_path not in profile_hidden_replays
        ):
            continue
        first = profile_hidden_replays[first_path]
        second = profile_hidden_replays[second_path]
        assert first.learned.snapshot is not None
        assert second.learned.snapshot is not None
        assert first.registered.snapshot is not None
        assert second.registered.snapshot is not None

        # These are independent leaderboard deliveries with differing content.
        assert (
            first.registered.snapshot.snapshot_id
            != second.registered.snapshot.snapshot_id
        )

        for role in ("rich", "overall"):
            first_layout = getattr(first.learned.evidence, f"{role}_layout")
            second_layout = getattr(second.learned.evidence, f"{role}_layout")
            first_registered_layout = getattr(
                first.registered.evidence,
                f"{role}_layout",
            )
            assert first_layout is not None
            assert second_layout is not None
            assert first_registered_layout is not None
            first_id = first_layout.detail_layout_id
            second_id = second_layout.detail_layout_id
            assert first_id is not None
            assert second_id is not None
            assert pattern_by_role[role].fullmatch(first_id)
            assert first_id == second_id
            assert first_id != first_registered_layout.detail_layout_id
        compared += 1

    if compared == 0:
        pytest.skip("no independent same-geometry capture pair is installed")


@pytest.mark.parametrize("unknown_role", ("rich", "overall"))
def test_mixed_registered_and_unknown_tables_keep_independent_details(
    unknown_role: str,
    profile_hidden_replays: dict[Path, _ReplayPair],
) -> None:
    path = ROOT / "tests/fixtures/solare/leaderboard721.pcapng"
    if path not in profile_hidden_replays:
        pytest.skip("the tracked complete Solare capture is not installed")
    registered_result = profile_hidden_replays[path].registered
    assert registered_result.snapshot is not None
    registered = registered_result.snapshot

    lookup_name = (
        "_rich_layout_for" if unknown_role == "rich" else "_overall_layout_for"
    )
    with ExitStack() as stack:
        stack.enter_context(
            patch.object(result_module, lookup_name, return_value=None)
        )
        stack.enter_context(
            patch.object(details_module, lookup_name, return_value=None)
        )
        mixed_result = replay_solare(path, retain_raw_extensions=True)

    assert mixed_result.status is SolareDetectionStatus.COMPLETE
    assert mixed_result.snapshot is not None
    mixed = mixed_result.snapshot
    assert len(mixed.players) == 620
    assert len(mixed.overall_top_100) == 100

    if unknown_role == "rich":
        assert tuple(
            item.to_dict(include_raw=True) for item in mixed.players
        ) == tuple(
            item.to_dict(include_raw=True) for item in registered.players
        )
        assert tuple(
            item.to_dict(include_raw=True) for item in mixed.overall_top_100
        ) == tuple(
            item.to_dict(include_raw=True)
            for item in registered.overall_top_100
        )
        assert (
            mixed.class_table_capabilities
            == registered.class_table_capabilities
        )
        assert mixed.overall_capabilities == registered.overall_capabilities
    else:
        assert tuple(
            item.to_dict(include_raw=True) for item in mixed.players
        ) == tuple(
            item.to_dict(include_raw=True) for item in registered.players
        )
        assert tuple(
            item.to_dict(include_raw=True) for item in mixed.overall_top_100
        ) == tuple(
            item.to_dict(include_raw=True)
            for item in registered.overall_top_100
        )
        assert mixed.class_table_capabilities == (
            registered.class_table_capabilities
        )
        assert mixed.overall_capabilities == registered.overall_capabilities

    assert mixed.snapshot_id == registered.snapshot_id

    rich_by_name = {item.name: item for item in mixed.players}
    shared = tuple(
        item
        for item in mixed.overall_top_100
        if item.name in rich_by_name
    )
    assert len(shared) == 100
    assert all(
        item.elo == rich_by_name[item.name].elo
        for item in shared
    )
