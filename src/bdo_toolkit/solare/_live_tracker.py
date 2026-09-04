"""Structured progress tracking for opcode-agnostic Solare capture."""

from __future__ import annotations

import time
from collections import Counter, deque
from collections.abc import Callable
from dataclasses import replace
from typing import Deque, Optional

from bdo_toolkit._protocol import BDOFrame

from ._constants import (
    DISCOVERY_MAX_FRAME_LENGTH,
    DISCOVERY_MIN_FAMILY_FRAMES,
    DISCOVERY_MIN_FRAME_LENGTH,
    DISCOVERY_MIN_RICH_RECORDS,
    DISCOVERY_RETENTION_MAX_BYTES,
    DISCOVERY_RETENTION_MAX_FRAMES,
    LIVE_CANDIDATE_IDLE_SECONDS,
)
from ._discovery import (
    _DiscoveryAnalysisCache,
    DiscoveredSolareFamily,
    SolareDiscoveryResult,
    _family_key,
    _rank_reset_starts,
    discover_solare,
)
from .models import SolareUpdate, SolareUpdateKind


def _discovery_score(result: SolareDiscoveryResult) -> tuple[int, int, int]:
    ranked = result.rich or result.ranked_candidate
    partial = result.overall or result.partial_overall
    if result.confirmed:
        stage = 5
    elif result.rich is not None and result.partial_overall is not None:
        stage = 4
    elif result.rich is not None:
        stage = 3
    elif ranked is not None and partial is not None:
        stage = 2
    elif ranked is not None:
        stage = 1
    elif result.menu_context is not None:
        stage = 0
    else:
        stage = -1
    return (
        stage,
        ranked.record_count if ranked is not None else 0,
        partial.record_count if partial is not None else 0,
    )


def _compact_discovery(result: SolareDiscoveryResult) -> SolareDiscoveryResult:
    """Drop raw frame ownership while retaining compact structural evidence."""

    def compact(
        family: Optional[DiscoveredSolareFamily],
    ) -> Optional[DiscoveredSolareFamily]:
        if family is None:
            return None
        return replace(family, frames=())

    return replace(
        result,
        rich=compact(result.rich),
        overall=compact(result.overall),
        ranked_candidate=compact(result.ranked_candidate),
        partial_overall=compact(result.partial_overall),
    )


class LiveSolareDiscoveryTracker:
    """Refresh structural discovery at useful milestones and emit updates."""

    def __init__(self, emit: Callable[[SolareUpdate], None]) -> None:
        self._emit = emit
        self._frames: Deque[BDOFrame] = deque()
        self._retained_bytes = 0
        self._peak_retained_frame_count = 0
        self._peak_retained_bytes = 0
        self._evicted_frame_count = 0
        self._evicted_bytes = 0
        self._observed_frame_count = 0
        self._rollover_warned = False
        self._analysis_cache = _DiscoveryAnalysisCache()
        self._family_counts: Counter[tuple[object, int, int, int]] = Counter()
        self._retained_family_counts: Counter[
            tuple[object, int, int, int]
        ] = Counter()
        self._family_recent: dict[
            tuple[object, int, int, int], Deque[BDOFrame]
        ] = {}
        self._family_targets: dict[tuple[object, int, int, int], set[int]] = {}
        self._announced_menu = False
        self._announced_ranked_players = 300
        self._announced_rich: Optional[tuple[object, ...]] = None
        self._announced_cross_check = 0
        self._announced_confirmed = False
        self._confirmed_frames: Optional[tuple[BDOFrame, ...]] = None
        self._dirty = False
        self._tail_finalized = False
        self._last_candidate_activity_at: Optional[float] = None
        self.result = SolareDiscoveryResult(0, ())
        self._best_result = self.result

    def observe(self, frame: BDOFrame) -> None:
        if self._confirmed_frames is not None:
            return
        if not (
            frame.flag == 0
            and DISCOVERY_MIN_FRAME_LENGTH
            <= frame.length
            <= DISCOVERY_MAX_FRAME_LENGTH
        ):
            return

        self._last_candidate_activity_at = time.monotonic()
        rolled_over = self._make_room_for(frame)
        if self.complete:
            return
        self._frames.append(frame)
        self._retained_bytes += frame.length
        self._observed_frame_count += 1
        self._update_peaks()
        self._dirty = True
        self._tail_finalized = False
        family_key = _family_key(frame)
        self._family_counts[family_key] += 1
        self._retained_family_counts[family_key] += 1
        family_count = self._family_counts[family_key]

        recent = self._family_recent.setdefault(family_key, deque(maxlen=10))
        recent.append(frame)
        if len(recent) == 10 and _rank_reset_starts(tuple(recent)) == (0,):
            first_count = family_count - 9
            targets = self._family_targets.setdefault(family_key, set())
            targets.update(
                {
                    first_count + 49,
                    first_count + 199,
                    first_count + 249,
                    first_count + 299,
                    first_count + 309,
                }
            )
        reset_interval = family_count in self._family_targets.get(
            family_key,
            (),
        )
        if reset_interval:
            self._family_targets[family_key].discard(family_count)

        ranked_known = self.result.ranked_candidate is not None
        rich_interval = family_count in {
            DISCOVERY_MIN_RICH_RECORDS // 2,
            250,
            300,
            310,
        }
        related_interval = (
            ranked_known
            and family_count >= DISCOVERY_MIN_FAMILY_FRAMES
            and family_count in {10, 50}
        )
        if (
            family_count == 24
            or rich_interval
            or related_interval
            or reset_interval
        ) and not rolled_over:
            self.refresh(end_of_burst=False)

    @property
    def complete(self) -> bool:
        return self._confirmed_frames is not None

    @property
    def confirmed_frames(self) -> Optional[tuple[BDOFrame, ...]]:
        """Exact first structurally confirmed window, latched permanently."""

        return self._confirmed_frames

    @property
    def retained_frames(self) -> tuple[BDOFrame, ...]:
        """Current bounded discovery input, or the exact confirmed window."""

        return tuple(self._frames)

    @property
    def retained_frame_count(self) -> int:
        return len(self._frames)

    @property
    def retained_bytes(self) -> int:
        return self._retained_bytes

    @property
    def peak_retained_frame_count(self) -> int:
        return self._peak_retained_frame_count

    @property
    def peak_retained_bytes(self) -> int:
        return self._peak_retained_bytes

    @property
    def evicted_frame_count(self) -> int:
        return self._evicted_frame_count

    @property
    def evicted_bytes(self) -> int:
        return self._evicted_bytes

    @property
    def observed_frame_count(self) -> int:
        return self._observed_frame_count

    @property
    def history_rolled_over(self) -> bool:
        return self._rollover_warned

    def refresh(
        self,
        *,
        end_of_burst: bool = True,
    ) -> SolareDiscoveryResult:
        if self._confirmed_frames is not None:
            return self.result
        if not self._dirty and (not end_of_burst or self._tail_finalized):
            return self.result
        candidate = discover_solare(
            self._frames,
            allow_trailing_overall=end_of_burst,
            _analysis_cache=self._analysis_cache,
        )
        candidate = replace(
            candidate,
            scanned_frames=self._observed_frame_count,
        )
        self._dirty = False
        self._tail_finalized = end_of_burst
        if candidate.confirmed:
            self._analysis_cache.clear()
            self.result = candidate
            assert candidate.rich is not None
            assert candidate.overall is not None
            selected: list[BDOFrame] = []
            seen: set[int] = set()
            for frame in (*candidate.rich.frames, *candidate.overall.frames):
                if id(frame) in seen:
                    continue
                seen.add(id(frame))
                selected.append(frame)
            for frame in self._frames:
                if id(frame) not in seen:
                    self._evicted_frame_count += 1
                    self._evicted_bytes += frame.length
            self._confirmed_frames = tuple(selected)
            self._frames = deque(self._confirmed_frames)
            self._retained_bytes = sum(
                frame.length for frame in self._confirmed_frames
            )
            # The selected discovery result and ``_frames`` are the only
            # intentional owners after confirmation.  The rolling reset
            # indexes are useful only while acquiring and must not keep
            # evicted or unrelated packet buffers alive behind the public
            # retained-frame/byte accounting.
            self._family_counts.clear()
            self._retained_family_counts.clear()
            self._family_recent.clear()
            self._family_targets.clear()
        else:
            compact = _compact_discovery(candidate)
            if _discovery_score(compact) >= _discovery_score(self._best_result):
                self._best_result = compact
            self.result = replace(
                self._best_result,
                scanned_frames=self._observed_frame_count,
            )
        self._announce_progress()
        return self.result

    def service_candidate_idle(self, now: float) -> bool:
        """Finalize a quiet candidate tail despite unrelated game traffic.

        Returns whether this call changed the tracker from provisional to
        structurally complete. The ordinary discovery checks—including rich-
        prefix rejection—remain authoritative at this boundary.
        """

        last_candidate_activity_at = self._last_candidate_activity_at
        if (
            self.complete
            or self._tail_finalized
            or last_candidate_activity_at is None
            or now < last_candidate_activity_at + LIVE_CANDIDATE_IDLE_SECONDS
        ):
            return False
        self.refresh()
        return self.complete

    def _make_room_for(self, frame: BDOFrame) -> bool:
        if (
            len(self._frames) < DISCOVERY_RETENTION_MAX_FRAMES
            and self._retained_bytes + frame.length
            <= DISCOVERY_RETENTION_MAX_BYTES
        ):
            return False

        # Evaluate the complete retained window before making room.  The
        # low-water marks retain more than the largest structural snapshot, so
        # the incoming frame can still complete a candidate without ownership
        # ever exceeding the advertised hard limits.
        self.refresh(end_of_burst=False)
        if self.complete:
            return True

        target_frames = DISCOVERY_RETENTION_MAX_FRAMES - max(
            64,
            DISCOVERY_RETENTION_MAX_FRAMES // 8,
        )
        target_bytes = (DISCOVERY_RETENTION_MAX_BYTES * 7) // 8
        self._analysis_cache.clear()
        while self._frames and (
            len(self._frames) >= target_frames
            or self._retained_bytes + frame.length > target_bytes
        ):
            evicted = self._frames.popleft()
            self._retained_bytes -= evicted.length
            self._evicted_frame_count += 1
            self._evicted_bytes += evicted.length
            key = _family_key(evicted)
            self._retained_family_counts[key] -= 1
            recent = self._family_recent.get(key)
            if recent is not None and any(item is evicted for item in recent):
                kept = (item for item in recent if item is not evicted)
                replacement: Deque[BDOFrame] = deque(kept, maxlen=10)
                if replacement:
                    self._family_recent[key] = replacement
                else:
                    self._family_recent.pop(key, None)
            if self._retained_family_counts[key] <= 0:
                self._retained_family_counts.pop(key, None)
                self._family_counts.pop(key, None)
                self._family_recent.pop(key, None)
                self._family_targets.pop(key, None)

        if not self._rollover_warned:
            self._rollover_warned = True
            self._emit(
                SolareUpdate(
                    kind=SolareUpdateKind.WARNING,
                    message=(
                        "Solare discovery history reached its bounded retention "
                        "window; older candidates were discarded after evaluation"
                    ),
                )
            )
        self._update_peaks()
        return True

    def _update_peaks(self) -> None:
        self._peak_retained_frame_count = max(
            self._peak_retained_frame_count,
            len(self._frames),
        )
        self._peak_retained_bytes = max(
            self._peak_retained_bytes,
            self._retained_bytes,
        )

    def _announce_progress(self) -> None:
        result = self.result
        menu = result.menu_context
        if menu is not None and not self._announced_menu:
            self._announced_menu = True
            self._emit(
                SolareUpdate(
                    kind=SolareUpdateKind.MENU_CONTEXT,
                    message=(
                        "Solare menu/history-like traffic was observed, but no "
                        "leaderboard load was sent; if the Leaderboard was "
                        "already opened, restart the game and retry capture "
                        "before opening it"
                    ),
                )
            )

        ranked = result.ranked_candidate
        if (
            not result.confirmed
            and result.partial_overall is None
            and ranked is not None
            and ranked.record_count >= self._announced_ranked_players + 100
        ):
            self._announced_ranked_players = (
                ranked.record_count // 100
            ) * 100
            self._emit(
                SolareUpdate(
                    kind=SolareUpdateKind.RANKED_PROGRESS,
                    message=(
                        f"{ranked.record_count} unique ranked players recovered; "
                        "waiting for class balance and the top-100 cross-check"
                    ),
                    ranked_players=ranked.record_count,
                )
            )

        rich = result.rich
        if rich is not None:
            identity = (
                rich.flow,
                rich.frame_length,
                rich.record_stride,
                rich.name_offset,
                rich.rank_offset,
                rich.class_offset,
            )
            if identity != self._announced_rich:
                self._announced_rich = identity
                self._emit(
                    SolareUpdate(
                        kind=SolareUpdateKind.RICH_CANDIDATE,
                        message=(
                            f"structurally valid rich table: {rich.record_count} "
                            f"players across {len(rich.class_counts)} class groups"
                        ),
                        ranked_players=rich.record_count,
                    )
                )

        partial = result.partial_overall
        if (
            not result.confirmed
            and ranked is not None
            and partial is not None
            and self._announced_cross_check == 0
        ):
            self._announced_cross_check = result.exact_cross_check
            self._emit(
                SolareUpdate(
                    kind=SolareUpdateKind.CROSS_CHECK,
                    message=(
                        f"{result.exact_cross_check}/{partial.record_count} shared "
                        "overall rank/name pairs match; continuing for 100 "
                        "overall entries"
                    ),
                    ranked_players=ranked.record_count,
                    overall_players=partial.record_count,
                    exact_cross_check=result.exact_cross_check,
                )
            )

        if result.confirmed and not self._announced_confirmed:
            self._announced_confirmed = True
            assert result.rich is not None
            assert result.overall is not None
            self._emit(
                SolareUpdate(
                    kind=SolareUpdateKind.SNAPSHOT_CONFIRMED,
                    message=(
                        "opcode-agnostic Arena of Solare leaderboard confirmed"
                    ),
                    ranked_players=result.rich.record_count,
                    overall_players=result.overall.record_count,
                    exact_cross_check=result.exact_cross_check,
                )
            )
