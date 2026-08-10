"""Conservative runtime revalidation for calibrated storage destinations.

Calibration remains authoritative for event decoding.  This module only looks
for strong cross-wrapper evidence that the calibrated destination column has
gone stale; it never selects a replacement column or changes an event.
"""

from __future__ import annotations

from collections import OrderedDict, defaultdict
from dataclasses import dataclass, field
from hashlib import blake2s
from typing import Optional

from ._protocol import FlowKey, storage_destination_candidates


# Four distinct wrappers prevent a short transaction pair from becoming a
# schema verdict.  Three distinct registered destination values distinguish a
# real column from the common ``0x05xx -> 0x0005`` one-byte overlap.  A proven
# column must occur in every candidate-bearing wrapper; there is no majority
# guess and ambiguous evidence remains silent.
_MIN_PROOF_WRAPPERS = 4
_MIN_PROOF_DESTINATIONS = 3

# One character-load hydration currently needs fewer than 80 distinct storage
# wrappers.  These limits retain a complete observed cohort with headroom while
# bounding adversarial/reconnect state to small fixed metadata (not packets).
_MAX_COHORTS = 64
_MAX_WRAPPERS_PER_COHORT = 128


@dataclass(frozen=True)
class StorageDestinationSchemaMismatch:
    """Strong evidence that a profile's destination column is stale."""

    opcode: int
    configured_offset: int
    observed_offset: int
    wrapper_count: int
    distinct_destinations: int


@dataclass
class _DestinationCohort:
    wrappers: OrderedDict[bytes, tuple[tuple[int, int], ...]] = field(
        default_factory=OrderedDict
    )
    mismatch_reported: bool = False


class StorageDestinationValidator:
    """Revalidate one destination column across bounded connection cohorts.

    Evidence is isolated by TCP four-tuple generation and opcode.  Identical
    wrappers are counted once, and only registered destination candidates
    before the first item record participate.  Unknown-town-only wrappers are
    retained for deduplication but do not vote for any column.
    """

    def __init__(self) -> None:
        self._cohorts: OrderedDict[
            tuple[FlowKey, int, int, int, int], _DestinationCohort
        ] = OrderedDict()

    def observe(
        self,
        *,
        flow: FlowKey,
        flow_generation: int,
        opcode: int,
        message: bytes,
        first_item_offset: int,
        configured_offset: Optional[int],
    ) -> Optional[StorageDestinationSchemaMismatch]:
        """Return a mismatch only after one alternate column is proven."""

        if configured_offset is None or first_item_offset <= 5:
            return None

        # One opcode may legitimately select more than one structural layout.
        # Destination evidence is comparable only when both the calibrated
        # destination column and the first-record boundary are the same.
        # Without this identity, a correct second layout can inherit the
        # first layout's candidate column and be diagnosed as stale.
        key = (
            flow,
            flow_generation,
            opcode,
            first_item_offset,
            configured_offset,
        )
        cohort = self._cohorts.pop(key, None)
        if cohort is None:
            cohort = _DestinationCohort()
        self._cohorts[key] = cohort
        while len(self._cohorts) > _MAX_COHORTS:
            self._cohorts.popitem(last=False)

        # A compact cryptographic fingerprint avoids retaining private packet
        # contents merely to suppress the per-record callbacks of one wrapper.
        fingerprint = blake2s(message, digest_size=16).digest()
        if fingerprint in cohort.wrappers:
            return None

        cohort.wrappers[fingerprint] = storage_destination_candidates(
            message,
            before_offset=first_item_offset,
        )
        while len(cohort.wrappers) > _MAX_WRAPPERS_PER_COHORT:
            cohort.wrappers.popitem(last=False)

        if cohort.mismatch_reported:
            return None

        candidate_wrappers = tuple(
            candidates for candidates in cohort.wrappers.values() if candidates
        )
        if len(candidate_wrappers) < _MIN_PROOF_WRAPPERS:
            return None

        support: dict[int, int] = defaultdict(int)
        destination_ids: dict[int, set[int]] = defaultdict(set)
        for candidates in candidate_wrappers:
            for offset, storage_id in candidates:
                support[offset] += 1
                destination_ids[offset].add(storage_id)

        proven_offsets = tuple(
            offset
            for offset, count in support.items()
            if count == len(candidate_wrappers)
            and len(destination_ids[offset]) >= _MIN_PROOF_DESTINATIONS
        )
        if len(proven_offsets) != 1:
            return None
        observed_offset = proven_offsets[0]
        if observed_offset == configured_offset:
            return None

        cohort.mismatch_reported = True
        return StorageDestinationSchemaMismatch(
            opcode=opcode,
            configured_offset=configured_offset,
            observed_offset=observed_offset,
            wrapper_count=len(candidate_wrappers),
            distinct_destinations=len(destination_ids[observed_offset]),
        )

    def close_flow(self, flow: FlowKey) -> None:
        """Discard every generation retained for a closed TCP four-tuple."""

        for key in tuple(self._cohorts):
            if key[0] == flow:
                del self._cohorts[key]

    @property
    def cohort_count(self) -> int:
        """Number of retained flow-generation/opcode cohorts (for health tests)."""

        return len(self._cohorts)

    @property
    def retained_wrapper_count(self) -> int:
        """Number of compact wrapper fingerprints currently retained."""

        return sum(len(cohort.wrappers) for cohort in self._cohorts.values())
