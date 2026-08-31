"""Structural worker-companion discovery and explicit candidate persistence."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from threading import Lock
from typing import Any, Iterable, Optional

from ._protocol import FlowKey, MAX_TARGET_MESSAGE_LENGTH
from .profiles import ProfileError, load_opcode_profile

TOKEN_WIDTH = 8
# Five-byte diversity was just permissive enough to treat an initial-load
# timestamp as a transaction token.  A worker token must now contain more than
# five distinct byte values.
MIN_TOKEN_UNIQUE_BYTES = 6
CANDIDATE_FORMAT_VERSION = 1
COMPANION_DETECTION = "shared-token-chain-v1"
DEFAULT_ORIGIN_LEARNING_MAX_CANDIDATES = 256
DEFAULT_ORIGIN_LEARNING_MAX_OBSERVATIONS = 10_000


class OriginLearningLimitError(RuntimeError):
    """Raised before an origin learner would exceed its retention budget."""

    def __init__(self, resource: str, limit: int) -> None:
        self.resource = resource
        self.limit = limit
        super().__init__(
            f"origin learning {resource} limit reached ({limit}); "
            "save the current candidates and start a new learner or raise "
            "the explicit limit"
        )


def _opcode_text(opcode: int) -> str:
    return f"0x{opcode:04X}"


def _utc_text(timestamp: Optional[float] = None) -> str:
    value = (
        dt.datetime.fromtimestamp(timestamp, tz=dt.UTC)
        if timestamp is not None
        else dt.datetime.now(tz=dt.UTC)
    )
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")


def _parse_opcode(value: object, location: str) -> int:
    if isinstance(value, bool):
        raise ProfileError(f"{location} must be a uint16")
    if isinstance(value, int):
        opcode = value
    elif isinstance(value, str):
        try:
            opcode = int(value, 16 if value.lower().startswith("0x") else 10)
        except ValueError as exc:
            raise ProfileError(f"{location} must be a uint16") from exc
    else:
        raise ProfileError(f"{location} must be a uint16")
    if not 0 <= opcode <= 0xFFFF:
        raise ProfileError(f"{location} must be a uint16")
    return opcode


def _find_all(message: bytes, token: bytes) -> tuple[int, ...]:
    positions: list[int] = []
    search_at = 5  # Never correlate against length/flag/opcode header bytes.
    while True:
        offset = message.find(token, search_at)
        if offset < 0:
            break
        positions.append(offset)
        search_at = offset + 1
    return tuple(positions)


def _shared_token(
    delta_message: bytes,
    first_message: bytes,
    second_message: bytes,
    delta_prefix_end: int,
) -> Optional[tuple[bytes, tuple[int, int, int]]]:
    """Return the strongest informative token shared by three frames.

    ``delta_prefix_end`` is the decoded first-record boundary.  Restricting
    candidates to that prefix prevents item instances, storage instances, and
    record timestamps from masquerading as operation tokens.
    """
    candidates: list[tuple[int, int, bytes, tuple[int, int, int]]] = []
    prefix_end = min(delta_prefix_end, len(delta_message))
    for delta_offset in range(5, prefix_end - TOKEN_WIDTH + 1):
        token = delta_message[delta_offset : delta_offset + TOKEN_WIDTH]
        unique_bytes = len(set(token))
        if unique_bytes < MIN_TOKEN_UNIQUE_BYTES:
            continue
        first_positions = _find_all(first_message, token)
        if not first_positions:
            continue
        second_positions = _find_all(second_message, token)
        if not second_positions:
            continue
        offsets = (delta_offset, first_positions[0], second_positions[0])
        # Prefer higher-entropy tokens, then the earliest delta-prefix token.
        candidates.append((unique_bytes, -delta_offset, token, offsets))
    if not candidates:
        return None
    _, _, token, offsets = max(candidates)
    return token, offsets


@dataclass(frozen=True)
class CompanionObservation:
    """One structurally correlated storage-delta companion chain."""

    timestamp: float
    flow: FlowKey
    stream_sequence: Optional[int]
    delta_opcode: int
    delta_length: int
    companion_opcodes: tuple[int, int]
    companion_lengths: tuple[int, int]
    token_digest: str
    token_offsets: tuple[int, int, int]

    @property
    def family_key(self) -> tuple[int, int, int, int, int]:
        return (
            self.delta_opcode,
            self.companion_opcodes[0],
            self.companion_opcodes[1],
            self.companion_lengths[0],
            self.companion_lengths[1],
        )

    @property
    def observation_id(self) -> str:
        identity = (
            f"{self.flow}|{self.stream_sequence}|{self.timestamp:.9f}|"
            f"{self.family_key}|{self.token_digest}"
        ).encode("utf-8")
        return hashlib.blake2b(identity, digest_size=16).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "detection": COMPANION_DETECTION,
            "delta_opcode": _opcode_text(self.delta_opcode),
            "delta_length": self.delta_length,
            "companion_opcodes": [
                _opcode_text(opcode) for opcode in self.companion_opcodes
            ],
            "companion_lengths": list(self.companion_lengths),
            "shared_token_digest": self.token_digest,
            "token_offsets": {
                "delta": self.token_offsets[0],
                "first_companion": self.token_offsets[1],
                "second_companion": self.token_offsets[2],
            },
            "observed_at": _utc_text(self.timestamp),
        }


def discover_companion_observation(
    *,
    delta_message: bytes,
    first_message: bytes,
    second_message: bytes,
    timestamp: float,
    flow: FlowKey,
    stream_sequence: Optional[int],
    delta_prefix_end: int,
) -> Optional[CompanionObservation]:
    """Recognize a three-frame worker chain without trusting opcode values."""
    for label, message in (
        ("delta", delta_message),
        ("first companion", first_message),
        ("second companion", second_message),
    ):
        if not 5 <= len(message) <= MAX_TARGET_MESSAGE_LENGTH:
            return None
        if int.from_bytes(message[0:2], "little") != len(message):
            return None
    if (
        isinstance(delta_prefix_end, bool)
        or not isinstance(delta_prefix_end, int)
        or not 5 + TOKEN_WIDTH <= delta_prefix_end <= len(delta_message)
    ):
        return None
    delta_opcode = int.from_bytes(delta_message[3:5], "little")
    first_opcode = int.from_bytes(first_message[3:5], "little")
    second_opcode = int.from_bytes(second_message[3:5], "little")
    # A second storage delta is a boundary, not a worker companion.  The two
    # observed worker companion roles are also distinct message families;
    # rejecting a repeated ambient opcode removes a known false correlation.
    if (
        first_opcode == delta_opcode
        or second_opcode == delta_opcode
        or first_opcode == second_opcode
    ):
        return None
    shared = _shared_token(
        delta_message,
        first_message,
        second_message,
        delta_prefix_end,
    )
    if shared is None:
        return None
    token, offsets = shared
    return CompanionObservation(
        timestamp=timestamp,
        flow=flow,
        stream_sequence=stream_sequence,
        delta_opcode=delta_opcode,
        delta_length=len(delta_message),
        companion_opcodes=(
            first_opcode,
            second_opcode,
        ),
        companion_lengths=(len(first_message), len(second_message)),
        token_digest=hashlib.blake2b(token, digest_size=8).hexdigest(),
        token_offsets=offsets,
    )


@dataclass(frozen=True)
class OriginCompanionCandidate:
    """Aggregated observations for one delta/companion opcode family."""

    delta_opcode: int
    companion_opcodes: tuple[int, int]
    companion_lengths: tuple[int, int]
    observations: int
    distinct_tokens: int
    delta_lengths: tuple[int, ...]
    delta_token_offsets: tuple[int, ...]
    first_token_offsets: tuple[int, ...]
    second_token_offsets: tuple[int, ...]
    first_seen: str
    last_seen: str
    observation_ids: tuple[str, ...] = field(repr=False)
    token_digests: tuple[str, ...] = field(repr=False)

    @property
    def family_key(self) -> tuple[int, int, int, int, int]:
        return (
            self.delta_opcode,
            self.companion_opcodes[0],
            self.companion_opcodes[1],
            self.companion_lengths[0],
            self.companion_lengths[1],
        )

    def confirmed(self, min_observations: int) -> bool:
        return self.observations >= min_observations

    def to_dict(self, min_observations: int) -> dict[str, Any]:
        return {
            "status": (
                "confirmed" if self.confirmed(min_observations) else "candidate"
            ),
            "detection": COMPANION_DETECTION,
            "delta_opcode": _opcode_text(self.delta_opcode),
            "companion_opcodes": [
                _opcode_text(opcode) for opcode in self.companion_opcodes
            ],
            "companion_lengths": list(self.companion_lengths),
            "observations": self.observations,
            "distinct_tokens": self.distinct_tokens,
            "delta_lengths": list(self.delta_lengths),
            "token_offsets": {
                "delta": list(self.delta_token_offsets),
                "first_companion": list(self.first_token_offsets),
                "second_companion": list(self.second_token_offsets),
            },
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            # Opaque IDs prevent the same pcap from inflating the count on rerun.
            "observation_ids": list(self.observation_ids),
            "token_digests": list(self.token_digests),
        }


@dataclass
class _CandidateState:
    delta_opcode: int
    companion_opcodes: tuple[int, int]
    companion_lengths: tuple[int, int]
    observation_ids: set[str] = field(default_factory=set)
    token_digests: set[str] = field(default_factory=set)
    delta_lengths: set[int] = field(default_factory=set)
    delta_offsets: set[int] = field(default_factory=set)
    first_offsets: set[int] = field(default_factory=set)
    second_offsets: set[int] = field(default_factory=set)
    first_timestamp: Optional[float] = None
    last_timestamp: Optional[float] = None
    first_seen_text: Optional[str] = None
    last_seen_text: Optional[str] = None

    def add(self, observation: CompanionObservation) -> bool:
        observation_id = observation.observation_id
        if observation_id in self.observation_ids:
            return False
        self.observation_ids.add(observation_id)
        self.token_digests.add(observation.token_digest)
        self.delta_lengths.add(observation.delta_length)
        self.delta_offsets.add(observation.token_offsets[0])
        self.first_offsets.add(observation.token_offsets[1])
        self.second_offsets.add(observation.token_offsets[2])
        if self.first_timestamp is None or observation.timestamp < self.first_timestamp:
            self.first_timestamp = observation.timestamp
        if self.last_timestamp is None or observation.timestamp > self.last_timestamp:
            self.last_timestamp = observation.timestamp
        return True

    def snapshot(self) -> OriginCompanionCandidate:
        first_values = [
            value
            for value in (
                self.first_seen_text,
                (
                    _utc_text(self.first_timestamp)
                    if self.first_timestamp is not None
                    else None
                ),
            )
            if value is not None
        ]
        first_seen = min(first_values) if first_values else _utc_text()
        last_values = [
            value
            for value in (
                self.last_seen_text,
                (
                    _utc_text(self.last_timestamp)
                    if self.last_timestamp is not None
                    else None
                ),
            )
            if value is not None
        ]
        last_seen = max(last_values) if last_values else first_seen
        return OriginCompanionCandidate(
            delta_opcode=self.delta_opcode,
            companion_opcodes=self.companion_opcodes,
            companion_lengths=self.companion_lengths,
            observations=len(self.observation_ids),
            distinct_tokens=len(self.token_digests),
            delta_lengths=tuple(sorted(self.delta_lengths)),
            delta_token_offsets=tuple(sorted(self.delta_offsets)),
            first_token_offsets=tuple(sorted(self.first_offsets)),
            second_token_offsets=tuple(sorted(self.second_offsets)),
            first_seen=first_seen,
            last_seen=last_seen,
            observation_ids=tuple(sorted(self.observation_ids)),
            token_digests=tuple(sorted(self.token_digests)),
        )


class OriginLearner:
    """Thread-safe in-memory aggregator for structurally discovered families."""

    def __init__(
        self,
        min_observations: int = 2,
        *,
        max_candidates: int = DEFAULT_ORIGIN_LEARNING_MAX_CANDIDATES,
        max_observations: int = DEFAULT_ORIGIN_LEARNING_MAX_OBSERVATIONS,
    ) -> None:
        if (
            isinstance(min_observations, bool)
            or not isinstance(min_observations, int)
            or min_observations <= 0
        ):
            raise ValueError("min_observations must be a positive integer")
        for name, value in (
            ("max_candidates", max_candidates),
            ("max_observations", max_observations),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        self.min_observations = min_observations
        self.max_candidates = max_candidates
        self.max_observations = max_observations
        self._states: dict[tuple[int, int, int, int, int], _CandidateState] = {}
        self._observation_count = 0
        self._lock = Lock()

    @classmethod
    def load(
        cls,
        path: str | Path,
        *,
        min_observations: Optional[int] = None,
        max_candidates: Optional[int] = None,
        max_observations: Optional[int] = None,
    ) -> "OriginLearner":
        candidate_path = Path(path)
        if not candidate_path.exists():
            return cls(
                2 if min_observations is None else min_observations,
                max_candidates=(
                    max_candidates
                    if max_candidates is not None
                    else DEFAULT_ORIGIN_LEARNING_MAX_CANDIDATES
                ),
                max_observations=(
                    max_observations
                    if max_observations is not None
                    else DEFAULT_ORIGIN_LEARNING_MAX_OBSERVATIONS
                ),
            )
        try:
            data = json.loads(candidate_path.read_text(encoding="utf-8-sig"))
        except (json.JSONDecodeError, UnicodeError) as exc:
            raise ProfileError(
                f"Could not parse origin candidates JSON {candidate_path}: {exc}"
            ) from exc
        if not isinstance(data, dict):
            raise ProfileError(f"Origin candidates {candidate_path} must be an object")
        version = data.get("version")
        if version != CANDIDATE_FORMAT_VERSION or isinstance(version, bool):
            raise ProfileError(
                f"version in {candidate_path} must be {CANDIDATE_FORMAT_VERSION}"
            )
        stored_min = data.get("min_observations", 2)
        if (
            isinstance(stored_min, bool)
            or not isinstance(stored_min, int)
            or stored_min <= 0
        ):
            raise ProfileError(
                f"min_observations in {candidate_path} must be a positive integer"
            )
        threshold = min_observations if min_observations is not None else stored_min
        stored_max_candidates = data.get(
            "max_candidates", DEFAULT_ORIGIN_LEARNING_MAX_CANDIDATES
        )
        stored_max_observations = data.get(
            "max_observations", DEFAULT_ORIGIN_LEARNING_MAX_OBSERVATIONS
        )
        try:
            learner = cls(
                threshold,
                max_candidates=(
                    max_candidates
                    if max_candidates is not None
                    else stored_max_candidates
                ),
                max_observations=(
                    max_observations
                    if max_observations is not None
                    else stored_max_observations
                ),
            )
        except ValueError as exc:
            if (
                min_observations is not None
                or max_candidates is not None
                or max_observations is not None
            ):
                raise
            raise ProfileError(
                f"invalid origin-learning limits in {candidate_path}: {exc}"
            ) from exc
        entries = data.get("candidates", [])
        if not isinstance(entries, list):
            raise ProfileError(f"candidates in {candidate_path} must be a list")
        for index, entry in enumerate(entries):
            learner._load_entry(entry, f"candidates[{index}] in {candidate_path}")
        return learner

    def _load_entry(self, entry: object, location: str) -> None:
        if not isinstance(entry, dict):
            raise ProfileError(f"{location} must be an object")
        if entry.get("detection") != COMPANION_DETECTION:
            raise ProfileError(f"{location}.detection must be {COMPANION_DETECTION!r}")
        delta_opcode = _parse_opcode(
            entry.get("delta_opcode"), f"{location}.delta_opcode"
        )
        raw_opcodes = entry.get("companion_opcodes")
        raw_lengths = entry.get("companion_lengths")
        if not isinstance(raw_opcodes, list) or len(raw_opcodes) != 2:
            raise ProfileError(f"{location}.companion_opcodes must contain two values")
        if not isinstance(raw_lengths, list) or len(raw_lengths) != 2:
            raise ProfileError(f"{location}.companion_lengths must contain two values")
        opcodes = (
            _parse_opcode(raw_opcodes[0], f"{location}.companion_opcodes"),
            _parse_opcode(raw_opcodes[1], f"{location}.companion_opcodes"),
        )
        lengths: list[int] = []
        for value in raw_lengths:
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or not 5 <= value <= 0xFFFF
            ):
                raise ProfileError(f"{location}.companion_lengths must be 5..65535")
            lengths.append(value)
        key = (delta_opcode, opcodes[0], opcodes[1], lengths[0], lengths[1])
        state = _CandidateState(delta_opcode, opcodes, (lengths[0], lengths[1]))
        observation_ids = entry.get("observation_ids", [])
        token_digests = entry.get("token_digests", [])
        delta_lengths = entry.get("delta_lengths", [])
        if not isinstance(observation_ids, list) or any(
            not isinstance(value, str) for value in observation_ids
        ):
            raise ProfileError(f"{location}.observation_ids must be a string list")
        if not isinstance(token_digests, list) or any(
            not isinstance(value, str) for value in token_digests
        ):
            raise ProfileError(f"{location}.token_digests must be a string list")
        if not isinstance(delta_lengths, list) or any(
            isinstance(value, bool)
            or not isinstance(value, int)
            or not 5 <= value <= 0xFFFF
            for value in delta_lengths
        ):
            raise ProfileError(f"{location}.delta_lengths must contain 5..65535")
        unique_observation_ids = set(observation_ids)
        for name, values in (
            ("token_digests", token_digests),
            ("delta_lengths", delta_lengths),
        ):
            if len(set(values)) > len(unique_observation_ids):
                raise ProfileError(
                    f"{location}.{name} cannot contain more distinct evidence "
                    "than observation_ids"
                )
        state.observation_ids.update(observation_ids)
        state.token_digests.update(token_digests)
        state.delta_lengths.update(delta_lengths)
        offsets = entry.get("token_offsets", {})
        if not isinstance(offsets, dict):
            raise ProfileError(f"{location}.token_offsets must be an object")
        for name, target in (
            ("delta", state.delta_offsets),
            ("first_companion", state.first_offsets),
            ("second_companion", state.second_offsets),
        ):
            values = offsets.get(name, [])
            if not isinstance(values, list) or any(
                isinstance(value, bool) or not isinstance(value, int) or value < 0
                for value in values
            ):
                raise ProfileError(f"{location}.token_offsets.{name} is invalid")
            if len(set(values)) > len(unique_observation_ids):
                raise ProfileError(
                    f"{location}.token_offsets.{name} cannot contain more "
                    "distinct evidence than observation_ids"
                )
            target.update(values)
        first_seen = entry.get("first_seen")
        last_seen = entry.get("last_seen")
        if first_seen is not None and not isinstance(first_seen, str):
            raise ProfileError(f"{location}.first_seen must be a string")
        if last_seen is not None and not isinstance(last_seen, str):
            raise ProfileError(f"{location}.last_seen must be a string")
        state.first_seen_text = first_seen
        state.last_seen_text = last_seen
        if key in self._states:
            raise ProfileError(f"{location} duplicates an earlier candidate family")
        if len(self._states) >= self.max_candidates:
            raise OriginLearningLimitError("candidate-family", self.max_candidates)
        retained_observations = len(state.observation_ids)
        if self._observation_count + retained_observations > self.max_observations:
            raise OriginLearningLimitError("observation", self.max_observations)
        self._states[key] = state
        self._observation_count += retained_observations

    def observe(self, observation: CompanionObservation) -> OriginCompanionCandidate:
        if not isinstance(observation, CompanionObservation):
            raise TypeError("OriginLearner.observe expects CompanionObservation")
        with self._lock:
            state = self._states.get(observation.family_key)
            if (
                state is not None
                and observation.observation_id in state.observation_ids
            ):
                return state.snapshot()
            if state is None:
                if len(self._states) >= self.max_candidates:
                    raise OriginLearningLimitError(
                        "candidate-family", self.max_candidates
                    )
                state = _CandidateState(
                    observation.delta_opcode,
                    observation.companion_opcodes,
                    observation.companion_lengths,
                )
            if self._observation_count >= self.max_observations:
                raise OriginLearningLimitError("observation", self.max_observations)
            added = state.add(observation)
            if added:
                self._observation_count += 1
                self._states[observation.family_key] = state
            return state.snapshot()

    @property
    def candidates(self) -> tuple[OriginCompanionCandidate, ...]:
        with self._lock:
            return tuple(self._states[key].snapshot() for key in sorted(self._states))

    @property
    def confirmed_candidates(self) -> tuple[OriginCompanionCandidate, ...]:
        return tuple(
            candidate
            for candidate in self.candidates
            if candidate.confirmed(self.min_observations)
        )

    def summary(self) -> str:
        """Return a human-readable multi-line candidate report."""
        candidates = self.candidates
        confirmed_count = sum(
            candidate.confirmed(self.min_observations) for candidate in candidates
        )
        lines = [
            f"observed {len(candidates)} origin companion family/families; "
            f"{confirmed_count} confirmed for promotion "
            f"(threshold: {self.min_observations} observation(s))"
        ]
        if not candidates:
            lines.append("no origin companion families observed")
            return "\n".join(lines)

        for candidate in candidates:
            status = (
                "confirmed"
                if candidate.confirmed(self.min_observations)
                else "candidate"
            )
            companions = " -> ".join(
                f"0x{opcode:04X}" for opcode in candidate.companion_opcodes
            )
            lengths = ", ".join(str(length) for length in candidate.companion_lengths)
            lines.append(
                f"{status}: delta=0x{candidate.delta_opcode:04X} "
                f"companions={companions} lengths=({lengths}) "
                f"observations={candidate.observations} "
                f"distinct_tokens={candidate.distinct_tokens}"
            )
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": CANDIDATE_FORMAT_VERSION,
            "generated_at": _utc_text(),
            "min_observations": self.min_observations,
            "max_candidates": self.max_candidates,
            "max_observations": self.max_observations,
            "candidates": [
                candidate.to_dict(self.min_observations)
                for candidate in self.candidates
            ],
        }

    def save(self, path: str | Path) -> Path:
        candidate_path = Path(path)
        _atomic_write_text(
            candidate_path,
            json.dumps(self.to_dict(), indent=2, sort_keys=True) + "\n",
        )
        return candidate_path


@dataclass(frozen=True)
class OriginPromotion:
    path: Path
    added: tuple[OriginCompanionCandidate, ...]
    backup_path: Optional[Path]
    written: bool


def promote_origin_candidates(
    candidates_path: str | Path,
    profile_path: str | Path,
    *,
    min_observations: Optional[int] = None,
    backup: bool = True,
) -> OriginPromotion:
    """Explicitly merge confirmed learned families into an opcode profile."""
    learner = OriginLearner.load(
        candidates_path,
        min_observations=min_observations,
    )
    confirmed = learner.confirmed_candidates
    destination = Path(profile_path)
    load_opcode_profile(destination)  # Strictly validate before preserving it.
    data = json.loads(destination.read_text(encoding="utf-8-sig"))
    families = data.setdefault("origin_companion_families", [])
    if not isinstance(families, list):
        raise ProfileError(f"origin_companion_families in {destination} must be a list")

    existing: set[tuple[int, int, int, int, int]] = set()
    for index, family in enumerate(families):
        if not isinstance(family, dict):
            raise ProfileError(
                f"origin_companion_families[{index}] in {destination} must be an object"
            )
        raw_opcodes = family.get("companion_opcodes")
        raw_lengths = family.get("companion_lengths")
        if not isinstance(raw_opcodes, list) or len(raw_opcodes) != 2:
            raise ProfileError("existing companion family has invalid opcodes")
        if not isinstance(raw_lengths, list) or len(raw_lengths) != 2:
            raise ProfileError("existing companion family has invalid lengths")
        existing.add(
            (
                _parse_opcode(family.get("delta_opcode"), "delta_opcode"),
                _parse_opcode(raw_opcodes[0], "companion opcode"),
                _parse_opcode(raw_opcodes[1], "companion opcode"),
                int(raw_lengths[0]),
                int(raw_lengths[1]),
            )
        )

    added = tuple(
        candidate for candidate in confirmed if candidate.family_key not in existing
    )
    if not added:
        return OriginPromotion(destination, (), None, False)
    promoted_at = _utc_text()
    for candidate in added:
        families.append(
            {
                "detection": COMPANION_DETECTION,
                "delta_opcode": _opcode_text(candidate.delta_opcode),
                "companion_opcodes": [
                    _opcode_text(opcode) for opcode in candidate.companion_opcodes
                ],
                "companion_lengths": list(candidate.companion_lengths),
                "observations": candidate.observations,
                "promoted_at": promoted_at,
            }
        )
    data["updated_at"] = promoted_at
    backup_path = None
    if backup:
        backup_path = _unique_backup_path(destination)
        shutil.copy2(destination, backup_path)
    _atomic_write_text(destination, json.dumps(data, indent=2, sort_keys=True) + "\n")
    return OriginPromotion(destination, added, backup_path, True)


def _unique_backup_path(path: Path) -> Path:
    backup_dir = path.parent / "opcodes_backups"
    backup_dir.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now(tz=dt.UTC).strftime("%Y%m%d%H%M%S%f")
    return backup_dir / f"{path.name}.bak.{stamp}"


def _atomic_write_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Optional[Path] = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()
