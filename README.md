# BDO Toolkit WORK IN PROGRESS, INCOMPLETE

WORK IN PROGRESS, INCOMPLETE

Passive, read-only packet telemetry tooling for developers building BDO helper
apps.

**📖 Full API reference: [ychwu.github.io/bdo-toolkit](https://ychwu.github.io/bdo-toolkit/)**

The toolkit goal is simple:

```text
packet capture or pcap replay
  -> item-event decoder -> structured BDOEvent stream
  -> Solare decoder     -> SolareCaptureResult -> complete result.snapshot
```

Only the API/session you select runs its decoder; choosing the item route does
not also decode Solare, and choosing Solare does not load an opcode profile.

```python
from bdo_toolkit import EventFilter, capture_live, replay_pcap

for event in replay_pcap(
    "session.pcapng",
    event_filter=EventFilter(sources={"Mob Drop"}),
):
    print(event.item_id, event.quantity)

# a worker-production tracker in one filter — deposit_origin is classified
# from packet structure as "worker" / "manual" / "unknown"
worker_deposits = EventFilter(
    event_types={"storage_delta"},
    deposit_origins={"worker"},
)
for event in capture_live(event_filter=worker_deposits):
    print(event.item_id, event.quantity, event.timestamp)
```

Delivery defaults are intentionally different for offline analysis and live
apps:

- `replay_pcap(..., event_filter=None)` yields the complete decoded replay
  stream, including snapshot records and neutral diagnostics.
- `capture_live(..., event_filter=None)`, `LiveCaptureSession(event_filter=None)`,
  and `AsyncLiveCaptureSession(event_filter=None)` use
  `EventFilter.activity()`: `loot_preview`, `item_received`, and
  `storage_delta`.
- Pass `EventFilter.all()` for every completed decoded live event, or
  `EventFilter.snapshot_records()` for only `inventory_snapshot` and
  `storage_snapshot` hydration records.
- A caller-supplied `EventFilter` is honored exactly. Values within one set are
  alternatives; every supplied criterion must match. Names and event types are
  exact and case-sensitive.

For an app with Start and Stop controls, use `LiveCaptureSession` instead of
trying to interrupt the blocking iterator yourself:

```python
from threading import Thread
from bdo_toolkit import EventFilter, LiveCaptureSession

session = LiveCaptureSession(
    event_filter=EventFilter(event_types={"item_received", "storage_delta"}),
)

def pump_events():
    for event in session.events():
        handle_event(event)

# Start button:
session.start()
worker = Thread(target=pump_events, daemon=True)
worker.start()

# Stop button (safe even when no events are arriving):
session.stop()
worker.join()
```

`stop()` wakes a blocked `events()` consumer, stops packet capture, finalizes
pending TCP and deposit-origin state, and lets the iterator drain already
decoded events before ending. A session is single-use; create a new one when
the feature is started again. See the runnable
[`controlled_live_capture.py`](examples/controlled_live_capture.py) example.

Shutdown is bounded and verified. If native capture or a decoder/feature worker
cannot be proven stopped, `stop()` raises, `session.cleanup_incomplete` remains
true, and the same session retains its pipeline for another `stop()` attempt.
If startup or a convenience wrapper cannot return that session normally, the
escaping exception exposes it as `exception.cleanup_owner` when Python permits
exception attributes. The first run error remains authoritative after cleanup
eventually succeeds. Inside `origin_observer` or a Solare `on_update` callback,
use non-blocking `request_stop()`; blocking stop/poll/wait/iteration on that
same session is rejected to prevent callback self-deadlocks.

`AsyncLiveCaptureSession.events()` fetches up to 64 immediately ready events per
executor submission, but transfers the entire batch into session-owned pending
storage before yielding the first event. Early break, iterator close,
cancellation after a yield, and sequential handoff to `poll()` therefore keep
every prefetched event reachable and ordered. Use one logical event consumer;
overlapping blocking consumption is rejected. `poll()` validates its timeout
even while draining pending data or after the synchronous session has stopped.

Packet acquisition controls shared with live calibration live in
`PacketCaptureOptions`. `LiveCaptureOptions` extends those settings with the
decoded-event queue size used by `capture_live()`, `LiveCaptureSession`, and
`AsyncLiveCaptureSession`:

```python
from bdo_toolkit import LiveCaptureOptions, LiveCaptureSession

options = LiveCaptureOptions(
    interface="Ethernet",
    use_bpf=True,
    auto_local_ip=True,
    event_queue_size=2048,
    packet_queue_size=4096,
)
session = LiveCaptureSession(live_options=options)
```

The native capture callback only performs a bounded packet handoff; decoding
runs on a worker thread. Packet-queue overflow fails the session with
`CaptureIntegrityError` instead of silently continuing. Inspect
`session.health.capture_is_clean` and its packet, native-drop, TCP-gap, and
flow-eviction counters before treating a live stream as complete telemetry.
An observed empty SYN anchors the first payload sequence. When capture begins
after the handshake, a bounded initial reorder set is retained briefly so
multiple lower/higher/overlapping segments can establish an evidence-backed
frame origin; unresolved data is released after 250 ms, at capacity pressure,
or at finalization. Out-of-order FIN is deferred while observed earlier bytes
remain recoverable, and a FIN-only missing range uses the ordinary TCP-gap
deadline. This recovers captured reordering but cannot reconstruct bytes that
were never observed.

## Arena of Solare snapshots

Solare is a separate public domain inside the same package. It shares passive
packet acquisition and TCP reassembly with the item-event APIs, but it returns
one terminal `SolareCaptureResult` instead of mixing finite leaderboard state
into the open-ended `BDOEvent` stream. Only a complete result contains the
atomic leaderboard at `result.snapshot`:

```python
from bdo_toolkit.solare import replay_solare

result = replay_solare("solare-session.pcapng")
if not result.complete:
    raise RuntimeError(f"{result.status.value}: {result.message}")

snapshot = result.snapshot
assert snapshot is not None
for entry in snapshot.overall_top_100:
    details = snapshot.get_player(entry.name)
    print(entry.global_rank, entry.name, details.elo if details else None)
```

Replay and live capture use the same incremental classifier. It discovers the
ranked, class-balanced, and overall families without accepting a known opcode
as identity; opcode is only an opaque key that keeps observed message families
apart. Reset-aligned generations allow a complete refresh between partial
ones, and the first snapshot to complete in observation order is selected and
latched.

The blocking live convenience reports progress, stops after confirmation, and
has a 120-second default deadline:

```python
from bdo_toolkit.solare import capture_solare_snapshot

result = capture_solare_snapshot(
    on_update=lambda update: print(f"[{update.kind.value}] {update.message}"),
    save_pcap="solare-next-patch.pcapng",
)
```

Start capture before opening or refreshing the Leaderboard tab. Pass
`capture_seconds=None` only for an intentional indefinite wait. Explicit
`LiveSolareSession` and `AsyncLiveSolareSession` instances have no built-in
deadline: the caller controls `start()`, `wait()`, `request_stop()`, and
`stop()`. An `on_update` callback must stay lightweight; it may call the
non-blocking `request_stop()`, but it must not call blocking control or update
consumption methods on the same session.

The two wire tables stay separate in the public snapshot. `players` contains
the 31 class top-20 groups and their optional details;
`overall_top_100` is the authoritative overall board. A highly represented
class can place a 21st player in the overall top 100 even though its class board
stops at 20. In that case `get_player(entry.name)` returns `None` for the
overall-only entry. The compatibility `top_100` property contains only the
detailed rich-table players whose global rank is 1 through 100, so it may be
shorter than 100 in this legitimate case.

Snapshot publication also requires clean acquisition health: any TCP gap or
reported packet drop, packet-queue overflow, or active-flow eviction before
confirmation returns `detected-incomplete`, even if the remaining rows happen
to match. Candidate discovery is bounded to 768 frames and 16 MiB and evaluates
the retained window before discarding older candidates. The live packet queue
is bounded to 4,096 packets, the progress queue to 64 updates, and active TCP
reassembly to 64 flows; the related counters live under
`result.evidence.health`. A rollover `warning` is progress, not an unbounded
audit log, while the newest terminal `finished` update remains available.

With `stop_on_complete=False`, the first snapshot and its health are latched
while capture may continue; later decoder messages are not retained or allowed
to mutate it. If `save_pcap` is also enabled, the recording can still grow for
as long as capture runs. That disk lifetime is caller-owned: set a deadline,
stop explicitly, or rotate files outside the toolkit.

The June 24, July 14, and July 17 capture generations use different opcodes
and record geometry; the structural classifier confirms all three. Deeper
player statistics are enabled only when a geometry-specific decoder validates
every record. Check `snapshot.capabilities`: `"rankings"` is independent from
`"performance"`. `"raw_extensions"` is additionally opt-in.

Each occupied class slot can expose matches, wins, draws, losses, raw recent
result codes, and, when retained explicitly, exact opaque gear/addon sections.
Pass `retain_raw_extensions=True` to `replay_solare()`,
`capture_solare_snapshot()`, or either session constructor before decoding. In
Python, `gear_loadout_raw.data` and `skill_addons_raw.data` are literal `bytes`
(2,001 and 501 bytes respectively). Their internal format is not claimed. Normal
`to_dict()` / `to_json()` output omits these large blobs; after retaining them,
pass `include_raw=True` to serialize them as hex. Serialization cannot recover
raw bytes that were not retained during capture or replay; replay the saved
PCAP again with retention enabled if needed.

Command-line equivalents keep progress on stderr and result JSON on stdout:

```powershell
bdo-toolkit solare live --save-pcap solare-next-patch.pcapng
bdo-toolkit solare replay solare-next-patch.pcapng --output snapshot.json
bdo-toolkit solare replay solare-next-patch.pcapng --include-raw --output raw.json
bdo-toolkit solare live --wait-forever
```

`solare live` shares the 120-second default. `--wait-forever` opts out, and
`--include-raw` both retains the opaque sections and includes them in JSON.

See [`solare_live_snapshot.py`](examples/solare_live_snapshot.py) and
[`solare_replay_snapshot.py`](examples/solare_replay_snapshot.py). Raw pcaps,
player UIDs, names, loadouts, and addons are sensitive account/gameplay data;
keep captures out of source control and obtain any consent appropriate to your
application.

Storage events expose their destination separately from their cause:

- `event.storage_id` is the numeric storage/town key from the packet.
- `event.storage_name` is the best-known town name, with
  `event.storage_name_confidence` describing provisional mappings.
- `event.storage_operation` is `"live"` for a mutation, `"snapshot"` for an
  observed character-load state record, or `"unknown"` when a recognized wrapper has
  an unfamiliar mode after a patch.
- A positively recognized `"snapshot"` bypasses deposit-origin classification.
  A recognized `"unknown"` operation is instead held briefly for the same
  bounded manual/worker evidence used by live deltas.

Recognized current-wrapper character-load contents are emitted as
`storage_snapshot`, never as deposits. The common
`EventFilter(event_types={"item_received", "storage_delta"})` therefore keeps
transfer logs quiet while the game hydrates that storage state. Older layouts
that cannot expose the discriminator retain the legacy `storage_delta` and
origin-classification behavior with `storage_operation=None`.

An unfamiliar current-wrapper mode starts as a neutral `storage_record`. If a
calibrated matching source-stack decrement proves `manual`, or a confirmed
shared-token chain proves `worker`, it is promoted before filtering to
`event_type="storage_delta"` and `storage_operation="live"`. The promoted event
also gains `extra["storage_delta"]`, `deposit_origin`, and
`extra["deposit_origin_evidence"]`, so normal live filters include it. With
neither independent signal, it remains `storage_record` with
`deposit_origin=None` and no deposit extras.

Every evidence-promoted neutral record also carries
`extra["storage_operation_evidence"]` with `wire_operation="unknown"`,
`inferred_operation="live"`, and `signal="matching_decrement"` or
`"worker_companions"`. A multi-record neutral wrapper is classified atomically:
all records are promoted together with the same origin, or the whole batch
remains neutral. For promoted multi-record manual batches,
`deposit_origin_evidence` may include `matching_decrement_record_indexes` to
show which 1-based records supplied the decrement match.

For the current storage wrapper, multi-record decoding does not assume that
message length is a multiple of a saved stride. Given declared record count
`N`, current message length `L`, and the calibrated single-record base length
`B`, the decoder derives `stride = (L - B) / (N - 1)` and accepts it only when
the geometry divides exactly and every declared record validates. Older
wrappers retain a strict marker-based fallback; a saved `repeat_stride` is only
the final compatibility path.

Only the single-record base `B` and ordinary item/context offsets come from the
opcode profile. The current wrapper's relative record-count field and its
mode/token signatures are built-in observations from this protocol generation;
calibration does **not** rediscover those wrapper relationships yet. Making
count and operation metadata calibration-derived is a separate future
enhancement.

Character-load inventory hydration is exposed separately as
`inventory_snapshot`. Its wrapper count is discovered in the framed header,
then used with the calibrated single-record base length to derive the actual
per-frame stride; every declared item, quantity, and instance must validate or
the entire frame fails closed. It never enters ordinary `item_received`
filters. Hydration is directly observed during both initial login and an
operator-labeled character switch, but the packet body does not identify which
trigger occurred.

The smallest public-API live path is the runnable
[`live_item_state_snapshot.py`](examples/live_item_state_snapshot.py) example.
Run it after calibration, perform initial login or switch characters, wait for
the playable world, and press Enter to print the aggregate diagnostic. The
richer live/offline tool is documented in
[`tools/character_load/README.md`](tools/character_load/README.md). The summary
reports occupied item stacks and explicitly leaves storage capacity and stable
inventory tab names provisional. Its experimental model exposes each validated
raw container code, slot, provisional label/confidence, and known currency
balance separately from ordinary item stacks. The live tool can also preserve
its filtered packet evidence with `--save-pcap`; raw captures are sensitive and
should remain in the git-ignored fixture tree.

The canonical experimental import surface is `bdo_toolkit.item_state`:

```python
from bdo_toolkit.item_state import (
    CharacterLoadSession,
    ItemStateCaptureLimits,
    analyze_item_state_pcap,
)

state = analyze_item_state_pcap(
    "character-load.pcapng",
    opcode_profile="opcodes.local",
    capture_limits=ItemStateCaptureLimits(),
)

heidel = state.storages.named("Heidel")
same_storage = state.storages.by_id(0x0020)
stacks = state.storages.find_item(7003)
locations = state.storages.locations_for(7003)
total_quantity = state.storages.total_quantity(7003)

print(len(state.storages), heidel.occupied_stacks if heidel else None)
print(total_quantity, [storage.name for storage in locations])

payload = state.to_dict()
print(payload["schema_version"])       # 3
print(state.identity_complete)          # instance-backed aggregation authority
print(state.coverage.completion_status)  # "unknown"
print(state.provenance.capture_mode)     # "pcap_replay"
```

`state.storages` remains an immutable tuple, so tuple type checks and operators,
iteration, integer indexing, and slicing work alongside the query helpers above.
The older `state.storage()` and
`state.storage_named()` helpers remain available. Existing
`bdo_toolkit.character_state` imports and their `CharacterStateSnapshot`,
`analyze_character_load_pcap()`, and `format_character_state()` names remain
supported compatibility aliases; the experimental aggregate is not exported
from the package root.

Coverage is observation metadata, not a completeness promise. There is no
proven protocol end marker, so `state.coverage.completion_status` remains
`"unknown"` and `capture_may_be_partial` remains true even when every registered
storage ID was observed. Records without an observed stack-instance identity
remain visible in diagnostics but are excluded from item queries, quantities,
occupied-stack totals, currencies, and duplicate inference; inspect
`state.identity_complete` and the inventory/storage missing-instance counters.
`state.provenance` records the capture mode, selected
profile, input or saved-capture path, generation-selection rule, and the fact
that login versus character-switch reason is not decoded. With an inventory
boundary it selects the latest observed hydration; storage-only evidence is
explicitly marked as retaining all observed storage and may span multiple loads.
Structured
`to_dict()` output carries `schema_version == 3` plus both objects so consumers
can audit what was observed and evolve parsers deliberately.

Item-state accumulation fails closed before exceeding 10,000 relevant frames,
50,000 snapshot records, or 64 MiB of retained relevant frame bytes. Customize
those bounds with `ItemStateCaptureLimits`; an exceeded bound raises
`ItemStateCaptureLimitError` and no partial snapshot is returned. Repeated
storage sweeps are selected chronologically, so a later proven empty state
clears an earlier occupied state for that destination.

After an opcode patch, the ordinary guided transfer calibration is still the
first recovery step: it genuinely relearns the receipt/storage opcodes,
first-item positions, and normalized single-record base lengths shared by live
transfers and hydration. It does **not** generically rediscover every field:
quantity and instance still assume `item+4` / `item+35`, inventory context
search relies on known values, and current storage destination recovery expects
`item-9`. Inventory snapshot count, repeat stride, and record-tail
slot/container positions are then discovered structurally at runtime. Storage
snapshot/live/empty classification is not fully calibration-derived yet: it
also depends on the observed item-relative mode/token/count/destination wrapper
relationships. If any of those assumptions move, recalibration alone will not
restore classification and the decoder or a future snapshot-specific
calibration phase must be enhanced.

## Installation

```powershell
git clone https://github.com/ychwu/bdo-toolkit.git
cd bdo-toolkit
pip install -e ".[dev]"
pytest
```

Requirements:

- Python 3.10+
- `scapy` (installed automatically)
- For **live capture on Windows**: [Npcap](https://npcap.com/) must be
  installed, and capture usually requires an elevated (Administrator) shell.
  Offline pcap replay needs neither.

Smoke test against one of your own captures:

```powershell
python examples/simple_log.py path\to\session.pcapng
bdo-toolkit replay path\to\session.pcapng --jsonl
```

## Documentation

The [API reference](https://ychwu.github.io/bdo-toolkit/) covers the full
public surface with examples:

- [Quick start](https://ychwu.github.io/bdo-toolkit/#quickstart) and
  [core concepts](https://ychwu.github.io/bdo-toolkit/#concepts)
- [`replay_pcap`](https://ychwu.github.io/bdo-toolkit/#replay-pcap) /
  [`capture_live`](https://ychwu.github.io/bdo-toolkit/#capture-live) — decode
  captures into events
- [`LiveCaptureSession`](https://ychwu.github.io/bdo-toolkit/#livecapturesession)
  — programmatic Start/Stop, polling, cleanup, and background error reporting
- [Asyncio integration](https://ychwu.github.io/bdo-toolkit/#asyncio) —
  awaitable item-event capture and interactive calibration lifecycle facades
- [Experimental item state](https://ychwu.github.io/bdo-toolkit/#character-state)
  — character-load inventory/storage queries, coverage, provenance, and
  structured schema
- Arena of Solare — opcode-agnostic live/replay snapshots, progress, evidence,
  player statistics, and opaque raw extensions (the completed reference draft
  is included in the next documentation publish)
- [`LiveCaptureOptions`](https://ychwu.github.io/bdo-toolkit/#livecaptureoptions)
  and [`EventFilter`](https://ychwu.github.io/bdo-toolkit/#eventfilter) — reusable
  live-event and event-selection configuration; `PacketCaptureOptions` carries
  the network settings shared with live calibration
- [`BDOEvent`](https://ychwu.github.io/bdo-toolkit/#bdoevent) — the stable
  event model and its [event types](https://ychwu.github.io/bdo-toolkit/#event-types)
- [Opcode profiles](https://ychwu.github.io/bdo-toolkit/#profiles) — bundled
  default, local overrides, staleness after game patches
- [Calibration](https://ychwu.github.io/bdo-toolkit/#calibration) — rebuild a
  profile after a patch, including
  [`CalibrationSession`](https://ychwu.github.io/bdo-toolkit/#calibrationsession)
  for embedding calibration in your own app's UI
- [Command line](https://ychwu.github.io/bdo-toolkit/#cli),
  [errors](https://ychwu.github.io/bdo-toolkit/#errors), and the
  [API stability policy](https://ychwu.github.io/bdo-toolkit/#stability)

## Calibration in 30 seconds

Opcodes and byte offsets can shift when the game is patched, and the bundled
profile may go stale. Rebuild a local profile from a known in-game action
(classic workflow: move a known quantity of Potatoes to storage):

Auto calibration detects transfer direction from packet structure, so you
don't declare which action is which — just move the item to storage and back:

```powershell
# start listening, move the item to storage and back, press Ctrl+C
bdo-toolkit calibrate --item-id 7003 --qty 3 --write opcodes.json
```

```python
# same thing as one library call: capture, calibrate, persist
from bdo_toolkit.calibration import calibrate_and_update

result, update = calibrate_and_update("opcodes.json", item_id=7003, quantity=3)
print(result.summary())                # what was found, human-readable
```

```python
# embedded in an app, stopped by your own UI instead of Ctrl+C
from bdo_toolkit.calibration import CalibrationSession, update_profile

session = CalibrationSession(item_id=7003, quantity=3)   # action defaults to auto
session.start()
# ... user moves the item to storage and back, then clicks "Done" ...
result = session.stop()
if "STORAGE_ITEM_DELTA" in result.events_found:
    update_profile(result, "opcodes.json")
```

Profile writes replace only the event families actually proven by the result,
so a partial calibration cannot erase valid companion specs that it did not
rediscover. Advanced maintenance tools can request an intentional full action
reset with `replace_entire_action=True`, or an intentional merge with
`update_profile(..., replace=False)` / the CLI's `--merge` flag.

When the network defaults are not suitable, pass
`capture_options=PacketCaptureOptions(...)` to `CalibrationSession`,
`AsyncCalibrationSession`, or `calibrate_live()`.

Live calibration retains the newest contiguous evidence tail, bounded by
50,000 frames and 64 MiB by default. `CalibrationResult.retention_status` and
the session's observed/retained/discarded counters disclose whether older
evidence was evicted; configure `max_retained_frames` and
`max_retained_bytes` when a longer workflow genuinely needs more history.

Then point the API at it: `replay_pcap("session.pcapng", opcode_profile="opcodes.json")`.

The bundled profile remains the default for now. For an older recording, pass
the profile captured for that game patch instead of combining opcode
generations. Decoding always uses one selected profile authority.

Direction is classified from structure, not taken on faith: an explicit
`--action` calibration refuses (rather than mislabels) a capture whose
structure contradicts the declared action. See the
[calibration docs](https://ychwu.github.io/bdo-toolkit/#calibration) for the
full workflow and how direction detection works.

A controlled multi/unstackable inventory-to-storage move can now normalize both
the storage wrapper and an instance-anchored repeated source decrement back to
their single-record base lengths and save the observed strides. That recovery
fails closed unless one exact cross-frame instance anchor and one coherent
repeat geometry are unique. A single-record move remains the most portable
fallback across an unfamiliar patch; capturing both shapes provides the
strongest calibration evidence.

## Worker origin: classification vs. learning

You do **not** need an `OriginLearner` to classify deposits. Normal
`capture_live()` and `replay_pcap()` calls always classify each storage delta as
`"worker"`, `"manual"`, or `"unknown"` in `event.deposit_origin`:

```python
from bdo_toolkit import EventFilter, capture_live

for event in capture_live(
    opcode_profile="opcodes.local",
    event_filter=EventFilter(event_types={"storage_delta"}),
):
    print(event.deposit_origin)
```

Worker classification uses a three-message **relationship**. It takes a
high-entropy transaction token only from the storage-delta prefix before item
record one, then searches a bounded forward window for two ordered companion
messages carrying that token. Unrelated messages may be interleaved. A new
storage delta, eight following messages, or the timeout closes the window;
incomplete stream data waits only until more bytes arrive or that timeout.

Character-load `storage_snapshot` messages bypass this classifier completely.
They have `deposit_origin=None` and cannot become worker deposits merely
because adjacent snapshot chunks share a timestamp.

A recognized wrapper whose operation is `"unknown"` takes the same bounded
classifier path before app filtering. Positive manual or worker evidence
promotes it to a live `storage_delta`; absent evidence leaves it as a neutral
`storage_record`, not as an `unknown` deposit.

| Bounded token relationship | Family confidence | Classification | Audit metadata |
| --- | --- | --- | --- |
| Present and profile-promoted | Known | `worker` | `known_family=True` |
| Present and structurally confirmed in-session | Confirmed | `worker` | `confirmed_family=True` |
| Ambiguous or absent | Unconfirmed/none | Not worker from companion evidence | Candidate evidence or no chain |

A matching calibrated source-stack decrement classifies an already-live delta
as `manual`; incomplete or absent evidence on an already-live delta stays
`unknown`. The same positive decrement or companion evidence promotes a neutral
`storage_record`, while missing evidence leaves that record neutral. Companion
opcode numbers are not hard-coded as the primary signal, but a structurally
discovered family must be unambiguous/confirmed or already promoted.

When available, manual matching uses the calibrated source-stack instance and
anchored repeat geometry as well as quantity. The audit trail under
`extra["deposit_origin_evidence"]["manual_decrement"]` reports the opcode,
record offsets/index, match kind, whether source and destination instances
matched, and `observed`, `structural`, or legacy `heuristic` confidence.

The evidence reports both whether a family was explicitly promoted
(`known_family`) and whether the current tracker trusted it
(`confirmed_family` plus `confirmation`). This makes first-seen patch behavior
auditable without making a separate learning command mandatory.

The optional `OriginLearner` persists which opcode/length families were seen.
The normal tracker performs its own in-memory confirmation; `OriginLearner` is
for cross-session patch auditing and explicit profile promotion. The workflow
has three separate steps:

| Goal | What to use | Writes files? |
| --- | --- | --- |
| Classify deposits | `capture_live()` or `replay_pcap()` | No |
| Aggregate observed families | `origin_observer=learner.observe` | No |
| Save candidates | `learner.save(...)` or `origin-learn` | Candidate JSON only |
| Mark reviewed families as known | `promote_origin_candidates(...)` or `origin-promote` | Explicitly updates the opcode profile |

`min_observations=2` means the separate persisted learner marks a family as a
confirmed **promotion candidate** after two independent observations. Runtime
classification has its own bounded-window confirmation evidence.

For the complete workflow, jump to
[classification](https://ychwu.github.io/bdo-toolkit/#origin-classification),
[learning](https://ychwu.github.io/bdo-toolkit/#origin-learner), or
[promotion](https://ychwu.github.io/bdo-toolkit/#origin-promotion) in the API
reference.

To audit families from the command line:

```powershell
# Offline discovery from one or more captures (omit --pcap to listen live).
bdo-toolkit origin-learn --profile opcodes.local `
  --pcap worker-single.pcapng --pcap worker-multi.pcapng

# After the configured observation threshold is met, explicitly promote it.
bdo-toolkit origin-promote opcodes.origin-candidates.json --profile opcodes.local
```

Apps can collect the same candidates without filesystem writes:

```python
from bdo_toolkit import OriginLearner, capture_live

learner = OriginLearner(min_observations=2)
for event in capture_live(
    opcode_profile="opcodes.local",
    origin_observer=learner.observe,
):
    print(event.deposit_origin)

print(learner.summary())

# Explicit opt-in persistence:
learner.save("opcodes.origin-candidates.json")
```

The learner stores hashes of shared tokens, never the raw token. Replaying the
same capture again does not inflate its observation count. Saving candidates
does not affect `known_family`; only explicit promotion into the normal opcode
profile does. Retention is bounded by default to 256 candidate families and
10,000 unique observations. `OriginLearningLimitError` is raised before either
limit would be exceeded; use explicit `max_candidates` / `max_observations`
only for a deliberately larger audit.

## Design Principles

- Passive/read-only only: never inject, send, delay, replay, or modify packets.
- Decode all known categories in the engine, then let apps filter events.
- Keep opcode profiles data-driven and easy to replace after patches.
- Keep positively recognized character-load snapshots out of origin
  classification, and require independent evidence before promoting an
  unfamiliar storage operation to a live mutation.
- Classify worker origins from a bounded, prefix-token relationship and fail
  closed when the relationship is ambiguous.
- Treat packet knowledge as provisional unless repeated captures prove it.
- Preserve raw fields and add new event fields without breaking old apps.

## Layout

```text
src/bdo_toolkit/
  capture.py            Live capture and pcap replay entry points
  solare/               Structural Solare snapshot API and models
  events.py             Stable app-facing event model
  filters.py            Event filtering helpers
  profiles.py           Opcode profile loading
  origin_learning.py    Structural companion discovery and opt-in learning
  writers.py            Console and JSONL writers
  calibration.py        Opcode profile calibration and profile updates
  item_state.py         Canonical experimental item-state facade
  character_state.py    Compatibility names and aggregate implementation
  cli.py                bdo-toolkit command line
  data/opcodes.json     Bundled default opcode profile
  _*.py                 Internal engine modules (may change without notice)

site/                   API reference, deployed to GitHub Pages
examples/               Small runnable examples
tools/character_load/   Experimental live/offline state diagnostic
tests/                  Test suite (see note on fixtures below)
```

Build apps against documented public APIs only; `_`-prefixed modules are
internal. `bdo_toolkit.item_state` is the canonical public-experimental module;
its names and aggregate semantics are not yet part of the stable package-root
contract. Existing `bdo_toolkit.character_state` imports remain supported for
compatibility.

## Testing

```powershell
pytest
```

The test suite has two tiers:

- **Synthetic tests** (always run, including in CI): engine unit tests and a
  synthetic-pcap round trip. These need no capture files.
- **Regression tests against real captures**: replay recorded pcaps and
  compare decoded events against JSONL baselines. The capture files are
  personal game-session recordings and are **not part of the public
  repository** — these tests skip automatically when the files are absent.

If you have local fixtures in `tests/fixtures/`, regenerate the baselines
after an intentional decoding change and review the diff:

```powershell
python scripts/regenerate_baselines.py
git diff tests/baselines/
```

## Roadmap

- Stable versioning for the lower-level `BDOEvent` stream schema.
- Promote the experimental item-state/query contract after its count,
  completeness, and post-patch behavior are validated.
- Stable inventory container/tab labels and storage-capacity discovery.

