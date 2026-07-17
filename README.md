# BDO Toolkit WORK IN PROGRESS, INCOMPLETE

WORK IN PROGRESS, INCOMPLETE

Passive, read-only packet telemetry tooling for developers building BDO helper
apps.

**📖 Full API reference: [ychwu.github.io/bdo-toolkit](https://ychwu.github.io/bdo-toolkit/)**

The toolkit goal is simple:

```text
packet capture or pcap replay in -> structured gameplay item events out
```

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

Asyncio apps can use the same capture engine without writing their own thread
bridge:

```python
import asyncio

from bdo_toolkit import AsyncLiveCaptureSession

async def main():
    async with AsyncLiveCaptureSession() as session:
        async for event in session:
            print(event.format_human())

asyncio.run(main())
```

`AsyncLiveCaptureSession` and `AsyncCalibrationSession` are additive facades
over the synchronous sessions. See the dedicated
[asyncio guide](https://ychwu.github.io/bdo-toolkit/asyncio.html) and the
runnable [`async_live_capture.py`](examples/async_live_capture.py) example.

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
)
session = LiveCaptureSession(live_options=options)
```

`"Batch Storage Deposit"` is not worker-only. It is a batch-style storage delta
observed in both passive worker deposits and manual bulk deposits.

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
- [Asyncio integration](https://ychwu.github.io/bdo-toolkit/asyncio.html) —
  `AsyncLiveCaptureSession`, `AsyncCalibrationSession`, cancellation, and
  Start/Stop patterns for async apps
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
bdo-toolkit calibrate --item-id 7003 --qty 3 --write opcodes.json --replace
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
    update_profile(result, "opcodes.json", replace=True)
```

In an asyncio app, await the calibration lifecycle directly:

```python
import asyncio

from bdo_toolkit import AsyncCalibrationSession

async def main():
    async with AsyncCalibrationSession(item_id=7003, quantity=3) as session:
        await asyncio.to_thread(
            input,
            "Move 3 Potatoes to storage and back, then press Enter...",
        )
        result = await session.stop()
    print(result.summary())

asyncio.run(main())
```

When the network defaults are not suitable, pass
`capture_options=PacketCaptureOptions(...)` to `CalibrationSession`,
`AsyncCalibrationSession`, or `calibrate_live()`.

Then point the API at it: `replay_pcap("session.pcapng", opcode_profile="opcodes.json")`.

The bundled profile remains the default for now. For an older recording, pass
the profile captured for that game patch instead of combining opcode
generations. Decoding always uses one selected profile authority.

Direction is classified from structure, not taken on faith: an explicit
`--action` calibration refuses (rather than mislabels) a capture whose
structure contradicts the declared action. See the
[calibration docs](https://ychwu.github.io/bdo-toolkit/#calibration) for the
full workflow and how direction detection works.

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

Worker classification uses a three-frame **structure**: the storage delta and
the next two contiguous companion frames must share the same informative
8-byte token. The exact companion opcode values are not part of that verdict.

| Shared-token structure | Promoted opcode family | Classification | Audit metadata |
| --- | --- | --- | --- |
| Present | Known | `worker` | `known_family=True` |
| Present | Unknown | `worker` | `known_family=False` |
| Absent | Even if the following opcodes look familiar | Not worker from companion evidence | No companion-chain audit record |

A matching calibrated source-stack decrement can classify the remaining case
as `manual`; incomplete or absent evidence stays `unknown`. In other words,
**companion frames are required for worker classification, but previously
learned companion opcode identities are not.**

The family lookup is still a cross-check: it reports whether the structural
match agrees with metadata already promoted into the profile. It never
upgrades, downgrades, or vetoes `deposit_origin`.

The optional `OriginLearner` records which opcode/length families were seen
after the structural classifier already found a worker chain. This is useful
for patch auditing; it does not make the classification happen. The workflow
has three separate steps:

| Goal | What to use | Writes files? |
| --- | --- | --- |
| Classify deposits | `capture_live()` or `replay_pcap()` | No |
| Aggregate observed families | `origin_observer=learner.observe` | No |
| Save candidates | `learner.save(...)` or `origin-learn` | Candidate JSON only |
| Mark reviewed families as known | `promote_origin_candidates(...)` or `origin-promote` | Explicitly updates the opcode profile |

`min_observations=2` means a family becomes a confirmed **promotion
candidate** after two independent observations. It does not mean "run the
learner twice," and it is not a worker-confidence threshold.

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
profile does.

## Design Principles

- Passive/read-only only: never inject, send, delay, replay, or modify packets.
- Decode all known categories in the engine, then let apps filter events.
- Keep opcode profiles data-driven and easy to replace after patches.
- Classify worker origins structurally; learned opcode families are audit
  metadata, never the sole verdict.
- Treat packet knowledge as provisional unless repeated captures prove it.
- Preserve raw fields and add new event fields without breaking old apps.

## Layout

```text
src/bdo_toolkit/
  capture.py            Live capture and pcap replay entry points
  events.py             Stable app-facing event model
  filters.py            Event filtering helpers
  profiles.py           Opcode profile loading
  origin_learning.py    Structural companion discovery and opt-in learning
  writers.py            Console and JSONL writers
  calibration.py        Opcode profile calibration and profile updates
  cli.py                bdo-toolkit command line
  data/opcodes.json     Bundled default opcode profile
  _*.py                 Internal engine modules (may change without notice)

site/                   API reference, deployed to GitHub Pages
examples/               Small runnable examples
tests/                  Test suite (see note on fixtures below)
```

Build apps against the public API only; `_`-prefixed modules are internal.

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

- Event schema versioning.
- Inventory snapshot event API.

