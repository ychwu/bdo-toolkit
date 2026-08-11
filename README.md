# BDO Toolkit

[![CI](https://img.shields.io/github/actions/workflow/status/ychwu/bdo-toolkit/ci.yml?branch=main&style=flat-square&label=CI)](https://github.com/ychwu/bdo-toolkit/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://github.com/ychwu/bdo-toolkit/blob/main/pyproject.toml)
[![Status: Alpha](https://img.shields.io/badge/status-alpha-d97706?style=flat-square)](https://ychwu.github.io/bdo-toolkit/#stability)
[![License: MIT](https://img.shields.io/badge/license-MIT-2f855a?style=flat-square)](https://github.com/ychwu/bdo-toolkit/blob/main/LICENSE)

Passive, read-only Python tooling that turns live or recorded Black Desert
traffic into structured, application-ready data.

[API reference](https://ychwu.github.io/bdo-toolkit/) ·
[Runnable examples](https://ychwu.github.io/bdo-toolkit/#item-examples) ·
[Command line](https://ychwu.github.io/bdo-toolkit/#cli) ·
[Report an issue](https://github.com/ychwu/bdo-toolkit/issues)

> **Passive, read-only boundary.** BDO Toolkit observes local traffic or saved
> captures. It does not send or modify packets, replay traffic to the game,
> automate gameplay, inspect process memory, or bypass anti-cheat software.

## What it provides

| In-game moment | What the toolkit provides | Status | Start here |
| --- | --- | --- | --- |
| Collect loot, gather items, withdraw items, or add items to town storage | A continuing `BDOEvent` stream describing supported item activity as it happens | Alpha | [Quickstart](https://ychwu.github.io/bdo-toolkit/#quickstart) |
| Log in or switch characters | One finite `ItemStateSnapshot` assembled from the existing inventory, known balances, and town-storage records observed while the character loads | Experimental | [Item-state overview](https://ychwu.github.io/bdo-toolkit/#item-state-overview) |
| Open or refresh the Arena of Solare Leaderboard | One `SolareCaptureResult`; a complete result contains the overall top 100 and all 31 class-specific top-20 lists | Alpha | [Solare overview](https://ychwu.github.io/bdo-toolkit/#solare-overview) |

The domains share passive packet capture, TCP reassembly, and framing while
keeping their app-facing models separate. Only the selected API runs its
domain decoder; Solare does not load an item opcode profile.

```text
live capture or pcap replay
  -> shared capture, TCP reassembly, and framing
     |-- item profile + event decoder -> BDOEvent stream
     |-- item profile + item-state assembler -> ItemStateSnapshot
     `-- Solare structural classifier -> SolareCaptureResult
```

## Installation

```powershell
python -m pip install bdo-toolkit
```

Python 3.10 or newer is required. Live capture on Windows also requires
[Npcap](https://npcap.com/) and permission to capture network traffic. Offline
PCAP and PCAPNG replay does not require Npcap or an elevated shell.

## Quick start: log mob drops live

```python
from bdo_toolkit import EventFilter, capture_live

mob_drops = EventFilter(
    event_types={"item_received"},
    sources={"Mob Drop"},
)

for event in capture_live(event_filter=mob_drops):
    print(event.format_human())
```

Start the program before collecting a mob drop, and press Ctrl+C to stop.
Source matching is exact and case-sensitive. Item decoding uses one selected
opcode profile, which must match the captured game patch; the bundled profile
is used when no local path is supplied.

For app-controlled start and stop, background workers, or complete shutdown
health, use [`LiveCaptureSession`](https://ychwu.github.io/bdo-toolkit/#live-capture-session).
The full [Item examples](https://ychwu.github.io/bdo-toolkit/#item-examples)
page routes from common application goals to the appropriate API.

## Runnable repository examples

These complete scripts live in the repository rather than the installed wheel.
The live item examples expect a calibrated `opcodes.local` in the repository
root; Solare uses structural classification and does not use that profile.

| Example | What it does | Notes |
| --- | --- | --- |
| [Mob Drop Logger](https://github.com/ychwu/bdo-toolkit/blob/main/examples/live_mob_drops.py) | Prints confirmed mob drops live. | Item profile required |
| [Live Transfer Log](https://github.com/ychwu/bdo-toolkit/blob/main/examples/live_transfer_log.py) | Prints item receipts and confirmed storage additions live. | Storage-decoder diagnostics go to stderr |
| [Async Live Transfer Log](https://github.com/ychwu/bdo-toolkit/blob/main/examples/async_live_capture.py) | Runs the live transfer log from an asyncio application. | Demonstrates application-controlled stop and drain |
| [Character-Load Item Snapshot](https://github.com/ychwu/bdo-toolkit/blob/main/examples/live_character_load_snapshot.py) | Captures and summarizes inventory, known balances, and town-storage state during the next login or character switch. | Experimental; observed state may be partial |
| [Solare Live Snapshot](https://github.com/ychwu/bdo-toolkit/blob/main/examples/solare_live_snapshot.py) | Captures one Arena of Solare Leaderboard result with progress and health evidence. | No item profile required |
| [Solare Replay Snapshot](https://github.com/ychwu/bdo-toolkit/blob/main/examples/solare_replay_snapshot.py) | Replays a saved Leaderboard capture and optionally writes JSON. | Deterministic development and support path |

## Calibrate after a game patch

A game patch can make an item opcode profile stale. The normal recovery path
for item-transfer decoding is automatic calibration: the toolkit listens while
the operator performs three controlled in-game moves.

The repository includes a complete
[`live_calibrate_profile.py`](https://github.com/ychwu/bdo-toolkit/blob/main/examples/live_calibrate_profile.py)
example:

1. Open the script and replace `ITEM_ID` with the raw ID of the selected item.
2. Prepare five matching unstackable items and use Velia or Heidel as the
   controlled storage destination.
3. From the repository root, run:

   ```powershell
   python examples/live_calibrate_profile.py
   ```

4. After listening begins, deposit 1 item, deposit the remaining 4, withdraw
   all 5 in one action, and then press Enter.

`QUANTITY = 1` is the quantity in each serialized item record, not the batch
size. The example writes repository-root `opcodes.local` only after the three
families it requires are present: `INVENTORY_TRANSFER`, `STORAGE_ITEM_DELTA`,
and `SOURCE_STACK_DECREMENT` for manual-origin evidence. An
[`async_calibrate_profile.py`](https://github.com/ychwu/bdo-toolkit/blob/main/examples/async_calibrate_profile.py)
variant is provided for asyncio applications.

See the [Calibration guide](https://ychwu.github.io/bdo-toolkit/#calibration-workflow)
for the full authority checks, CLI workflow, offline calibration, profile-write
behavior, and advanced modes. Solare is structurally classified and does not
use item calibration.

## Important operating boundaries

- **Passive only:** the toolkit never sends, modifies, delays, or injects game
  traffic.
- **Patch-specific item profiles:** use one profile matching the captured game
  patch. Recalibrate instead of combining opcode generations.
- **Live and replay defaults differ:** live item capture defaults to ordinary
  activity; unfiltered replay is exhaustive. An explicit `EventFilter` is
  honored exactly in either path.
- **Finite state is observational:** `ItemStateSnapshot` can be partial and
  reports coverage, provenance, warnings, and decoder health rather than
  claiming complete account state.
- **Solare is fail-closed:** consume `result.snapshot` only when
  `result.complete` is true.
- **Captures can be sensitive:** PCAPs can contain character names, gameplay
  history, item state, leaderboard data, and opaque identifier-like bytes that
  the toolkit does not decode or publish. Keep raw recordings out of source
  control and obtain any consent appropriate to the application.

## Documentation

The [API reference](https://ychwu.github.io/bdo-toolkit/) owns the supported
integration contracts, failure behavior, examples, and patch guidance.

| Goal | Documentation |
| --- | --- |
| Understand the package and choose a domain | [Package overview](https://ychwu.github.io/bdo-toolkit/#overview) |
| Start from a functional item use case | [Item examples](https://ychwu.github.io/bdo-toolkit/#item-examples) |
| Capture or replay item events | [Capture functions](https://ychwu.github.io/bdo-toolkit/#capture-functions) and [`LiveCaptureSession`](https://ychwu.github.io/bdo-toolkit/#live-capture-session) |
| Integrate with asyncio | [Asyncio integration](https://ychwu.github.io/bdo-toolkit/#asyncio) |
| Query character-load inventory and storage | [Item-state overview](https://ychwu.github.io/bdo-toolkit/#item-state-overview) |
| Capture or replay Arena of Solare | [Solare overview](https://ychwu.github.io/bdo-toolkit/#solare-overview) |
| Recover item decoding after a patch | [Profiles](https://ychwu.github.io/bdo-toolkit/#profiles) and [Calibration](https://ychwu.github.io/bdo-toolkit/#calibration-workflow) |
| Diagnose failures or review compatibility | [Errors](https://ychwu.github.io/bdo-toolkit/#errors) and [Stability](https://ychwu.github.io/bdo-toolkit/#stability) |

## Development

```powershell
git clone https://github.com/ychwu/bdo-toolkit.git
cd bdo-toolkit
python -m pip install -e ".[dev]"
python -m pytest -q -W error
python -m mypy src/bdo_toolkit
python -m pip wheel . --no-deps --wheel-dir dist
```

CI runs tests, type checking, wheel construction, and a CLI smoke test on
Ubuntu and Windows with Python 3.10 and 3.14. Regression tests that require
private game-session captures skip automatically when those local fixtures are
absent.

## License

BDO Toolkit is available under the
[MIT License](https://github.com/ychwu/bdo-toolkit/blob/main/LICENSE).
