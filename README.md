# bdo-toolkit

[![CI](https://img.shields.io/github/actions/workflow/status/ychwu/bdo-toolkit/ci.yml?branch=main&style=flat-square&label=CI)](https://github.com/ychwu/bdo-toolkit/actions/workflows/ci.yml)
[![Python 3.14+](https://img.shields.io/badge/python-3.14%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://github.com/ychwu/bdo-toolkit/blob/main/pyproject.toml)
![Tested on NA/EU](https://img.shields.io/badge/tested-NA%2FEU-5b61a8?style=flat-square)
[![Package: Stable](https://img.shields.io/badge/package-stable-2f855a?style=flat-square)](https://ychwu.github.io/bdo-toolkit/#stability)
[![License: MIT](https://img.shields.io/badge/license-MIT-2f855a?style=flat-square)](https://github.com/ychwu/bdo-toolkit/blob/main/LICENSE)

Passive, read-only Python tooling that turns live or recorded Black Desert
traffic into structured, application-ready data.

[Documentation](https://ychwu.github.io/bdo-toolkit/) ·
[Quickstart](https://ychwu.github.io/bdo-toolkit/#quickstart) ·
[Examples](https://ychwu.github.io/bdo-toolkit/#item-examples) ·
[API index](https://ychwu.github.io/bdo-toolkit/#api-index) ·
[Report an issue](https://github.com/ychwu/bdo-toolkit/issues)

> **Passive, read-only boundary.** bdo-toolkit observes local traffic or saved
> captures. It does not send or modify packets, replay traffic to the game,
> automate gameplay, inspect process memory, or bypass anti-cheat software.

## Capabilities

bdo-toolkit exposes four passive workflows. Each can observe live traffic or
replay a saved PCAP or PCAPNG file.

| Capability | What it provides | Main interfaces | Status |
| --- | --- | --- | --- |
| Item activity | A continuing stream of typed `BDOEvent` objects for supported loot, gathering, inventory, and storage changes | [`capture_live()` and `replay_pcap()`](https://ychwu.github.io/bdo-toolkit/#capture-functions), [`EventFilter`](https://ychwu.github.io/bdo-toolkit/#event-filter) | Stable |
| Inventory and town storage | A finite `ItemStateSnapshot` assembled from character-load traffic, with inventory, known balances, and observed town storage | [`bdo_toolkit.item_state`](https://ychwu.github.io/bdo-toolkit/#item-state-overview) | Beta |
| Arena of Solare leaderboards | A finite `SolareCaptureResult` containing overall rankings, class tables, and player statistics when the capture is complete | [`bdo_toolkit.solare`](https://ychwu.github.io/bdo-toolkit/#solare-overview) | Beta |
| Item-profile calibration | A local opcode profile rebuilt from controlled capture evidence when a game patch changes item traffic | [Calibration APIs and workflow](https://ychwu.github.io/bdo-toolkit/#calibration-workflow) | Stable |

These workflows include synchronous and
[asyncio](https://ychwu.github.io/bdo-toolkit/#asyncio) sessions, capture and
decoder health diagnostics, console and JSONL event writers, and a
[command-line interface](https://ychwu.github.io/bdo-toolkit/#cli). Exact
signatures, fields, lifecycle behavior, and failure contracts are in the
[API index](https://ychwu.github.io/bdo-toolkit/#api-index).

Testing and validation cover **NA/EU only**. Compatibility with other regional
services is unknown.

## Installation

```powershell
python -m pip install bdo-toolkit
```

Python 3.14 or newer is required. Before live capture, complete
[Installation & setup](https://ychwu.github.io/bdo-toolkit/#capture-foundation),
including Npcap on Windows and permission to capture on the selected interface.
Offline PCAP and PCAPNG replay does not require Npcap.

## Get started

1. Complete [Installation & setup](https://ychwu.github.io/bdo-toolkit/#capture-foundation).
2. For item events or item state, prepare a current local profile through
   [Opcode profile setup](https://ychwu.github.io/bdo-toolkit/#profiles).
3. Run the [Quickstart](https://ychwu.github.io/bdo-toolkit/#quickstart) or
   choose a task from the [Examples](https://ychwu.github.io/bdo-toolkit/#item-examples)
   index.

Local calibration is the dependable patch-day path because maintained profiles
require manual verification and may lag a weekly update. The
[Calibration guide](https://ychwu.github.io/bdo-toolkit/#calibration-workflow)
walks through rebuilding one. Arena of Solare uses structural classification
and does not require an item opcode profile.

## Runnable examples

The source checkout includes maintained, run-ready lessons. They are not
installed with the Python wheel.

| Workflow | Representative script |
| --- | --- |
| Observe live item activity | [`examples/live_transfer_log.py`](https://github.com/ychwu/bdo-toolkit/blob/main/examples/live_transfer_log.py) |
| Capture inventory and town storage on character load | [`examples/live_character_load_snapshot.py`](https://github.com/ychwu/bdo-toolkit/blob/main/examples/live_character_load_snapshot.py) |
| Rebuild an item profile after a patch | [`examples/live_calibrate_profile.py`](https://github.com/ychwu/bdo-toolkit/blob/main/examples/live_calibrate_profile.py) |
| Capture an Arena of Solare leaderboard load | [`examples/solare_live_snapshot.py`](https://github.com/ychwu/bdo-toolkit/blob/main/examples/solare_live_snapshot.py) |

See the [Examples index](https://ychwu.github.io/bdo-toolkit/#item-examples)
for every script, its prerequisites, and the guide that explains it.

## Support

For questions, contact me on Discord: `._.__.__._._.__._____.__._.___.`

For bugs and feature requests, [open a GitHub issue](https://github.com/ychwu/bdo-toolkit/issues).

## License

bdo-toolkit is available under the
[MIT License](https://github.com/ychwu/bdo-toolkit/blob/main/LICENSE).
