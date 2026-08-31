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

| In-game task | Python result | Status | Guide |
| --- | --- | --- | --- |
| Watch supported item changes such as loot, gathering, and storage activity | A continuing stream of typed `BDOEvent` objects | Stable | [Item events](https://ychwu.github.io/bdo-toolkit/#item-overview) |
| Log in or switch characters | One observational `ItemStateSnapshot` of inventory, known balances, and town storage | Beta | [Inventory & town storage](https://ychwu.github.io/bdo-toolkit/#item-state-overview) |
| Load the Arena of Solare Leaderboard | One `SolareCaptureResult`; a complete result contains a leaderboard snapshot | Beta | [Arena of Solare](https://ychwu.github.io/bdo-toolkit/#solare-overview) |

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

## Documentation

The documentation separates task-focused guides from the symbol-first API
reference. Exact signatures, fields, lifecycle behavior, and failure contracts
live there rather than in this README.

| Goal | Start here |
| --- | --- |
| Understand the package | [Overview](https://ychwu.github.io/bdo-toolkit/#overview) |
| Build with live item events | [Item events](https://ychwu.github.io/bdo-toolkit/#item-overview) |
| Query character inventory and town storage | [Inventory & town storage](https://ychwu.github.io/bdo-toolkit/#item-state-overview) |
| Rebuild item decoding after a patch | [Calibration](https://ychwu.github.io/bdo-toolkit/#calibration-workflow) |
| Capture and query an Arena of Solare leaderboard | [Arena of Solare](https://ychwu.github.io/bdo-toolkit/#solare-overview) |
| Integrate with an asyncio application | [Asyncio integration](https://ychwu.github.io/bdo-toolkit/#asyncio) |
| Look up a class, function, or model | [API index](https://ychwu.github.io/bdo-toolkit/#api-index) |
| Use the terminal interface | [Command line](https://ychwu.github.io/bdo-toolkit/#cli) |
| Diagnose a problem | [Troubleshooting](https://ychwu.github.io/bdo-toolkit/#errors) |
| Review data handling and project boundaries | [Safety & privacy](https://ychwu.github.io/bdo-toolkit/#stability) |

## Support

For questions, contact me on Discord: `._.__.__._._.__._____.__._.___.`

For bugs and feature requests, [open a GitHub issue](https://github.com/ychwu/bdo-toolkit/issues).

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
Ubuntu and Windows with Python 3.14. Tests that require private
game-session captures skip when those local fixtures are absent.

## License

bdo-toolkit is available under the
[MIT License](https://github.com/ychwu/bdo-toolkit/blob/main/LICENSE).
