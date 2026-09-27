# bdo-toolkit

[![CI](https://img.shields.io/github/actions/workflow/status/ychwu/bdo-toolkit/ci.yml?branch=main&style=flat-square&label=CI)](https://github.com/ychwu/bdo-toolkit/actions/workflows/ci.yml)
[![PyPI version](https://img.shields.io/pypi/v/bdo-toolkit?style=flat-square&label=version)](https://pypi.org/project/bdo-toolkit/)
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

## Live-capture limitations

Live capture depends heavily on your network setup and on whether the capture
backend can see BDO traffic. VPNs and routing services such as ExitLag may require
manual interface, local IP, and port settings; automatic detection may select the
wrong connection. Traffic visible only as an encrypted tunnel cannot be decoded.
Follow [Diagnose capture when automatic selection fails](https://ychwu.github.io/bdo-toolkit/#capture-foundation/diagnose-network)
to inspect connections on Windows, select grouped capture settings, and verify
them with game activity. The guide covers VPNs, local proxies, and cases where
no usable adapter is found. Discovery does not apply settings or verify decoding.

## Capabilities

bdo-toolkit exposes three passive workflows. Each can observe live traffic or
replay a saved PCAP or PCAPNG file.

| Capability | What it provides | Guide | Status |
| --- | --- | --- | --- |
| Item activity | A continuing stream of typed `BDOEvent` objects for supported loot, gathering, inventory, and storage changes | [Item events](https://ychwu.github.io/bdo-toolkit/#item-overview) | Stable |
| Grind tracking | One capture for confirmed mob drops, with optional profile-based Agris and solo XP | [GrindSession](https://ychwu.github.io/bdo-toolkit/#grind-session) | Experimental |
| Inventory and town storage | A finite `ItemStateSnapshot` assembled from character-load traffic, with inventory, known balances, and observed town storage | [Inventory & town storage](https://ychwu.github.io/bdo-toolkit/#item-state-overview) | Beta |
| Arena of Solare leaderboards | A finite `SolareCaptureResult` containing overall rankings, class tables, and player statistics when the capture is complete | [Arena of Solare](https://ychwu.github.io/bdo-toolkit/#solare-overview) | Beta |

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
| Observe calibration progress and stop on completion | [`examples/live_calibration_progress.py`](https://github.com/ychwu/bdo-toolkit/blob/main/examples/live_calibration_progress.py) · [async](https://github.com/ychwu/bdo-toolkit/blob/main/examples/async_calibration_progress.py) |
| Capture an Arena of Solare leaderboard load | [`examples/solare_live_snapshot.py`](https://github.com/ychwu/bdo-toolkit/blob/main/examples/solare_live_snapshot.py) |

See the [Examples index](https://ychwu.github.io/bdo-toolkit/#item-examples)
for every script, its prerequisites, and the guide that explains it.

## Experimental grind tracking

Use `bdo_toolkit.grind.GrindSession` for one capture and TCP reassembly pipeline
serving confirmed mob-drop receipts plus optional Agris and solo XP:

```python
from bdo_toolkit import load_opcode_profile
from bdo_toolkit.grind import GrindSession

profile = load_opcode_profile("opcodes.local")
with GrindSession(profile=profile, track_xp=True) as session:
    for event in session.events():
        print(event.to_dict())
```

Both optional readers default off. Enabled readers require saved layouts;
`track_agris=True` additionally requires `expected_maximum_points` for your
character. Recording never runs discovery, fetches profiles, or writes them.
Handle `GrindFeatureError` and inspect `session.status`: a recognized optional
reader failure disables that feature while others continue; shared capture loss
raises and invalidates the entire session. Events are not correlated to kills.
Stop before changing characters; XP remains solo-only. Existing standalone APIs
remain supported; do not run them alongside the grind session for the same work.
See the [API reference](https://ychwu.github.io/bdo-toolkit/#grind-session)
and [runnable example](examples/live_grind.py) (`--help` lists feature switches).

## Experimental solo XP tracking

`load_opcode_profile(path).xp` optionally exposes an immutable `XPProfileLayout`
from `bdo_toolkit.profiles`. Fetching a profile retains this section. Its fields
are `opcode`, `message_length`, `level_offset`, `current_offset`,
`required_offset`, `flag=0`, and `encoding="level-u8-xp-u64le-solo-v1"`.
Offsets are measured from the start of the complete BDO message, including its
five-byte header. The supported read is a one-byte level (1–75) and two unsigned
eight-byte little-endian XP counters. The required counter is the whole level's
requirement, not the remaining XP. No balances or player identifiers belong in
this section.

Use `bdo_toolkit.xp.LiveXPSession(profile=profile)` to observe level, balances,
percentage, signed XP changes and net XP since the first update. Pass the
`.profile` returned by `fetch_opcode_profile(...)`, or load an installed profile
with `load_opcode_profile(...)`. Users do not need manual calibration when a
maintainer supplies a current XP layout. See the [XP API reference](https://ychwu.github.io/bdo-toolkit/#xp-live-session)
and the runnable [live example](examples/live_xp.py).

The first reading establishes a baseline, not the gain that caused it. Stop
before switching characters. Party/group tracking is unsupported; the tracker
does not detect whether you are solo. Known acquisition loss or unexplained
state changes invalidate current readings and session totals. Offline
`replay_xp(...)` uses the same decoder and requires an explicit matching profile.

Maintainers can use `update_xp_profile(layout, path)` to merge reviewed XP
geometry into an existing active opcode profile with backup and atomic replace.
It preserves item/Agris sections and does not perform calibration or publish.
Fetching does not establish compatibility with the running patch. XP is a
separate API, not a new BDOEvent in the item capture stream or an installed CLI
command; existing profiles may omit XP, but the XP API requires it.

## Support

For questions, contact me on Discord: `._.__.__._._.__._____.__._.___.`

For bugs and feature requests, [open a GitHub issue](https://github.com/ychwu/bdo-toolkit/issues).

## License

bdo-toolkit is available under the
[MIT License](https://github.com/ychwu/bdo-toolkit/blob/main/LICENSE).
