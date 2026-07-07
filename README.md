# BDO Toolkit

Passive, read-only packet telemetry tooling for developers building BDO helper
apps.

The toolkit goal is simple:

```text
packet capture or pcap replay in -> structured gameplay item events out
```

Example app code:

```python
from bdo_toolkit import replay_pcap

for event in replay_pcap("session.pcapng", sources={"Mob Drop"}):
    print(event.item_id, event.quantity)
```

Live capture is also exposed:

```python
from bdo_toolkit import capture_live

for event in capture_live(event_types={"storage_delta"}, sources={"Worker Deposit"}):
    print(event.to_dict())
```

## Current Status

This folder is an isolated prototype workspace intended to move into its own
repository later. It currently uses `home_internet_analyzer.py` through a
transitional `legacy_bridge` module so the public API can be tested before the
parser internals are fully migrated.

The public API is designed to stay stable while the internals change:

```text
bdo_toolkit.replay_pcap(...)
bdo_toolkit.capture_live(...)
BDOEvent.to_dict()
BDOEvent.format_human()
ConsoleEventWriter
JsonlEventWriter
EventFilter
```

## Design Principles

- Passive/read-only only: never inject, send, delay, replay, or modify packets.
- Decode all known categories in the engine, then let apps filter events.
- Keep opcode profiles data-driven and easy to replace after patches.
- Treat packet knowledge as provisional unless repeated captures prove it.
- Preserve raw fields and add new event fields without breaking old apps.

## Layout

```text
src/bdo_toolkit/
  capture.py          Live capture and pcap replay entry points
  events.py           Stable app-facing event model
  filters.py          Event filtering helpers
  legacy_bridge.py    Temporary adapter to the current prototype parser
  profiles.py         Opcode profile loading
  writers.py          Console and JSONL writers

examples/
  simple_log.py
  grind_loot_counter.py
  worker_production_log.py
  live_mob_drops.py

profiles/
  opcodes.json        Current active opcode profile copy

docs/
  PACKET_PROTOCOL_WIKI.md
  CONTEXT.md
  AGENT_CONTEXT.md
  HANDOFF.md
```

## Event Types

Current app-facing event types:

```text
loot_preview       A preview/offered item record, currently gathering-focused
item_received      Inventory receipt/update such as mob drops, gathering, storage pulls
storage_delta      Item added to storage, including manual deposits and worker deposits
```

Event objects intentionally include both normalized fields and an `extra`
mapping for newly discovered packet fields.

## Quick Start From This Repo

From the parent repo root:

```powershell
$env:PYTHONPATH="bdo-toolkit\src;."
py - <<'PY'
from bdo_toolkit import replay_pcap

for event in replay_pcap("captures/fixtures/5960_qty1_and_4015_qty1_multi.pcapng"):
    print(event.format_human())
PY
```

Run tests from the parent repo root:

```powershell
py -m unittest discover -s tests
```

## Migration Plan

1. Keep the prototype script stable.
2. Build app-facing package APIs in this isolated folder.
3. Move TCP reassembly into native package modules.
4. Move BDO frame parsing into native package modules.
5. Move decoders by category: inventory receipts, storage deltas, snapshots.
6. Replace `legacy_bridge.py` with native orchestration.
7. Move this folder into its own repo.

