# Character loadouts and calibration

A normal world login can supply per-character inventories and equipment alongside the active inventory and town storage. Start capture before entering the world. For town storage, use the first login after a fresh launch. A character switch may supply character data without a town storage load.

## Read a snapshot

`CharacterLoadSession(opcode_profile="opcodes.local")` includes characters by default. Call `start()` before entering the world and `stop()` after loading settles. Saved captures use the same snapshot contract.

```python
from bdo_toolkit.item_state import analyze_item_state_pcap

snapshot = analyze_item_state_pcap("login.pcap", opcode_profile="opcodes.local")
roster = snapshot.to_dict()["characters"]
for owner_id, character in roster["by_id"].items():
    if character["gear"]["observed"]:
        for item in character["gear"]["items"]:
            print(owner_id, item["role"], item["raw_slot"], item["base_item_id"])
```

Use the opaque `owner_id` to associate a character with an app’s saved label. The same IDs recurred across the historical captures tested. A name can be available for the logged-in character. Remote names, class and level can be unknown. `raw_metadata_value` has no verified meaning. Combat stats are optional.

Each character has `main_inventory`, `pearl_inventory`, `gear`, `life_skills` and `other_inventory`. For each section, `available` replaces saved items, including with an empty list. `unavailable` preserves the previous observation. Inspect `characters.warnings` separately from inventory and town storage results.

For remote characters, the importer checks that the inventory pages occupy consecutive bytes on the same connection and that a different framed message touches each end. If any page or either boundary is missing, the whole remote item table is withheld. A complete table covers main inventory, Pearl inventory, equipment and other inventory for each owner with remote rows. An owner found only in validated combat stats is covered when the active character is known and is someone else. A roster entry alone never establishes an empty section.

Life skills combine equipment-wheel tools and a separate life-gear list. Both sources are needed to replace the whole section. A remote fishing rod or hunting weapon may appear under `items` with `observed_sources` even when the section is `unavailable`. It can be displayed without deleting previously saved life gear.

Place gear using `role`, and life gear using `activity` plus `role`. Preserve `source` and `raw_slot` when a label is unknown. The hunting and farming knot assignments (life slots 53 and 54) carry `role_inferred`. For equipped artifacts with a decoded socket layout, `lightstones` preserves both socket positions, with `null` for an empty socket. An empty list provides no socket reading. Loose artifacts in bags and town storage currently provide no socket reading.

## Calibrate after a patch

Character calibration uses one normal login and requires no character name. Run it before or after inventory-transfer calibration. Both can share one `opcodes.local`.

```powershell
python -m bdo_toolkit.cli character-calibrate --live --capture-seconds 120 --save-pcap login.pcap --profile opcodes.local
```

Enter the world after the capture-ready message and let the timer finish. To replay, replace `--live --capture-seconds 120 --save-pcap login.pcap` with `--pcap login.pcap`. The CLI defaults to `opcodes.local` in the current directory. Success replaces only its `characters` section, backs up a changed existing profile in `opcodes_backups/`, or creates a profile if needed. An optional `--previous-profile` and matching `--reference-pcap` can corroborate layouts that a single login leaves unresolved.

The CLI saves a profile and exits 0 when it finds a unique corroborated remote inventory and roster layout. Read the per-family results even when `usable` is true. Stats, active gear, life gear, identity and remote lightstone offsets may be unavailable. If the core evidence is insufficient or ambiguous, the CLI reports `usable: false`, exits 2 and writes no profile.

Live and replay use an explicit `character_profile=` override first, then the embedded `characters` section. If that section is absent, they look for the existing `<item-profile>.characters.json` sidecar. If both are absent they try the built-in November layout. A malformed embedded section makes character data unavailable and supplies a warning. Inventory and storage can still decode. Start a new session after updating the profile.

For a standalone layout file, the existing CLI form `--output opcodes.local.characters.json` remains supported. Use `--overwrite` to replace that standalone file.

## Research TODO

- Verify socket contents on unequipped artifacts in character bags and town storage before exposing those fields. Compare a known socketed artifact across locations and validate each packet layout independently.
- Investigate blind calibration when bag rows also contain socket data. The August 31 and September 1 captures required a verified reference to recover the remote offsets.
