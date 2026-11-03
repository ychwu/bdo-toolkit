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

Each character has `main_inventory`, `pearl_inventory`, `gear`, `life_skills` and `other_inventory`. Check each section’s `status` and `observed_sources` before replacing saved data. An unavailable section gives no evidence that the player emptied it. If the roster itself is unavailable, inspect `characters.warnings` and continue using the available inventory and storage results.

Place gear using `role`, and life gear using `activity` plus `role`. Preserve `source` and `raw_slot` when a label is unknown. The hunting and farming knot assignments (life slots 53 and 54) carry `role_inferred`. For equipped artifacts with a decoded socket layout, `lightstones` preserves both socket positions, with `null` for an empty socket. An empty list provides no socket reading. Loose artifacts in bags and town storage currently provide no socket reading.

## Calibrate after a patch

Character calibration can run independently of inventory-transfer calibration. It uses raw login traffic and requires no character name. Run from a directory containing the item profile, or choose an output path beside it.

```powershell
python -m bdo_toolkit.cli character-calibrate --live --capture-seconds 120 --save-pcap login.pcap --output opcodes.local.characters.json
```

Enter the world after the capture-ready message and let the timer finish. To replay, replace `--live --capture-seconds 120 --save-pcap login.pcap` with `--pcap login.pcap`. Use `--overwrite` to replace an existing character profile. An optional `--previous-profile` and matching `--reference-pcap` can corroborate layouts that a single login leaves unresolved.

The CLI saves a profile and exits 0 when it finds a unique corroborated remote inventory and roster layout. Read the per-family results even when `usable` is true. Stats, active gear, life gear, identity and remote lightstone offsets may be unavailable. If the core evidence is insufficient or ambiguous, the CLI reports `usable: false`, exits 2 and writes no profile.

The importer looks for `<item-profile>.characters.json` by default. Pass `character_profile=` to select another layout. With no sidecar it tries the built-in November layout. Start a new session after updating the profile.

## Research TODO

- Verify socket contents on unequipped artifacts in character bags and town storage before exposing those fields. Compare a known socketed artifact across locations and validate each packet layout independently.
- Investigate blind calibration when bag rows also contain socket data. The August 31 and September 1 captures required a verified reference to recover the remote offsets.
