"""Equipment semantics verified on normal-login captures from November 2026."""

GEAR = {
    0: "main_hand",
    1: "off_hand",
    3: "body_armor",
    4: "gloves",
    5: "shoes",
    6: "helmet",
    7: "necklace",
    8: "ring_1",
    9: "ring_2",
    10: "earring_1",
    11: "earring_2",
    12: "belt",
    14: "outfit_body",
    15: "outfit_gloves",
    16: "outfit_shoes",
    17: "outfit_helmet",
    18: "outfit_main_hand",
    19: "outfit_off_hand",
    20: "underwear",
    21: "head_accessory",
    22: "eye_accessory",
    23: "lower_face_accessory",
    27: "alchemy_stone",
    29: "awakening_weapon",
    30: "outfit_awakening_weapon",
    31: "tome",
    32: "artifact_1",
    33: "artifact_2",
    45: "carrier",
}
MAIN_LIFE = {
    40: ("fishing", "rod"),
    41: ("fishing", "float"),
    42: ("fishing", "harpoon"),
    43: ("hunting", "matchlock"),
    44: ("hunting", "sniper_rifle"),
}

LIFE: dict[int, tuple[str, str]] = {}
for start, activity, roles in (
    (
        0,
        "gathering",
        "axe fluid_collector hoe butcher_knife tanning_knife pickaxe clothes artifact_1 artifact_2",
    ),
    (9, "fishing", "clothes chair artifact_1 artifact_2"),
    (13, "hunting", "clothes bag artifact_1 artifact_2"),
    (17, "cooking", "clothes ladle artifact_1 artifact_2"),
    (21, "alchemy", "clothes flask artifact_1 artifact_2"),
    (25, "processing", "clothes processing_stone artifact_1 artifact_2"),
    (29, "training", "clothes riding_crop artifact_1 artifact_2"),
    (33, "trading", "clothes artifact_1 artifact_2"),
    (36, "sailing", "clothes sailing_log artifact_1 artifact_2"),
    (43, "farming", "clothes artifact_1 artifact_2"),
    (46, "shared", "necklace belt ring_1 ring_2 earring_1 earring_2 alchemy_stone"),
    (55, "processing", "knot"),
    (56, "cooking", "knot"),
    (57, "alchemy", "knot"),
    (58, "training", "knot"),
    (59, "shared", "orb"),
):
    LIFE.update({start + i: (activity, role) for i, role in enumerate(roles.split())})

# Neither knot was present in the reference captures. Keep the chosen order
# explicit and surface its uncertainty on every item using these positions.
INFERRED_LIFE = {53: ("hunting", "knot"), 54: ("farming", "knot")}
LIFE.update(INFERRED_LIFE)
