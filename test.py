from bdo_toolkit import capture_live

# This iterator blocks between matching events.
for event in capture_live(
    event_types={"storage_delta"},
    deposit_origins={"worker"},
    opcode_profile="C:/Users/qredn/Desktop/projects/bdo-toolkit/opcodes.local"
):
    print(event.format_human())