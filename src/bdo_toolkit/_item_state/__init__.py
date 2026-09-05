"""Private implementation of the experimental item-state APIs.

Public entry points remain in ``bdo_toolkit.item_state`` and
``bdo_toolkit.character_state``. Internal dependencies flow from constants and
models through frame records and inventory/storage inference to assembly and
session lifecycle. Formatting reads models. Modules here must not import the
public facades or add packet-capture ownership to the inference layers.
"""
