"""Public Agris configuration and immutable balance-only serialization."""

from dataclasses import FrozenInstanceError

import pytest

from bdo_toolkit.agris._discovery import AgrisTracker
from bdo_toolkit.agris._validation import validate_expected_maximum_points
from bdo_toolkit.agris.models import AgrisBalance, AgrisDiscoveryOptions, AgrisLayout, AgrisStatus
from bdo_toolkit.events import Flow


@pytest.mark.parametrize("value", [True, False, None, "100000", 100000.0])
def test_cap_rejects_nonintegers(value):
    with pytest.raises(TypeError, match="expected_maximum_points"):
        validate_expected_maximum_points(value)
    with pytest.raises(TypeError, match="expected_maximum_points"):
        AgrisTracker(expected_maximum_points=value)


@pytest.mark.parametrize("value", [0, -1, 2**32])
def test_cap_rejects_outside_uint32(value):
    with pytest.raises(ValueError, match="expected_maximum_points"):
        validate_expected_maximum_points(value)


@pytest.mark.parametrize("value", [1, 60000, 100000, 0xFFFFFFFF])
def test_cap_accepts_explicit_uint32(value):
    assert validate_expected_maximum_points(value) == value


def test_tracker_has_no_implicit_cap():
    with pytest.raises(TypeError, match="expected_maximum_points"):
        AgrisTracker()


@pytest.mark.parametrize("name", ["minimum_updates", "max_families", "max_columns", "max_candidates"])
@pytest.mark.parametrize("value", [True, False, 1.5, "5", None])
def test_integer_discovery_options_are_strict(name, value):
    with pytest.raises(TypeError, match=name):
        AgrisDiscoveryOptions(**{name: value})


@pytest.mark.parametrize("name", ["minimum_updates", "max_families", "max_columns", "max_candidates"])
@pytest.mark.parametrize("value", [-1, 0])
def test_discovery_limits_are_positive(name, value):
    with pytest.raises(ValueError, match=name):
        AgrisDiscoveryOptions(**{name: value})


@pytest.mark.parametrize("value", [1, 2])
def test_discovery_needs_at_least_three_distinct_balances(value):
    with pytest.raises(ValueError, match="minimum_updates"):
        AgrisDiscoveryOptions(minimum_updates=value)


@pytest.mark.parametrize("value", [True, None, "3"])
def test_settling_rejects_nonnumeric_options(value):
    with pytest.raises(TypeError, match="settle_seconds"):
        AgrisDiscoveryOptions(settle_seconds=value)


@pytest.mark.parametrize("value", [-0.1, float("nan"), float("inf"), -float("inf")])
def test_settling_rejects_negative_or_nonfinite(value):
    with pytest.raises(ValueError, match="settle_seconds"):
        AgrisDiscoveryOptions(settle_seconds=value)


def test_models_are_frozen_and_serialization_is_balance_only():
    flow = Flow("192.0.2.1", 8889, "192.0.2.2", 41000)
    balance = AgrisBalance(99960, 100000, 12.5, flow, 1)
    layout = AgrisLayout(0x1234, 40, 9, 13, flow, 1)
    status = AgrisStatus("tracking", 100000, balance, (layout,), 12)
    for model in (balance, layout, status, AgrisDiscoveryOptions()):
        with pytest.raises(FrozenInstanceError):
            model.extra = True
    assert balance.to_dict() == {
        "schema_version": 1,
        "event_type": "agris_balance",
        "remaining_points": 99960,
        "maximum_points": 100000,
        "observed_at": 12.5,
        "flow": flow.to_dict(),
        "connection_epoch": 1,
        "confidence": "inferred",
    }
    assert status.to_dict()["balance"] == balance.to_dict()
    assert status.to_dict()["candidates"] == [layout.to_dict()]
    dumped = balance.to_dict()
    dumped["flow"]["source_ip"] = "changed"
    assert balance.flow.source_ip == "192.0.2.1"


def test_status_copies_runtime_list_to_immutable_tuple():
    candidates = []
    status = AgrisStatus("searching", 100000, None, candidates, 0)
    candidates.append("not a layout")
    assert status.candidates == ()
