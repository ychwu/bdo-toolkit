"""Public import and annotation contracts across private package refactors."""

import pickle
from typing import get_type_hints

from bdo_toolkit import calibration


def test_calibration_public_objects_keep_pickle_and_annotation_contracts():
    for name in calibration.__all__:
        obj = getattr(calibration, name)
        if not callable(obj):
            continue
        assert pickle.loads(pickle.dumps(obj)) is obj
        get_type_hints(obj)
        if name != "ProfileError":
            assert obj.__module__ == "bdo_toolkit.calibration"
