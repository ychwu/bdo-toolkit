"""Private archive routing must fail closed without weakening public-clone tests."""
import json
from pathlib import Path

import pytest

from fixture_paths import CaptureCatalog


def _catalog(tmp_path, *, entries=None, profiles=None):
    path = tmp_path / 'catalog.json'
    path.write_text(json.dumps({
        'schema_version': 1,
        'profiles': profiles or {},
        'captures': entries or [],
    }), encoding='utf-8')
    return CaptureCatalog(path)


def _entry(capture_id='sample', path='patches/known/storage/deposit.pcapng', **changes):
    return {
        'id': capture_id, 'path': path, 'profile_id': None,
        'profile_status': 'missing', 'baseline': None,
        'legacy_names': ['old-name.pcapng'], 'source_paths': [], **changes,
    }


def test_absent_archive_is_optional_but_required_lookup_fails(tmp_path):
    catalog = CaptureCatalog(tmp_path / 'catalog.json')
    assert catalog.entries == []
    assert not catalog.capture_path('sample', required=False).exists()
    with pytest.raises(FileNotFoundError, match='catalog'):
        catalog.capture_path('sample')


def test_pinned_profile_and_legacy_alias_survive_path_reorganization(tmp_path):
    entry = _entry(profile_id='historical', baseline={'path': 'baselines/sample.jsonl'})
    catalog = _catalog(tmp_path, entries=[entry], profiles={
        'historical': {'path': 'patches/known/profiles/items.json'}
    })
    capture = catalog.path(entry['path'])
    capture.parent.mkdir(parents=True)
    capture.write_bytes(b'private fixture placeholder')
    profile = catalog.path('patches/known/profiles/items.json')
    profile.parent.mkdir(parents=True)
    profile.write_text('{}')
    assert catalog.capture_path('sample') == capture
    assert catalog.capture_path('old-name.pcapng') == capture
    assert catalog.profile_path(catalog.for_path(capture)) == profile
    profile.unlink()
    with pytest.raises(FileNotFoundError, match='recorded profile'):
        catalog.profile_path(entry)


@pytest.mark.parametrize('status', ['missing', 'not-required'])
def test_unpaired_capture_never_falls_back_to_an_available_profile(tmp_path, status):
    entry = _entry(profile_status=status)
    catalog = _catalog(tmp_path, entries=[entry], profiles={'other-era': {'path': 'other.json'}})
    (tmp_path / 'other.json').write_text('{}')
    with pytest.raises(ValueError, match='no item profile'):
        catalog.profile_path(entry)


def test_ambiguous_alias_and_unknown_id_do_not_pick_a_capture(tmp_path):
    catalog = _catalog(tmp_path, entries=[_entry(), _entry('second', 'second.pcapng')])
    for name in ('old-name.pcapng', 'typo'):
        with pytest.raises(ValueError, match='unknown or ambiguous'):
            catalog.capture_path(name, required=False)
    assert catalog.entry('sample')['id'] == 'sample'


@pytest.mark.parametrize('field', ['capture', 'profile', 'baseline'])
def test_catalog_cannot_route_outside_its_private_root(tmp_path, field):
    entry = _entry()
    profiles = {}
    if field == 'capture':
        entry['path'] = '../outside.pcapng'
    elif field == 'profile':
        entry['profile_id'] = 'escape'
        profiles['escape'] = {'path': '../outside.json'}
    else:
        entry['baseline'] = {'path': '../outside.jsonl'}
    with pytest.raises(ValueError, match='escapes archive'):
        _catalog(tmp_path, entries=[entry], profiles=profiles)


@pytest.mark.parametrize('duplicate', ['id', 'path'])
def test_duplicate_catalog_identity_is_rejected(tmp_path, duplicate):
    second = _entry('second', 'second.pcapng')
    second[duplicate] = _entry()[duplicate]
    with pytest.raises(ValueError, match='duplicate capture'):
        _catalog(tmp_path, entries=[_entry(), second])
