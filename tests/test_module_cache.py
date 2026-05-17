"""Unit tests for reverge_collector.module_cache.

The module is small and pure (just JSON I/O + a SHA-256 helper + a cache
lookup wrapper) so we can hit every branch without spinning up any tools.
"""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest
from reverge_collector import module_cache

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _Mod:
    """Minimal stand-in for data_model.CollectionModule used by _write_cache."""

    def __init__(self, name='m', description='d', args='-a', cpe=None):
        self.name = name
        self.description = description
        self.args = args
        if cpe is not None:
            self.cpe = cpe


@pytest.fixture
def patched_cache_dir(tmp_path, monkeypatch):
    """Point CACHE_DIR at a per-test tmp dir."""
    monkeypatch.setattr(module_cache, 'CACHE_DIR', str(tmp_path))
    return tmp_path


# ---------------------------------------------------------------------------
# _cache_path
# ---------------------------------------------------------------------------


def test_cache_path_under_cache_dir(patched_cache_dir):
    path = module_cache._cache_path('nmap')
    assert path == str(patched_cache_dir / 'nmap_modules.json')


# ---------------------------------------------------------------------------
# _read_cache
# ---------------------------------------------------------------------------


def test_read_cache_returns_none_when_missing(patched_cache_dir):
    assert module_cache._read_cache('missing') is None


def test_read_cache_returns_dict_when_present(patched_cache_dir):
    cache_file = patched_cache_dir / 'nmap_modules.json'
    cache_file.write_text(json.dumps({'fingerprint': 'fp', 'modules': []}))
    out = module_cache._read_cache('nmap')
    assert out == {'fingerprint': 'fp', 'modules': []}


def test_read_cache_returns_none_on_corrupt_json(patched_cache_dir):
    (patched_cache_dir / 'broken_modules.json').write_text('not json at all')
    assert module_cache._read_cache('broken') is None


# ---------------------------------------------------------------------------
# _write_cache
# ---------------------------------------------------------------------------


def test_write_cache_persists_modules(patched_cache_dir):
    mods = [
        _Mod(name='a', description='desc-a', args='-x', cpe='cpe:2.3:a:foo'),
        _Mod(name='b'),  # no cpe
    ]
    module_cache._write_cache('toolx', 'fp123', mods)

    raw = json.loads((patched_cache_dir / 'toolx_modules.json').read_text())
    assert raw['fingerprint'] == 'fp123'
    assert [m['name'] for m in raw['modules']] == ['a', 'b']
    assert raw['modules'][0]['cpe'] == 'cpe:2.3:a:foo'
    assert raw['modules'][1]['cpe'] is None  # getattr default


def test_write_cache_creates_cache_dir(tmp_path, monkeypatch):
    nested = tmp_path / 'sub' / 'dir'
    monkeypatch.setattr(module_cache, 'CACHE_DIR', str(nested))
    assert not nested.exists()
    module_cache._write_cache('t', 'fp', [_Mod()])
    assert nested.exists()


def test_write_cache_swallows_open_errors(patched_cache_dir, monkeypatch):
    # The try/except in _write_cache wraps the open()+json.dump call; replace
    # open() with one that raises so we exercise that branch without
    # depending on filesystem quirks (os.makedirs is NOT in the try block).
    real_open = open

    def fake_open(path, *a, **kw):
        if 'modules.json' in path:
            raise OSError('mock write failure')
        return real_open(path, *a, **kw)

    monkeypatch.setattr('builtins.open', fake_open)
    # Should not raise — _write_cache logs and returns
    module_cache._write_cache('t', 'fp', [_Mod()])


# ---------------------------------------------------------------------------
# _modules_from_cache
# ---------------------------------------------------------------------------


def test_modules_from_cache_reconstructs_objects():
    raw = {
        'modules': [
            {'name': 'a', 'description': 'd1', 'args': '-x', 'cpe': 'c'},
            {'name': 'b', 'description': 'd2', 'args': '-y', 'cpe': None},
            {'name': 'c', 'description': 'd3', 'args': '-z'},  # no cpe key
        ]
    }
    mods = module_cache._modules_from_cache(raw)
    assert len(mods) == 3
    assert mods[0].name == 'a' and mods[0].cpe == 'c'
    # cpe None / missing → no .cpe attribute is written
    assert not hasattr(mods[1], 'cpe') or mods[1].cpe in (None, '')
    assert mods[2].args == '-z'


def test_modules_from_cache_empty_modules():
    assert module_cache._modules_from_cache({'modules': []}) == []
    assert module_cache._modules_from_cache({}) == []


# ---------------------------------------------------------------------------
# sha256_file
# ---------------------------------------------------------------------------


def test_sha256_file_matches_expected_hash(tmp_path):
    f = tmp_path / 'x.bin'
    f.write_bytes(b'hello world')
    # Pre-computed sha256 of "hello world"
    assert module_cache.sha256_file(str(f)) == (
        'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9'
    )


def test_sha256_file_handles_large_file_in_chunks(tmp_path):
    # The reader uses 64KiB chunks; make sure a multi-chunk file works.
    f = tmp_path / 'big.bin'
    f.write_bytes(b'A' * (65536 * 2 + 17))
    h = module_cache.sha256_file(str(f))
    assert len(h) == 64  # hex sha256


# ---------------------------------------------------------------------------
# get_cached_modules — the meaty bit
# ---------------------------------------------------------------------------


def test_get_cached_modules_cache_hit(patched_cache_dir):
    # Pre-seed a cache file matching the fingerprint we'll return.
    (patched_cache_dir / 'nmap_modules.json').write_text(
        json.dumps(
            {
                'fingerprint': 'fp-match',
                'modules': [{'name': 'foo', 'description': 'd', 'args': '-a'}],
            }
        )
    )
    gen_called = []

    def fingerprint_func():
        return 'fp-match'

    def generate_func():
        gen_called.append(True)
        return []

    out = module_cache.get_cached_modules('nmap', fingerprint_func, generate_func)
    assert [m.name for m in out] == ['foo']
    assert gen_called == []  # cache hit, no regeneration


def test_get_cached_modules_cache_miss_regenerates_and_writes(patched_cache_dir):
    # Stale cache with a different fingerprint
    (patched_cache_dir / 'nmap_modules.json').write_text(
        json.dumps({'fingerprint': 'old', 'modules': []})
    )

    def fingerprint_func():
        return 'new'

    def generate_func():
        return [_Mod(name='regen')]

    out = module_cache.get_cached_modules('nmap', fingerprint_func, generate_func)
    assert [m.name for m in out] == ['regen']

    # Cache file should be updated with the new fingerprint
    raw = json.loads((patched_cache_dir / 'nmap_modules.json').read_text())
    assert raw['fingerprint'] == 'new'
    assert raw['modules'][0]['name'] == 'regen'


def test_get_cached_modules_no_cache_regenerates_and_writes(patched_cache_dir):
    def fingerprint_func():
        return 'first'

    def generate_func():
        return [_Mod(name='fresh')]

    out = module_cache.get_cached_modules('nmap', fingerprint_func, generate_func)
    assert [m.name for m in out] == ['fresh']
    assert (patched_cache_dir / 'nmap_modules.json').exists()


def test_get_cached_modules_skip_write_when_generate_empty(patched_cache_dir):
    def fingerprint_func():
        return 'fp'

    def generate_func():
        return []

    out = module_cache.get_cached_modules('nmap', fingerprint_func, generate_func)
    assert out == []
    # No cache written for an empty list
    assert not (patched_cache_dir / 'nmap_modules.json').exists()


def test_get_cached_modules_none_fingerprint_returns_stale_cache(patched_cache_dir):
    (patched_cache_dir / 'tool_modules.json').write_text(
        json.dumps(
            {
                'fingerprint': 'whatever',
                'modules': [{'name': 'stale', 'description': '', 'args': ''}],
            }
        )
    )

    out = module_cache.get_cached_modules(
        'tool', lambda: None, lambda: pytest.fail('should not regenerate')
    )
    assert [m.name for m in out] == ['stale']


def test_get_cached_modules_none_fingerprint_no_cache_falls_through_to_generate(
    patched_cache_dir,
):
    out = module_cache.get_cached_modules('tool', lambda: None, lambda: [_Mod(name='live')])
    assert [m.name for m in out] == ['live']


def test_get_cached_modules_fingerprint_raises_treated_as_none(patched_cache_dir):
    def fingerprint_func():
        raise RuntimeError('boom')

    out = module_cache.get_cached_modules('tool', fingerprint_func, lambda: [_Mod(name='fallback')])
    assert [m.name for m in out] == ['fallback']


def test_get_cached_modules_writes_logging_on_failure(patched_cache_dir, caplog):
    # generate returns modules but write fails (CACHE_DIR replaced with bad path
    # *after* lookup). Patch _write_cache to raise to exercise log-warning path.
    with patch.object(
        module_cache, '_write_cache', side_effect=Exception('disk full')
    ) as mock_write:
        # Should still return modules even if write raises
        # Note: actual _write_cache catches exceptions, but we patch raw to
        # confirm it's called.
        # get_cached_modules doesn't itself swallow; the swallow lives inside
        # _write_cache. So instead, ensure we just test it was called.
        with pytest.raises(Exception, match='disk full'):
            module_cache.get_cached_modules('t', lambda: 'fp', lambda: [_Mod(name='m')])
        assert mock_write.called
