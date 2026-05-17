"""Tests for data_model.ScheduledScan.__init__ wordlist + interface branches.

These exercise the per-tool wordlist setup logic — fresh download, cached
hit, hash-mismatch re-download, missing-hash re-download, and the I/O
fallback — without going through the full route-test scaffolding.
"""

from __future__ import annotations

import json
import os
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from reverge_collector import data_model
from reverge_collector.data_model import (
    CollectionToolStatus,
    ScheduledScan,
    wordlist_path,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_wordlist(wid: str, whash: str = 'h'):
    return SimpleNamespace(id=wid, hash=whash)


def make_tool(
    tool_id: str = 't1',
    name: str = 'nmap',
    *,
    enabled: int = 1,
    status: int = CollectionToolStatus.CREATED.value,
    wordlists=None,
):
    if wordlists is None:
        wordlists = []
    inner = SimpleNamespace(
        wordlists=wordlists,
        name=name,
        args='',
    )
    return SimpleNamespace(
        id=tool_id,
        enabled=enabled,
        status=status,
        collection_tool=inner,
        args_override=None,
    )


def make_scheduled_input(tools, scan_id='scan-xyz', sched_id='sch-xyz', target_id=1):
    return SimpleNamespace(
        id=sched_id,
        scan_id=scan_id,
        target_id=target_id,
        collection_tools=tools,
    )


def make_scan_thread(*, scan_obj=None, wordlist_payload=None):
    """Return a minimal scan_thread.recon_manager spy."""
    rm = MagicMock()
    rm.get_scheduled_scan.return_value = scan_obj
    rm.get_wordlist.return_value = wordlist_payload
    rm.update_scan_status.return_value = ''
    rm.update_tool_status.return_value = ''
    return SimpleNamespace(recon_manager=rm)


def empty_scope():
    """Tiny valid scope_dict — no obj_list entries, no ports."""
    return {
        'b64_port_bitmap': '',
        'obj_list': [],
    }


# ---------------------------------------------------------------------------
# Status & enable handling
# ---------------------------------------------------------------------------


def test_init_skips_completed_tool():
    tool_done = make_tool(tool_id='t-done', status=CollectionToolStatus.COMPLETED.value)
    tool_active = make_tool(tool_id='t-live', status=CollectionToolStatus.CREATED.value)
    sched = make_scheduled_input([tool_done, tool_active])
    thread = make_scan_thread(scan_obj={'scan_id': 's', 'scope': empty_scope()})
    s = ScheduledScan(thread, sched)
    assert 't-done' not in s.collection_tool_map
    assert 't-live' in s.collection_tool_map


def test_init_includes_disabled_tool_without_wordlist_fetch():
    """enabled=0 → tool still in map, but get_wordlist is never called."""
    tool = make_tool(tool_id='t-off', enabled=0, wordlists=[make_wordlist('w1')])
    sched = make_scheduled_input([tool])
    thread = make_scan_thread(scan_obj={'scan_id': 's', 'scope': empty_scope()})
    s = ScheduledScan(thread, sched)
    assert 't-off' in s.collection_tool_map
    thread.recon_manager.get_wordlist.assert_not_called()
    assert tool.collection_tool.wordlist_path is None


# ---------------------------------------------------------------------------
# Wordlist download paths
# ---------------------------------------------------------------------------


def _wordlist_file(wid):
    return os.path.join(wordlist_path, str(wid))


@pytest.fixture
def clean_wordlist_files():
    """Remove any test wordlist files before + after each test."""
    # Use unique-enough IDs to avoid colliding with real ones
    test_ids = ['wl-fresh', 'wl-cached', 'wl-mismatch', 'wl-nohash', 'wl-bad-json']
    tool_ids = ['t-dl', 't-cache', 't-mismatch', 't-nohash', 't-bad']
    paths = [_wordlist_file(x) for x in test_ids + tool_ids]
    for p in paths:
        if os.path.exists(p):
            os.remove(p)
    yield
    for p in paths:
        if os.path.exists(p):
            os.remove(p)


def test_init_downloads_wordlist_when_file_missing(clean_wordlist_files):
    payload = {'hash': 'h1', 'words': ['a', 'b', 'c']}
    tool = make_tool(tool_id='t-dl', wordlists=[make_wordlist('wl-fresh', 'h1')])
    sched = make_scheduled_input([tool])
    thread = make_scan_thread(
        scan_obj={'scan_id': 's', 'scope': empty_scope()},
        wordlist_payload=payload,
    )
    s = ScheduledScan(thread, sched)
    # Downloaded once
    thread.recon_manager.get_wordlist.assert_called_once_with('wl-fresh')
    # File written
    assert os.path.exists(_wordlist_file('wl-fresh'))
    # Combined wordlist file at tool id path written with the three words
    combined = _wordlist_file('t-dl')
    assert os.path.exists(combined)
    with open(combined) as f:
        body = f.read()
    assert 'a' in body and 'b' in body and 'c' in body
    # Wordlist path attached to tool
    assert tool.collection_tool.wordlist_path == combined
    assert 't-dl' in s.collection_tool_map


def test_init_uses_cached_wordlist_when_hash_matches(clean_wordlist_files):
    payload = {'hash': 'cached-h', 'words': ['x', 'y']}
    # Pre-populate cache
    with open(_wordlist_file('wl-cached'), 'w') as f:
        json.dump(payload, f)
    tool = make_tool(tool_id='t-cache', wordlists=[make_wordlist('wl-cached', 'cached-h')])
    sched = make_scheduled_input([tool])
    thread = make_scan_thread(scan_obj={'scan_id': 's', 'scope': empty_scope()})
    ScheduledScan(thread, sched)
    # No re-download — cache hit
    thread.recon_manager.get_wordlist.assert_not_called()
    combined = _wordlist_file('t-cache')
    assert os.path.exists(combined)


def test_init_redownloads_when_cached_hash_mismatches(clean_wordlist_files):
    cached = {'hash': 'old', 'words': ['old1']}
    fresh = {'hash': 'new', 'words': ['new1', 'new2']}
    with open(_wordlist_file('wl-mismatch'), 'w') as f:
        json.dump(cached, f)
    tool = make_tool(tool_id='t-mismatch', wordlists=[make_wordlist('wl-mismatch', 'new')])
    sched = make_scheduled_input([tool])
    thread = make_scan_thread(
        scan_obj={'scan_id': 's', 'scope': empty_scope()},
        wordlist_payload=fresh,
    )
    ScheduledScan(thread, sched)
    # Re-downloaded because cached hash != requested hash
    thread.recon_manager.get_wordlist.assert_called_once_with('wl-mismatch')
    with open(_wordlist_file('wl-mismatch')) as f:
        on_disk = json.load(f)
    assert on_disk['hash'] == 'new'


def test_init_redownloads_when_cached_lacks_hash_field(clean_wordlist_files):
    cached_no_hash = {'words': ['x']}  # no 'hash' key
    fresh = {'hash': 'fresh', 'words': ['y']}
    with open(_wordlist_file('wl-nohash'), 'w') as f:
        json.dump(cached_no_hash, f)
    tool = make_tool(tool_id='t-nohash', wordlists=[make_wordlist('wl-nohash', 'fresh')])
    sched = make_scheduled_input([tool])
    thread = make_scan_thread(
        scan_obj={'scan_id': 's', 'scope': empty_scope()},
        wordlist_payload=fresh,
    )
    ScheduledScan(thread, sched)
    # The 'no hash' branch raises and falls into the except → re-download
    thread.recon_manager.get_wordlist.assert_called_once_with('wl-nohash')


def test_init_redownloads_when_cached_file_is_invalid_json(clean_wordlist_files):
    # Write garbage that won't parse
    with open(_wordlist_file('wl-bad-json'), 'w') as f:
        f.write('{not-json')
    fresh = {'hash': 'ok', 'words': ['recovered']}
    tool = make_tool(tool_id='t-bad', wordlists=[make_wordlist('wl-bad-json', 'ok')])
    sched = make_scheduled_input([tool])
    thread = make_scan_thread(
        scan_obj={'scan_id': 's', 'scope': empty_scope()},
        wordlist_payload=fresh,
    )
    ScheduledScan(thread, sched)
    thread.recon_manager.get_wordlist.assert_called_once_with('wl-bad-json')


def test_init_skips_combined_file_when_no_words(clean_wordlist_files):
    """Wordlist with empty 'words' → no combined file written."""
    payload = {'hash': 'h', 'words': []}
    tool = make_tool(tool_id='t-empty', wordlists=[make_wordlist('wl-empty', 'h')])
    sched = make_scheduled_input([tool])
    thread = make_scan_thread(
        scan_obj={'scan_id': 's', 'scope': empty_scope()},
        wordlist_payload=payload,
    )
    try:
        ScheduledScan(thread, sched)
        # Tool's wordlist_path stays None when there were no words
        assert tool.collection_tool.wordlist_path is None
    finally:
        for p in (_wordlist_file('wl-empty'), _wordlist_file('t-empty')):
            if os.path.exists(p):
                os.remove(p)


# ---------------------------------------------------------------------------
# Server response validation
# ---------------------------------------------------------------------------


def test_init_raises_when_scan_obj_is_none():
    tool = make_tool()
    sched = make_scheduled_input([tool])
    thread = make_scan_thread(scan_obj=None)
    with pytest.raises(RuntimeError, match='No scan object'):
        ScheduledScan(thread, sched)


def test_init_raises_when_scan_id_missing():
    tool = make_tool()
    sched = make_scheduled_input([tool])
    thread = make_scan_thread(scan_obj={'scope': empty_scope()})
    with pytest.raises(RuntimeError, match='No scan object'):
        ScheduledScan(thread, sched)


def test_init_raises_when_scan_id_is_none():
    tool = make_tool()
    sched = make_scheduled_input([tool])
    thread = make_scan_thread(scan_obj={'scan_id': None, 'scope': empty_scope()})
    with pytest.raises(RuntimeError, match='No scan object'):
        ScheduledScan(thread, sched)


def test_init_raises_when_scope_missing():
    tool = make_tool()
    sched = make_scheduled_input([tool])
    thread = make_scan_thread(scan_obj={'scan_id': 's'})  # no 'scope'
    with pytest.raises(RuntimeError, match='No scan scope'):
        ScheduledScan(thread, sched)


def test_init_raises_when_scope_is_none():
    tool = make_tool()
    sched = make_scheduled_input([tool])
    thread = make_scan_thread(scan_obj={'scan_id': 's', 'scope': None})
    with pytest.raises(RuntimeError, match='No scan scope'):
        ScheduledScan(thread, sched)


# ---------------------------------------------------------------------------
# Interface handling
# ---------------------------------------------------------------------------


def test_init_sets_selected_interface_when_present():
    tool = make_tool()
    sched = make_scheduled_input([tool])
    thread = make_scan_thread(
        scan_obj={
            'scan_id': 's',
            'scope': empty_scope(),
            'interface': {'name': 'eth0', 'ip': '10.0.0.1'},
        }
    )
    s = ScheduledScan(thread, sched)
    assert s.selected_interface == {'name': 'eth0', 'ip': '10.0.0.1'}


def test_init_selected_interface_is_none_when_omitted():
    tool = make_tool()
    sched = make_scheduled_input([tool])
    thread = make_scan_thread(scan_obj={'scan_id': 's', 'scope': empty_scope()})
    s = ScheduledScan(thread, sched)
    assert s.selected_interface is None


def test_init_selected_interface_is_none_when_falsy():
    """An empty dict / falsy interface is treated as not-set."""
    tool = make_tool()
    sched = make_scheduled_input([tool])
    thread = make_scan_thread(
        scan_obj={'scan_id': 's', 'scope': empty_scope(), 'interface': {}}
    )
    s = ScheduledScan(thread, sched)
    assert s.selected_interface is None


# ---------------------------------------------------------------------------
# Misc invariants
# ---------------------------------------------------------------------------


def test_init_calls_update_scan_status_with_running():
    """The constructor should announce RUNNING to the server."""
    tool = make_tool()
    sched = make_scheduled_input([tool])
    thread = make_scan_thread(scan_obj={'scan_id': 'fresh-scan-id', 'scope': empty_scope()})
    s = ScheduledScan(thread, sched)
    thread.recon_manager.update_scan_status.assert_called_with(
        s.id, data_model.ScanStatus.RUNNING.value
    )


def test_init_overrides_scan_id_with_server_value():
    tool = make_tool()
    sched = make_scheduled_input([tool], scan_id='local-id')
    thread = make_scan_thread(scan_obj={'scan_id': 'server-id', 'scope': empty_scope()})
    s = ScheduledScan(thread, sched)
    assert s.scan_id == 'server-id'


def test_init_has_pending_imports_starts_false():
    tool = make_tool()
    sched = make_scheduled_input([tool])
    thread = make_scan_thread(scan_obj={'scan_id': 's', 'scope': empty_scope()})
    s = ScheduledScan(thread, sched)
    assert s.has_pending_imports is False
