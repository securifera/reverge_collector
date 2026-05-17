"""Tests for reverge_collector.tool_runner — idempotency helpers."""

from __future__ import annotations

import json
import os
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from reverge_collector import tool_runner


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------


def test_get_pre_import_marker_lives_alongside_output():
    out = '/scans/abc/tool-outputs/nmap_out.xml'
    assert (
        tool_runner.get_pre_import_marker(out)
        == '/scans/abc/tool-outputs/tool_pre_import_json'
    )


def test_get_import_marker_lives_alongside_output():
    out = '/scans/abc/tool-outputs/nmap_out.xml'
    assert (
        tool_runner.get_import_marker(out)
        == '/scans/abc/tool-outputs/tool_import_json'
    )


# ---------------------------------------------------------------------------
# import_already_done
# ---------------------------------------------------------------------------


def test_import_already_done_false_when_marker_missing(tmp_path):
    out = tmp_path / 'scan_out.xml'
    out.write_text('placeholder')
    scan_obj = SimpleNamespace(scan_data=MagicMock())
    assert tool_runner.import_already_done(scan_obj, str(out)) is False


def test_import_already_done_true_when_marker_present(tmp_path):
    out = tmp_path / 'scan_out.xml'
    out.write_text('placeholder')
    marker = tmp_path / 'tool_import_json'
    marker.write_text(json.dumps([{'id': 'rec1', 'type': 'host'}]))

    scan_data = MagicMock()
    scan_obj = SimpleNamespace(scan_data=scan_data)
    assert tool_runner.import_already_done(scan_obj, str(out)) is True
    # And the cached import_arr was applied to scope
    scan_data.update.assert_called_once_with([{'id': 'rec1', 'type': 'host'}])


def test_import_already_done_with_empty_marker_still_true(tmp_path):
    out = tmp_path / 'o.xml'
    out.write_text('x')
    (tmp_path / 'tool_import_json').write_text('')
    scan_obj = SimpleNamespace(scan_data=MagicMock())
    # Empty file is treated as "already done" (no scope to restore)
    assert tool_runner.import_already_done(scan_obj, str(out)) is True


def test_import_already_done_corrupt_marker_still_true(tmp_path):
    out = tmp_path / 'o.xml'
    out.write_text('x')
    (tmp_path / 'tool_import_json').write_text('this is not json')
    scan_obj = SimpleNamespace(scan_data=MagicMock())
    # JSON error is logged but treated as "already done"
    assert tool_runner.import_already_done(scan_obj, str(out)) is True


# ---------------------------------------------------------------------------
# load_pre_import_arr
# ---------------------------------------------------------------------------


def test_load_pre_import_arr_returns_none_when_missing(tmp_path):
    out = tmp_path / 'o.xml'
    out.write_text('x')
    assert tool_runner.load_pre_import_arr(str(out)) is None


def test_load_pre_import_arr_returns_parsed_json(tmp_path):
    out = tmp_path / 'o.xml'
    out.write_text('x')
    payload = [{'id': 'r1'}, {'id': 'r2'}]
    (tmp_path / 'tool_pre_import_json').write_text(json.dumps(payload))
    assert tool_runner.load_pre_import_arr(str(out)) == payload


def test_load_pre_import_arr_empty_returns_none(tmp_path):
    out = tmp_path / 'o.xml'
    out.write_text('x')
    (tmp_path / 'tool_pre_import_json').write_text('')
    assert tool_runner.load_pre_import_arr(str(out)) is None


def test_load_pre_import_arr_corrupt_returns_none(tmp_path):
    out = tmp_path / 'o.xml'
    out.write_text('x')
    (tmp_path / 'tool_pre_import_json').write_text('not json')
    assert tool_runner.load_pre_import_arr(str(out)) is None


# ---------------------------------------------------------------------------
# _remap_import_arr
# ---------------------------------------------------------------------------


def test_remap_import_arr_no_op_when_map_empty():
    arr = [{'id': 'r1'}, {'id': 'r2'}]
    assert tool_runner._remap_import_arr(arr, None) is arr
    assert tool_runner._remap_import_arr(arr, []) is arr


def test_remap_import_arr_substitutes_ids():
    arr = [
        {'id': 'orig-1', 'parent': {'id': 'orig-1'}},
        {'id': 'orig-2'},
    ]
    updated_map = [
        {'orig_id': 'orig-1', 'db_id': 'db-1'},
        {'orig_id': 'orig-2', 'db_id': 'db-2'},
    ]
    out = tool_runner._remap_import_arr(arr, updated_map)
    assert out[0]['id'] == 'db-1'
    assert out[0]['parent']['id'] == 'db-1'
    assert out[1]['id'] == 'db-2'


def test_remap_import_arr_skips_identity_mappings():
    arr = [{'id': 'r1'}]
    # orig == db → no substitution needed → returns original arr
    out = tool_runner._remap_import_arr(arr, [{'orig_id': 'r1', 'db_id': 'r1'}])
    assert out is arr


# ---------------------------------------------------------------------------
# post_pre_import — exercises the file-IO + recon_manager.import_data path
# ---------------------------------------------------------------------------


def test_post_pre_import_calls_recon_manager_and_writes_marker(tmp_path):
    out = tmp_path / 'out.xml'
    out.write_text('x')
    import_arr = [{'id': 'orig'}]

    recon_manager = MagicMock()
    recon_manager.import_data.return_value = [
        {'orig_id': 'orig', 'db_id': 'db-x'}
    ]

    scan_data = MagicMock()
    scan_obj = SimpleNamespace(
        scan_id='scan-abc',
        scan_thread=SimpleNamespace(recon_manager=recon_manager),
        current_tool=SimpleNamespace(id='tool-id'),
        scan_data=scan_data,
    )

    tool_runner.post_pre_import(scan_obj, import_arr, str(out))

    recon_manager.import_data.assert_called_once_with('scan-abc', 'tool-id', import_arr)
    marker = tmp_path / 'tool_import_json'
    assert marker.exists()
    written = json.loads(marker.read_text())
    assert written == [{'id': 'db-x'}]  # remapped
    scan_data.update.assert_called_once_with(written)


# ---------------------------------------------------------------------------
# import_results
# ---------------------------------------------------------------------------


def test_import_results_no_op_for_empty_obj_arr(tmp_path):
    scan_obj = SimpleNamespace(
        scan_id='s',
        scan_thread=SimpleNamespace(recon_manager=MagicMock()),
        current_tool=SimpleNamespace(id='t'),
        scan_data=MagicMock(),
    )
    # Should not raise, should not write any markers
    tool_runner.import_results(scan_obj, [], str(tmp_path / 'out.xml'))
    assert not (tmp_path / 'tool_import_json').exists()
    assert not (tmp_path / 'tool_pre_import_json').exists()


def test_import_results_writes_pre_then_post_markers(tmp_path):
    from reverge_collector.data_model import Host

    out_path = tmp_path / 'scan_out.xml'
    out_path.write_text('x')

    h = Host()
    h.ipv4_addr = '1.2.3.4'

    recon_manager = MagicMock()
    recon_manager.import_data.return_value = []  # server returns no remappings

    scan_data = MagicMock()
    scan_obj = SimpleNamespace(
        scan_id='s',
        scan_thread=SimpleNamespace(recon_manager=recon_manager),
        current_tool=SimpleNamespace(id='t'),
        scan_data=scan_data,
    )

    tool_runner.import_results(scan_obj, [h], str(out_path))

    # Both markers written, in this order
    pre = tmp_path / 'tool_pre_import_json'
    post = tmp_path / 'tool_import_json'
    assert pre.exists()
    assert post.exists()
    # Pre contains the full jsonable
    pre_arr = json.loads(pre.read_text())
    assert pre_arr[0]['type'] == 'host'
    # Post contains the (potentially remapped) update array
    assert isinstance(json.loads(post.read_text()), list)
    recon_manager.import_data.assert_called_once()
    scan_data.update.assert_called_once()
