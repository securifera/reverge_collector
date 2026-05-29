"""Tests for feroxbuster_scan.execute_scan target-build branches."""

from __future__ import annotations

import base64
import json
import os
import threading
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from reverge_collector import data_model
from reverge_collector.scan_utils import get_port_byte_array


def _scope(obj_list, port_list_str='443'):
    return {
        'b64_port_bitmap': base64.b64encode(get_port_byte_array(port_list_str)).decode(),
        'obj_list': obj_list,
    }


def make_scan(tmp_path, *, obj_list=None, args='', wordlist_path=None):
    if obj_list is None:
        obj_list = []
    scan_id = 'ferox-' + os.urandom(3).hex()
    scan_data = data_model.ScanData(_scope(obj_list))
    return SimpleNamespace(
        id=scan_id,
        scan_id=scan_id,
        target_id=1,
        scan_data=scan_data,
        current_tool=SimpleNamespace(
            id='tool-ferox',
            name='feroxbuster',
            args=args,
            wordlist_path=wordlist_path,
        ),
        current_tool_instance_id='inst-' + os.urandom(3).hex(),
        collection_tool_map={},
        selected_interface=None,
        register_tool_executor=MagicMock(),
        tool_executor_map={},
        tool_executor_lock=threading.Lock(),
    )


def test_execute_scan_skips_when_output_exists(tmp_path, monkeypatch):
    from reverge_collector.feroxbuster_scan import execute_scan, get_output_path

    monkeypatch.chdir(tmp_path)
    scan = make_scan(tmp_path)
    out = get_output_path(scan)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, 'w') as f:
        f.write('{}')
    with patch('reverge_collector.scan_utils.executor.submit') as m:
        execute_scan(scan)
        m.assert_not_called()


def test_execute_scan_no_targets_writes_empty_meta(tmp_path, monkeypatch):
    """No URLs from scope → empty url_to_id_map → empty meta written."""
    from reverge_collector.feroxbuster_scan import execute_scan, get_output_path

    monkeypatch.chdir(tmp_path)
    scan = make_scan(tmp_path, obj_list=[])
    with patch('reverge_collector.scan_utils.executor.submit') as m:
        execute_scan(scan)
        m.assert_not_called()
    body = json.loads(open(get_output_path(scan)).read())
    assert body == {'url_to_id_map': {}, 'output_file': None}


def test_execute_scan_with_url_metadata_submits(tmp_path, monkeypatch):
    from reverge_collector.feroxbuster_scan import execute_scan, get_output_path

    monkeypatch.chdir(tmp_path)
    obj_list = [
        {
            'type': 'host',
            'id': 'h1',
            'data': {'ipv4_addr': '10.0.0.1'},
            'tags': [data_model.RecordTag.SCOPE.value],
        },
        {
            'type': 'port',
            'id': 'p1',
            'parent': {'type': 'host', 'id': 'h1'},
            'data': {'port': '443', 'proto': 0, 'secure': True},
            'tags': [data_model.RecordTag.SCOPE.value],
        },
    ]
    scan = make_scan(tmp_path, obj_list=obj_list)
    fut = MagicMock()
    fut.result.return_value = {'exit_code': 0, 'stdout': '', 'stderr': ''}
    with patch('reverge_collector.scan_utils.executor.submit', return_value=fut) as sub:
        execute_scan(scan)
    assert sub.called
    body = json.loads(open(get_output_path(scan)).read())
    assert body['url_to_id_map']
    assert body['output_file']


def test_execute_scan_includes_wordlist_when_set(tmp_path, monkeypatch):
    from reverge_collector.feroxbuster_scan import execute_scan

    monkeypatch.chdir(tmp_path)
    wl = tmp_path / 'wl'
    wl.write_text('admin\nlogin\n')
    obj_list = [
        {
            'type': 'host',
            'id': 'h1',
            'data': {'ipv4_addr': '10.0.0.1'},
            'tags': [data_model.RecordTag.SCOPE.value],
        },
        {
            'type': 'port',
            'id': 'p1',
            'parent': {'type': 'host', 'id': 'h1'},
            'data': {'port': '443', 'proto': 0, 'secure': True},
            'tags': [data_model.RecordTag.SCOPE.value],
        },
    ]
    scan = make_scan(tmp_path, obj_list=obj_list, wordlist_path=str(wl))
    fut = MagicMock()
    fut.result.return_value = {'exit_code': 0, 'stdout': '', 'stderr': ''}
    with patch('reverge_collector.scan_utils.executor.submit', return_value=fut) as sub:
        execute_scan(scan)
    cmd = sub.call_args.kwargs['cmd_args']
    assert '-w' in cmd
    assert str(wl) in cmd


def test_execute_scan_appends_extra_args(tmp_path, monkeypatch):
    from reverge_collector.feroxbuster_scan import execute_scan

    monkeypatch.chdir(tmp_path)
    obj_list = [
        {
            'type': 'host',
            'id': 'h1',
            'data': {'ipv4_addr': '10.0.0.1'},
            'tags': [data_model.RecordTag.SCOPE.value],
        },
        {
            'type': 'port',
            'id': 'p1',
            'parent': {'type': 'host', 'id': 'h1'},
            'data': {'port': '443', 'proto': 0, 'secure': True},
            'tags': [data_model.RecordTag.SCOPE.value],
        },
    ]
    scan = make_scan(tmp_path, obj_list=obj_list, args='-t 10 --quiet')
    fut = MagicMock()
    fut.result.return_value = {'exit_code': 0, 'stdout': '', 'stderr': ''}
    with patch('reverge_collector.scan_utils.executor.submit', return_value=fut) as sub:
        execute_scan(scan)
    cmd = sub.call_args.kwargs['cmd_args']
    assert '-t' in cmd
    assert '10' in cmd
    assert '--quiet' in cmd


def test_execute_scan_failure_raises(tmp_path, monkeypatch):
    from reverge_collector.feroxbuster_scan import execute_scan

    monkeypatch.chdir(tmp_path)
    obj_list = [
        {
            'type': 'host',
            'id': 'h1',
            'data': {'ipv4_addr': '10.0.0.1'},
            'tags': [data_model.RecordTag.SCOPE.value],
        },
        {
            'type': 'port',
            'id': 'p1',
            'parent': {'type': 'host', 'id': 'h1'},
            'data': {'port': '443', 'proto': 0, 'secure': True},
            'tags': [data_model.RecordTag.SCOPE.value],
        },
    ]
    scan = make_scan(tmp_path, obj_list=obj_list)
    bad = MagicMock()
    bad.result.return_value = {'exit_code': 2, 'stdout': '', 'stderr': 'feroxbuster died'}
    with (
        patch('reverge_collector.scan_utils.executor.submit', return_value=bad),
        pytest.raises(RuntimeError, match='exited with code 2'),
    ):
        execute_scan(scan)
