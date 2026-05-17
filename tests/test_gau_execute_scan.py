"""Tests for gau_scan.execute_scan branches not reached by route tests."""

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


def make_scan(tmp_path, *, obj_list=None, args='', port_list_str='443'):
    if obj_list is None:
        obj_list = []
    scan_id = 'gau-' + os.urandom(3).hex()
    scan_data = data_model.ScanData(_scope(obj_list, port_list_str))
    return SimpleNamespace(
        id=scan_id,
        scan_id=scan_id,
        target_id=1,
        scan_data=scan_data,
        current_tool=SimpleNamespace(id='tool-gau', name='gau', args=args),
        current_tool_instance_id='inst-' + os.urandom(3).hex(),
        collection_tool_map={},
        selected_interface=None,
        register_tool_executor=MagicMock(),
        tool_executor_map={},
        tool_executor_lock=threading.Lock(),
    )


def test_execute_scan_skips_when_output_exists(tmp_path, monkeypatch):
    from reverge_collector.gau_scan import execute_scan, get_output_path

    monkeypatch.chdir(tmp_path)
    scan = make_scan(tmp_path, obj_list=[])
    out = get_output_path(scan)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, 'w') as f:
        f.write('{}')
    with patch('reverge_collector.scan_utils.executor.submit') as m:
        execute_scan(scan)
        m.assert_not_called()


def test_execute_scan_with_scope_domain_submits(tmp_path, monkeypatch):
    """A SCOPE-tagged Domain in scan_data → gau is invoked with that domain
    on stdin."""
    from reverge_collector.gau_scan import execute_scan, get_output_path

    monkeypatch.chdir(tmp_path)
    obj_list = [
        {
            'type': 'host',
            'id': 'h1',
            'data': {'ipv4_addr': '10.0.0.1'},
            'tags': [data_model.RecordTag.SCOPE.value],
        },
        {
            'type': 'domain',
            'id': 'd1',
            'parent': {'type': 'host', 'id': 'h1'},
            'data': {'name': 'example.com'},
            'tags': [data_model.RecordTag.SCOPE.value],
        },
    ]
    scan = make_scan(tmp_path, obj_list=obj_list)
    fut = MagicMock()
    fut.result.return_value = {'exit_code': 0, 'stdout': '', 'stderr': ''}
    with patch('reverge_collector.scan_utils.executor.submit', return_value=fut) as sub:
        execute_scan(scan)
    assert sub.called
    # stdin_data carries the domain
    assert 'example.com' in sub.call_args.kwargs['stdin_data']
    out = get_output_path(scan)
    assert os.path.exists(out)


def test_execute_scan_with_url_metadata_submits(tmp_path, monkeypatch):
    """When url_metadata_map has entries, gau is invoked with each base URL's
    netloc on stdin."""
    from reverge_collector.gau_scan import execute_scan

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
    stdin = sub.call_args.kwargs['stdin_data']
    # IP-derived netloc shows up
    assert '10.0.0.1' in stdin


def test_execute_scan_failure_raises(tmp_path, monkeypatch):
    from reverge_collector.gau_scan import execute_scan

    monkeypatch.chdir(tmp_path)
    obj_list = [
        {
            'type': 'host',
            'id': 'h1',
            'data': {'ipv4_addr': '10.0.0.1'},
            'tags': [data_model.RecordTag.SCOPE.value],
        },
        {
            'type': 'domain',
            'id': 'd1',
            'parent': {'type': 'host', 'id': 'h1'},
            'data': {'name': 'example.com'},
            'tags': [data_model.RecordTag.SCOPE.value],
        },
    ]
    scan = make_scan(tmp_path, obj_list=obj_list)
    bad = MagicMock()
    bad.result.return_value = {'exit_code': 1, 'stdout': '', 'stderr': 'gau failed'}
    with (
        patch('reverge_collector.scan_utils.executor.submit', return_value=bad),
        pytest.raises(RuntimeError, match='exited with code 1'),
    ):
        execute_scan(scan)
