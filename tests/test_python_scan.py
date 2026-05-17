"""Tests for python_scan.execute_scan and parse_python_scan_output."""

from __future__ import annotations

import base64
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


def make_scan(tmp_path, *, obj_list=None, args='print("hi")', port_list_str='443'):
    if obj_list is None:
        obj_list = []
    scan_id = 'pyscan-' + os.urandom(3).hex()
    scan_data = data_model.ScanData(_scope(obj_list, port_list_str))
    return SimpleNamespace(
        id=scan_id,
        scan_id=scan_id,
        target_id=1,
        scan_data=scan_data,
        current_tool=SimpleNamespace(id='tool-py', name='python', args=args),
        current_tool_instance_id='inst-' + os.urandom(3).hex(),
        collection_tool_map={},
        selected_interface=None,
        register_tool_executor=MagicMock(),
        tool_executor_map={},
        tool_executor_lock=threading.Lock(),
    )


def test_execute_scan_skips_when_output_exists(tmp_path, monkeypatch):
    from reverge_collector.python_scan import execute_scan, get_output_path

    monkeypatch.chdir(tmp_path)
    scan = make_scan(tmp_path, obj_list=[])
    out = get_output_path(scan)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, 'w') as f:
        f.write('existing')
    with patch('reverge_collector.scan_utils.executor.submit') as m:
        execute_scan(scan)
        m.assert_not_called()


def test_execute_scan_requires_custom_args(tmp_path, monkeypatch):
    from reverge_collector.python_scan import execute_scan

    monkeypatch.chdir(tmp_path)
    scan = make_scan(tmp_path, args='')
    with pytest.raises(RuntimeError, match='Custom arguments'):
        execute_scan(scan)


def test_execute_scan_no_targets_raises(tmp_path, monkeypatch):
    from reverge_collector.python_scan import execute_scan

    monkeypatch.chdir(tmp_path)
    scan = make_scan(tmp_path, obj_list=[], args='print(1)')
    # No host:port pairs in scope → length 0 → RuntimeError
    with pytest.raises(RuntimeError, match='No ports'):
        execute_scan(scan)


def test_execute_scan_success_writes_stdout(tmp_path, monkeypatch):
    from reverge_collector.python_scan import execute_scan, get_output_path

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
    scan = make_scan(tmp_path, obj_list=obj_list, args='print("ok")')
    fut = MagicMock()
    fut.result.return_value = {'exit_code': 0, 'stdout': 'ok\n', 'stderr': ''}
    with patch('reverge_collector.scan_utils.executor.submit', return_value=fut):
        execute_scan(scan)
    out = get_output_path(scan)
    assert os.path.exists(out)
    assert open(out).read() == 'ok\n'


def test_execute_scan_nonzero_exit_raises(tmp_path, monkeypatch):
    from reverge_collector.python_scan import execute_scan

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
    scan = make_scan(tmp_path, obj_list=obj_list, args='import sys; sys.exit(2)')
    fut = MagicMock()
    fut.result.return_value = {'exit_code': 2, 'stdout': '', 'stderr': 'oh no'}
    with patch('reverge_collector.scan_utils.executor.submit', return_value=fut):
        with pytest.raises(RuntimeError, match='exited with code 2'):
            execute_scan(scan)


def test_parse_returns_empty_for_empty_output(tmp_path):
    from reverge_collector.python_scan import parse_python_scan_output

    f = tmp_path / 'out.txt'
    f.write_text('')
    out = parse_python_scan_output(str(f), tool_instance_id='ti', tool_id='td')
    assert out == []


def test_parse_emits_collection_module_only_when_no_target_map(tmp_path):
    from reverge_collector.python_scan import parse_python_scan_output

    f = tmp_path / 'out.txt'
    f.write_text('result\n')
    out = parse_python_scan_output(
        str(f), tool_instance_id='ti', tool_id='td', target_map=None
    )
    # One CollectionModule object, no CollectionModuleOutput
    types = {type(r).__name__ for r in out}
    assert types == {'CollectionModule'}


def test_parse_emits_module_output_per_target(tmp_path):
    from reverge_collector.python_scan import parse_python_scan_output

    f = tmp_path / 'out.txt'
    f.write_text('payload\n')
    target_map = {
        '10.0.0.1:443': {
            'host_obj': SimpleNamespace(ipv4_addr='10.0.0.1'),
            'port_obj': SimpleNamespace(id='p1', port='443'),
        },
        '10.0.0.2:443': {
            'host_obj': SimpleNamespace(ipv4_addr='10.0.0.2'),
            'port_obj': SimpleNamespace(id='p2', port='443'),
        },
    }
    out = parse_python_scan_output(
        str(f), tool_instance_id='ti', tool_id='td', target_map=target_map
    )
    types = [type(r).__name__ for r in out]
    assert types.count('CollectionModule') == 1
    assert types.count('CollectionModuleOutput') == 2
