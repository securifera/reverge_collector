"""Tests for httpx_scan.execute_scan target-build branches."""

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


def make_scan(
    tmp_path,
    *,
    obj_list=None,
    args='',
    peer_tools=None,
    port_list_str='443',
):
    if obj_list is None:
        obj_list = []
    if peer_tools is None:
        peer_tools = []
    scan_id = 'httpx-' + os.urandom(3).hex()
    scan_data = data_model.ScanData(_scope(obj_list, port_list_str))
    collection_tool_map = {}
    for peer in peer_tools:
        collection_tool_map[peer] = SimpleNamespace(collection_tool=SimpleNamespace(name=peer))
    return SimpleNamespace(
        id=scan_id,
        scan_id=scan_id,
        target_id=1,
        scan_data=scan_data,
        current_tool=SimpleNamespace(id='tool-httpx', name='httpx', args=args),
        current_tool_instance_id='inst-' + os.urandom(3).hex(),
        collection_tool_map=collection_tool_map,
        selected_interface=None,
        register_tool_executor=MagicMock(),
        tool_executor_map={},
        tool_executor_lock=threading.Lock(),
    )


def test_execute_scan_skips_when_output_exists(tmp_path, monkeypatch):
    from reverge_collector.httpx_scan import execute_scan, get_output_path

    monkeypatch.chdir(tmp_path)
    scan = make_scan(tmp_path)
    out = get_output_path(scan)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, 'w') as f:
        f.write('{}')
    with patch('reverge_collector.scan_utils.executor.submit') as m:
        execute_scan(scan)
        m.assert_not_called()


def test_execute_scan_masscan_branch_uses_url_metadata(tmp_path, monkeypatch):
    """When masscan ran, port_target_list_map is built from
    scan_data.get_url_metadata_map()."""
    from reverge_collector.httpx_scan import execute_scan

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
    scan = make_scan(tmp_path, obj_list=obj_list, peer_tools=['masscan'])
    fut = MagicMock()
    fut.result.return_value = {'exit_code': 0, 'stdout': '', 'stderr': ''}
    with patch('reverge_collector.scan_utils.executor.submit', return_value=fut) as sub:
        execute_scan(scan)
    assert sub.called


def test_execute_scan_scope_urls_branch(tmp_path, monkeypatch):
    """Scope URLs (no masscan) populate port_target_list_map per port."""
    from reverge_collector.httpx_scan import execute_scan

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
        {
            'type': 'httpendpoint',
            'id': 'ep1',
            'parent': {'type': 'port', 'id': 'p1'},
            'data': {},
            'tags': [data_model.RecordTag.SCOPE.value],
        },
    ]
    scan = make_scan(tmp_path, obj_list=obj_list)
    fut = MagicMock()
    fut.result.return_value = {'exit_code': 0, 'stdout': '', 'stderr': ''}
    with patch('reverge_collector.scan_utils.executor.submit', return_value=fut) as sub:
        execute_scan(scan)
    assert sub.called


def test_execute_scan_host_port_branch_no_masscan(tmp_path, monkeypatch):
    """No masscan, no URL endpoints — scope ports drive httpx (each host
    becomes an input line per port)."""
    from reverge_collector.httpx_scan import execute_scan

    monkeypatch.chdir(tmp_path)
    obj_list = [
        {
            'type': 'host',
            'id': 'h1',
            'data': {'ipv4_addr': '10.0.0.1'},
            'tags': [data_model.RecordTag.SCOPE.value],
        },
        {
            'type': 'host',
            'id': 'h2',
            'data': {'ipv4_addr': '10.0.0.2'},
            'tags': [data_model.RecordTag.SCOPE.value],
        },
    ]
    scan = make_scan(tmp_path, obj_list=obj_list, port_list_str='80')
    fut = MagicMock()
    fut.result.return_value = {'exit_code': 0, 'stdout': '', 'stderr': ''}
    with patch('reverge_collector.scan_utils.executor.submit', return_value=fut) as sub:
        execute_scan(scan)
    assert sub.called


def test_execute_scan_appends_extra_args(tmp_path, monkeypatch):
    from reverge_collector.httpx_scan import execute_scan

    monkeypatch.chdir(tmp_path)
    obj_list = [
        {
            'type': 'host',
            'id': 'h1',
            'data': {'ipv4_addr': '10.0.0.1'},
            'tags': [data_model.RecordTag.SCOPE.value],
        },
    ]
    scan = make_scan(
        tmp_path,
        obj_list=obj_list,
        port_list_str='80',
        args='-tls-probe -follow-redirects',
    )
    fut = MagicMock()
    fut.result.return_value = {'exit_code': 0, 'stdout': '', 'stderr': ''}
    with patch('reverge_collector.scan_utils.executor.submit', return_value=fut) as sub:
        execute_scan(scan)
    cmd = sub.call_args.kwargs['cmd_args']
    assert '-tls-probe' in cmd
    assert '-follow-redirects' in cmd


def test_execute_scan_failure_raises(tmp_path, monkeypatch):
    from reverge_collector.httpx_scan import execute_scan

    monkeypatch.chdir(tmp_path)
    obj_list = [
        {
            'type': 'host',
            'id': 'h1',
            'data': {'ipv4_addr': '10.0.0.1'},
            'tags': [data_model.RecordTag.SCOPE.value],
        },
    ]
    scan = make_scan(tmp_path, obj_list=obj_list, port_list_str='80')
    bad = MagicMock()
    bad.result.return_value = {'exit_code': 2, 'stdout': '', 'stderr': 'httpx fell over'}
    with (
        patch('reverge_collector.scan_utils.executor.submit', return_value=bad),
        pytest.raises(RuntimeError, match='exited with code 2'),
    ):
        execute_scan(scan)


def test_execute_scan_subnet_fallback_branch(tmp_path, monkeypatch):
    """No host_port pairs and no scope URLs — subnet expansion fallback
    populates port_target_list_map from get_url_metadata_map()."""
    from reverge_collector.httpx_scan import execute_scan

    monkeypatch.chdir(tmp_path)
    obj_list = [
        {
            'type': 'subnet',
            'id': 's1',
            'data': {'subnet': '10.0.0.0', 'mask': 30},
            'tags': [data_model.RecordTag.SCOPE.value],
        },
    ]
    scan = make_scan(tmp_path, obj_list=obj_list, port_list_str='80')
    fut = MagicMock()
    fut.result.return_value = {'exit_code': 0, 'stdout': '', 'stderr': ''}
    with patch('reverge_collector.scan_utils.executor.submit', return_value=fut) as sub:
        execute_scan(scan)
    assert sub.called


def test_execute_scan_port_list_branch_via_existing_ports(tmp_path, monkeypatch):
    """When host:port pairs exist but no scope URLs, port_obj.get_url_list
    is consumed to build the per-port ip_set."""
    from reverge_collector.httpx_scan import execute_scan

    monkeypatch.chdir(tmp_path)
    obj_list = [
        {
            'type': 'host',
            'id': 'h1',
            'data': {'ipv4_addr': '10.0.0.5'},
            'tags': [data_model.RecordTag.SCOPE.value],
        },
        {
            'type': 'port',
            'id': 'p1',
            'parent': {'type': 'host', 'id': 'h1'},
            'data': {'port': '8080', 'proto': 0, 'secure': False},
            'tags': [data_model.RecordTag.SCOPE.value],
        },
    ]
    scan = make_scan(tmp_path, obj_list=obj_list, port_list_str='')  # no scope ports
    fut = MagicMock()
    fut.result.return_value = {'exit_code': 0, 'stdout': '', 'stderr': ''}
    with patch('reverge_collector.scan_utils.executor.submit', return_value=fut) as sub:
        execute_scan(scan)
    assert sub.called
