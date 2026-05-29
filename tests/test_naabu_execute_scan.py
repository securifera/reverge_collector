"""Tests for naabu_scan.execute_scan target-build branches and the
Naabu.parse_output meta-file dispatcher."""

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
    selected_interface=None,
    port_list_str='443',
):
    if obj_list is None:
        obj_list = []
    if peer_tools is None:
        peer_tools = []
    scan_id = 'naabu-' + os.urandom(3).hex()
    scan_data = data_model.ScanData(_scope(obj_list, port_list_str))
    collection_tool_map = {}
    for peer in peer_tools:
        collection_tool_map[peer] = SimpleNamespace(collection_tool=SimpleNamespace(name=peer))
    return SimpleNamespace(
        id=scan_id,
        scan_id=scan_id,
        target_id=1,
        scan_data=scan_data,
        current_tool=SimpleNamespace(id='tool-naabu', name='naabu', args=args),
        current_tool_instance_id='inst-' + os.urandom(3).hex(),
        collection_tool_map=collection_tool_map,
        selected_interface=selected_interface,
        register_tool_executor=MagicMock(),
        tool_executor_map={},
        tool_executor_lock=threading.Lock(),
    )


# ===========================================================================
# execute_scan
# ===========================================================================


def test_execute_scan_skips_when_output_exists(tmp_path, monkeypatch):
    from reverge_collector.naabu_scan import execute_scan, get_output_path

    monkeypatch.chdir(tmp_path)
    scan = make_scan(tmp_path)
    meta = get_output_path(scan)
    os.makedirs(os.path.dirname(meta), exist_ok=True)
    with open(meta, 'w') as f:
        f.write('{}')
    with patch('reverge_collector.scan_utils.executor.submit') as sub:
        execute_scan(scan)
        sub.assert_not_called()


def test_execute_scan_masscan_branch_uses_host_port_map(tmp_path, monkeypatch):
    """masscan-already-ran → host_port_obj_map is used to drive targets."""
    from reverge_collector.naabu_scan import execute_scan, get_output_path

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
    meta = get_output_path(scan)
    body = json.loads(open(meta).read())
    assert len(body['naabu_scan_list']) == 1


def test_execute_scan_subnet_branch_writes_target(tmp_path, monkeypatch):
    """A scope subnet (no masscan) → naabu invoked with subnet/mask."""
    from reverge_collector.naabu_scan import execute_scan, get_output_path

    monkeypatch.chdir(tmp_path)
    obj_list = [
        {
            'type': 'subnet',
            'id': 's1',
            'data': {'subnet': '10.0.0.0', 'mask': 30},
            'tags': [data_model.RecordTag.SCOPE.value],
        },
    ]
    scan = make_scan(tmp_path, obj_list=obj_list, port_list_str='80,443')
    fut = MagicMock()
    fut.result.return_value = {'exit_code': 0, 'stdout': '', 'stderr': ''}
    with patch('reverge_collector.scan_utils.executor.submit', return_value=fut) as sub:
        execute_scan(scan)
    assert sub.called
    meta = get_output_path(scan)
    body = json.loads(open(meta).read())
    # One scan obj for the subnet
    assert len(body['naabu_scan_list']) == 1


def test_execute_scan_subnet_with_hostname_skips_mask(tmp_path, monkeypatch):
    """A subnet record whose `.subnet` is a hostname (not an IP) → naabu
    receives the bare hostname without a /mask suffix (else naabu would
    reject it as a malformed CIDR)."""
    from reverge_collector.naabu_scan import execute_scan, get_output_path

    monkeypatch.chdir(tmp_path)
    obj_list = [
        {
            'type': 'subnet',
            'id': 's1',
            # Bare hostname as the "subnet" — callers use /32 to mark a
            # single-host marker, but naabu must see the hostname only.
            'data': {'subnet': 'host.example.com', 'mask': 32},
            'tags': [data_model.RecordTag.SCOPE.value],
        },
    ]
    scan = make_scan(tmp_path, obj_list=obj_list, port_list_str='80')
    fut = MagicMock()
    fut.result.return_value = {'exit_code': 0, 'stdout': '', 'stderr': ''}
    with patch('reverge_collector.scan_utils.executor.submit', return_value=fut) as sub:
        execute_scan(scan)
    assert sub.called
    # The input file contains the bare hostname, no /mask
    cmd = sub.call_args.kwargs['cmd_args']
    ip_list_path = cmd[cmd.index('-l') + 1]
    body = open(ip_list_path).read().strip()
    assert body == 'host.example.com'


def test_execute_scan_host_only_branch(tmp_path, monkeypatch):
    """No subnet, no host:port pairs, only scope hosts + port_list → naabu
    receives one scan_obj with hosts + domains in ip_set."""
    from reverge_collector.naabu_scan import execute_scan, get_output_path

    monkeypatch.chdir(tmp_path)
    obj_list = [
        {
            'type': 'host',
            'id': 'h1',
            'data': {'ipv4_addr': '10.0.0.7'},
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
    scan = make_scan(tmp_path, obj_list=obj_list, port_list_str='80')
    fut = MagicMock()
    fut.result.return_value = {'exit_code': 0, 'stdout': '', 'stderr': ''}
    with patch('reverge_collector.scan_utils.executor.submit', return_value=fut) as sub:
        execute_scan(scan)
    assert sub.called
    # Both the IP and the domain make it into the input file
    cmd = sub.call_args.kwargs['cmd_args']
    ip_list_path = cmd[cmd.index('-l') + 1]
    body = open(ip_list_path).read()
    assert '10.0.0.7' in body
    assert 'example.com' in body


def test_execute_scan_emits_interface_flag(tmp_path, monkeypatch):
    """selected_interface non-None → '-interface <name>' is appended."""
    from reverge_collector.naabu_scan import execute_scan

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
            'data': {'port': '443', 'proto': 0, 'secure': True},
            'tags': [data_model.RecordTag.SCOPE.value],
        },
    ]
    scan = make_scan(
        tmp_path,
        obj_list=obj_list,
        peer_tools=['masscan'],
        selected_interface=SimpleNamespace(name=' eth1 '),
    )
    fut = MagicMock()
    fut.result.return_value = {'exit_code': 0, 'stdout': '', 'stderr': ''}
    with patch('reverge_collector.scan_utils.executor.submit', return_value=fut) as sub:
        execute_scan(scan)
    cmd = sub.call_args.kwargs['cmd_args']
    assert '-interface' in cmd
    assert cmd[cmd.index('-interface') + 1] == 'eth1'


def test_execute_scan_appends_extra_args(tmp_path, monkeypatch):
    from reverge_collector.naabu_scan import execute_scan

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
            'data': {'port': '443', 'proto': 0, 'secure': True},
            'tags': [data_model.RecordTag.SCOPE.value],
        },
    ]
    scan = make_scan(
        tmp_path,
        obj_list=obj_list,
        peer_tools=['masscan'],
        args='-rate 5000 -timeout 5',
    )
    fut = MagicMock()
    fut.result.return_value = {'exit_code': 0, 'stdout': '', 'stderr': ''}
    with patch('reverge_collector.scan_utils.executor.submit', return_value=fut) as sub:
        execute_scan(scan)
    cmd = sub.call_args.kwargs['cmd_args']
    assert '-rate' in cmd
    assert '5000' in cmd


def test_execute_scan_failure_raises(tmp_path, monkeypatch):
    from reverge_collector.naabu_scan import execute_scan

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
            'data': {'port': '443', 'proto': 0, 'secure': True},
            'tags': [data_model.RecordTag.SCOPE.value],
        },
    ]
    scan = make_scan(tmp_path, obj_list=obj_list, peer_tools=['masscan'])
    bad = MagicMock()
    bad.result.return_value = {'exit_code': 2, 'stdout': '', 'stderr': 'naabu fell over'}
    with (
        patch('reverge_collector.scan_utils.executor.submit', return_value=bad),
        pytest.raises(RuntimeError, match='exited with code 2'),
    ):
        execute_scan(scan)


def test_execute_scan_empty_scope_writes_empty_meta(tmp_path, monkeypatch):
    from reverge_collector.naabu_scan import execute_scan, get_output_path

    monkeypatch.chdir(tmp_path)
    scan = make_scan(tmp_path, obj_list=[])
    with patch('reverge_collector.scan_utils.executor.submit') as sub:
        execute_scan(scan)
    sub.assert_not_called()
    meta = get_output_path(scan)
    body = json.loads(open(meta).read())
    assert body == {'naabu_scan_list': []}


# ===========================================================================
# Naabu.parse_output
# ===========================================================================


def test_parse_output_skips_missing_or_empty_subfiles(tmp_path):
    from reverge_collector.naabu_scan import Naabu

    out_missing = tmp_path / 'missing'
    out_empty = tmp_path / 'empty'
    out_empty.write_text('')
    meta = tmp_path / 'meta.json'
    meta.write_text(
        json.dumps(
            {
                'naabu_scan_list': [
                    {'naabu_command': [], 'output_file': str(out_missing)},
                    {'naabu_command': [], 'output_file': str(out_empty)},
                ]
            }
        )
    )
    scan = make_scan(tmp_path)
    inst = Naabu()
    assert inst.parse_output(str(meta), scan) == []


def test_parse_output_aggregates_records_across_subfiles(tmp_path):
    from reverge_collector.naabu_scan import Naabu

    sub1 = tmp_path / 'naabu_out_0'
    sub1.write_text(json.dumps({'ip': '10.0.0.1', 'port': 22, 'host': 'srv1'}) + '\n')
    sub2 = tmp_path / 'naabu_out_1'
    sub2.write_text(json.dumps({'ip': '10.0.0.2', 'port': 80, 'host': 'srv2'}) + '\n')
    meta = tmp_path / 'meta.json'
    meta.write_text(
        json.dumps(
            {
                'naabu_scan_list': [
                    {'naabu_command': [], 'output_file': str(sub1)},
                    {'naabu_command': [], 'output_file': str(sub2)},
                ]
            }
        )
    )
    scan = make_scan(tmp_path)
    inst = Naabu()
    records = inst.parse_output(str(meta), scan)
    ips = {r.ipv4_addr for r in records if type(r).__name__ == 'Host'}
    assert ips == {'10.0.0.1', '10.0.0.2'}
