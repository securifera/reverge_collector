"""Tests for nmap_scan.execute_scan target-source branches.

execute_scan() has four mutually-exclusive paths for assembling the
scan target list:
  1. masscan-already-ran → consume the host_port_obj_map per-port
  2. subnet present → one scan_obj per subnet
  3. no subnet, host:port pairs present → one scan_obj per port
  4. no subnet, no host:port pairs, port_list non-empty → single combined
     scan_obj with all hosts + domains
plus the skip-when-output-exists short-circuit and the
selected_interface / resolve_dns / failure-exit-code branches.

Each test stubs ``scan_utils.executor.submit`` so no subprocess is
ever started, and stubs the returned future's ``result()`` to drive
the success / failure branches.
"""

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

# ---------------------------------------------------------------------------
# Helpers — fake ScheduledScan with a real ScanData
# ---------------------------------------------------------------------------


def _make_scope(obj_list, port_list_str='443'):
    return {
        'b64_port_bitmap': base64.b64encode(get_port_byte_array(port_list_str)).decode(),
        'obj_list': obj_list,
    }


def make_scan(
    tmp_path,
    *,
    obj_list=None,
    port_list_str='443',
    args='',
    peer_tools=None,
    selected_interface=None,
):
    if obj_list is None:
        obj_list = []
    if peer_tools is None:
        peer_tools = []  # e.g. ['masscan']

    scan_id = 'nmap-scan-' + os.urandom(3).hex()
    scan_data = data_model.ScanData(_make_scope(obj_list, port_list_str))
    current_tool = SimpleNamespace(id='tool-nmap', name='nmap', args=args)

    collection_tool_map = {}
    for peer in peer_tools:
        collection_tool_map[peer] = SimpleNamespace(collection_tool=SimpleNamespace(name=peer))

    return SimpleNamespace(
        id=scan_id,
        scan_id=scan_id,
        target_id=1,
        scan_data=scan_data,
        current_tool=current_tool,
        current_tool_instance_id='inst-' + os.urandom(3).hex(),
        collection_tool_map=collection_tool_map,
        selected_interface=selected_interface,
        register_tool_executor=MagicMock(),
        tool_executor_map={},
        tool_executor_lock=threading.Lock(),
    )


@pytest.fixture
def stub_future_ok():
    fut = MagicMock()
    fut.result.return_value = {'exit_code': 0, 'stdout': '', 'stderr': ''}
    return fut


@pytest.fixture
def stub_submit(stub_future_ok):
    with patch(
        'reverge_collector.scan_utils.executor.submit',
        return_value=stub_future_ok,
    ) as m:
        yield m


# ---------------------------------------------------------------------------
# Short-circuit: meta file already exists
# ---------------------------------------------------------------------------


def test_execute_scan_skips_when_output_exists(tmp_path, monkeypatch):
    from reverge_collector.nmap_scan import execute_scan, get_output_path

    monkeypatch.chdir(tmp_path)
    scan = make_scan(tmp_path)
    meta = get_output_path(scan)
    os.makedirs(os.path.dirname(meta), exist_ok=True)
    with open(meta, 'w') as f:
        f.write('{}')
    # If we don't skip, submit would have been called — patch and confirm not
    with patch('reverge_collector.scan_utils.executor.submit') as m:
        execute_scan(scan)
        m.assert_not_called()


# ---------------------------------------------------------------------------
# Branch: masscan already ran → host_port_obj_map driven
# ---------------------------------------------------------------------------


def test_execute_scan_uses_host_port_map_when_masscan_present(tmp_path, monkeypatch, stub_submit):
    from reverge_collector.nmap_scan import execute_scan, get_output_path

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
    execute_scan(scan)
    # submit was called once (one port group)
    assert stub_submit.called
    # nmap_in_0 was written with the IP
    meta = get_output_path(scan)
    dir_path = os.path.dirname(meta)
    ip_file = os.path.join(dir_path, 'nmap_in_0')
    assert os.path.exists(ip_file)
    assert '10.0.0.5' in open(ip_file).read()
    # Meta file contains the command list
    assert os.path.exists(meta)
    meta_data = json.loads(open(meta).read())
    assert 'nmap_scan_list' in meta_data
    assert len(meta_data['nmap_scan_list']) == 1
    cmd = meta_data['nmap_scan_list'][0]['nmap_command']
    assert 'nmap' in cmd
    # -n flag is appended when resolve_dns is False
    assert '-n' in cmd


# ---------------------------------------------------------------------------
# Branch: subnet present, no masscan → one scan_obj per subnet
# ---------------------------------------------------------------------------


def test_execute_scan_subnet_branch(tmp_path, monkeypatch, stub_submit):
    from reverge_collector.nmap_scan import execute_scan, get_output_path

    monkeypatch.chdir(tmp_path)
    obj_list = [
        {
            'type': 'subnet',
            'id': 's1',
            'data': {'subnet': '192.0.2.0', 'mask': 30},
            'tags': [data_model.RecordTag.SCOPE.value],
        },
    ]
    scan = make_scan(tmp_path, obj_list=obj_list, port_list_str='80,443')
    execute_scan(scan)
    meta = get_output_path(scan)
    meta_data = json.loads(open(meta).read())
    assert len(meta_data['nmap_scan_list']) == 1
    cmd = meta_data['nmap_scan_list'][0]['nmap_command']
    # Port list is the consolidated 80,443
    p_idx = cmd.index('-p')
    assert '80' in cmd[p_idx + 1]
    assert '443' in cmd[p_idx + 1]


# ---------------------------------------------------------------------------
# Branch: no subnet, host:port pairs → one scan_obj per port
# ---------------------------------------------------------------------------


def test_execute_scan_host_port_branch_no_masscan(tmp_path, monkeypatch, stub_submit):
    from reverge_collector.nmap_scan import execute_scan, get_output_path

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
        {
            'type': 'port',
            'id': 'p1',
            'parent': {'type': 'host', 'id': 'h1'},
            'data': {'port': '22', 'proto': 0, 'secure': False},
            'tags': [data_model.RecordTag.SCOPE.value],
        },
        {
            'type': 'port',
            'id': 'p2',
            'parent': {'type': 'host', 'id': 'h2'},
            'data': {'port': '22', 'proto': 0, 'secure': False},
            'tags': [data_model.RecordTag.SCOPE.value],
        },
    ]
    scan = make_scan(tmp_path, obj_list=obj_list)
    execute_scan(scan)
    meta = get_output_path(scan)
    meta_data = json.loads(open(meta).read())
    # Two hosts grouped under one port → one scan_obj
    assert len(meta_data['nmap_scan_list']) == 1


# ---------------------------------------------------------------------------
# Branch: no subnet, no host:port pairs, port_list non-empty → combined scan
# ---------------------------------------------------------------------------


def test_execute_scan_hosts_only_branch_combined_scan(tmp_path, monkeypatch, stub_submit):
    from reverge_collector.nmap_scan import execute_scan, get_output_path

    monkeypatch.chdir(tmp_path)
    obj_list = [
        {
            'type': 'host',
            'id': 'h1',
            'data': {'ipv4_addr': '10.0.0.1'},
            'tags': [data_model.RecordTag.SCOPE.value],
        },
    ]
    scan = make_scan(tmp_path, obj_list=obj_list, port_list_str='8080')
    execute_scan(scan)
    meta = get_output_path(scan)
    meta_data = json.loads(open(meta).read())
    assert len(meta_data['nmap_scan_list']) == 1
    cmd = meta_data['nmap_scan_list'][0]['nmap_command']
    # Port from scope
    p_idx = cmd.index('-p')
    assert cmd[p_idx + 1] == '8080'


# ---------------------------------------------------------------------------
# selected_interface adds '-e <name>'
# ---------------------------------------------------------------------------


def test_execute_scan_emits_interface_flag(tmp_path, monkeypatch, stub_submit):
    from reverge_collector.nmap_scan import execute_scan, get_output_path

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
        selected_interface=SimpleNamespace(name=' eth1 '),
    )
    execute_scan(scan)
    meta = get_output_path(scan)
    meta_data = json.loads(open(meta).read())
    cmd = meta_data['nmap_scan_list'][0]['nmap_command']
    assert '-e' in cmd
    e_idx = cmd.index('-e')
    assert cmd[e_idx + 1] == 'eth1'  # stripped


# ---------------------------------------------------------------------------
# script_args appended from tool.args
# ---------------------------------------------------------------------------


def test_execute_scan_appends_extra_args(tmp_path, monkeypatch, stub_submit):
    from reverge_collector.nmap_scan import execute_scan, get_output_path

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
        args='-sV --script vulners',
    )
    execute_scan(scan)
    meta = get_output_path(scan)
    meta_data = json.loads(open(meta).read())
    cmd = meta_data['nmap_scan_list'][0]['nmap_command']
    # The args appear after the standard nmap flags
    assert '-sV' in cmd
    assert '--script' in cmd
    assert 'vulners' in cmd


# ---------------------------------------------------------------------------
# Failure exit_code raises RuntimeError
# ---------------------------------------------------------------------------


def test_execute_scan_raises_when_subprocess_exits_nonzero(tmp_path, monkeypatch):
    from reverge_collector.nmap_scan import execute_scan

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

    bad_future = MagicMock()
    bad_future.result.return_value = {
        'exit_code': 1,
        'stdout': '',
        'stderr': 'nmap fell over',
    }
    with (
        patch(
            'reverge_collector.scan_utils.executor.submit',
            return_value=bad_future,
        ),
        pytest.raises(RuntimeError, match='exited with code 1'),
    ):
        execute_scan(scan)


# ---------------------------------------------------------------------------
# Empty ip_set scan_obj is skipped (continue branch)
# ---------------------------------------------------------------------------


def test_execute_scan_no_targets_writes_empty_meta(tmp_path, monkeypatch):
    from reverge_collector.nmap_scan import execute_scan, get_output_path

    monkeypatch.chdir(tmp_path)
    scan = make_scan(tmp_path, obj_list=[])
    with patch('reverge_collector.scan_utils.executor.submit') as m:
        execute_scan(scan)
        m.assert_not_called()
    meta = get_output_path(scan)
    assert os.path.exists(meta)
    meta_data = json.loads(open(meta).read())
    assert meta_data['nmap_scan_list'] == []
