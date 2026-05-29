"""Tests for masscan helpers: get_mac_address, get_default_gateway,
get_masscan_input, execute_scan, parse_masscan_xml."""

from __future__ import annotations

import base64
import os
import threading
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from reverge_collector import data_model
from reverge_collector.scan_utils import get_port_byte_array


def _scope(obj_list, port_list_str='80'):
    return {
        'b64_port_bitmap': base64.b64encode(get_port_byte_array(port_list_str)).decode(),
        'obj_list': obj_list,
    }


def make_scan(tmp_path, *, obj_list=None, args='', selected_interface=None):
    if obj_list is None:
        obj_list = []
    scan_id = 'mass-' + os.urandom(3).hex()
    scan_data = data_model.ScanData(_scope(obj_list))
    return SimpleNamespace(
        id=scan_id,
        scan_id=scan_id,
        target_id=1,
        scan_data=scan_data,
        current_tool=SimpleNamespace(id='tool-mass', name='masscan', args=args),
        current_tool_instance_id='inst-' + os.urandom(3).hex(),
        collection_tool_map={},
        selected_interface=selected_interface,
        register_tool_executor=MagicMock(),
        tool_executor_map={},
        tool_executor_lock=threading.Lock(),
    )


# ===========================================================================
# get_mac_address
# ===========================================================================


class TestGetMacAddress:
    def test_extracts_mac_from_arp_output(self):
        from reverge_collector.masscan import get_mac_address

        fut = MagicMock()
        fut.result.return_value = {
            'stdout': 'Address                  HWtype  HWaddress           Flags Mask            Iface\n'
            '192.168.1.1              ether   aa:bb:cc:dd:ee:ff   C                     eth0\n'
        }
        with patch('reverge_collector.scan_utils.executor.submit', return_value=fut):
            mac = get_mac_address('192.168.1.1')
        assert mac == 'aa:bb:cc:dd:ee:ff'

    def test_returns_none_when_no_mac_in_output(self):
        from reverge_collector.masscan import get_mac_address

        fut = MagicMock()
        fut.result.return_value = {'stdout': 'no mac here'}
        with patch('reverge_collector.scan_utils.executor.submit', return_value=fut):
            assert get_mac_address('192.168.1.1') is None

    def test_returns_none_when_subprocess_fails(self):
        from reverge_collector.masscan import get_mac_address

        fut = MagicMock()
        fut.result.side_effect = RuntimeError('arp failed')
        with patch('reverge_collector.scan_utils.executor.submit', return_value=fut):
            assert get_mac_address('192.168.1.1') is None


# ===========================================================================
# get_default_gateway
# ===========================================================================


def test_get_default_gateway_returns_address_on_success():
    from reverge_collector import masscan as mod

    fake_gws = {'default': {mod.ni.AF_INET: ('10.0.0.1', 'eth0')}}
    with patch.object(mod.ni, 'gateways', return_value=fake_gws):
        assert mod.get_default_gateway() == '10.0.0.1'


def test_get_default_gateway_returns_none_on_error():
    from reverge_collector import masscan as mod

    with patch.object(mod.ni, 'gateways', side_effect=Exception('no nics')):
        assert mod.get_default_gateway() is None


# ===========================================================================
# execute_scan
# ===========================================================================


def test_execute_scan_skips_when_output_exists(tmp_path, monkeypatch):
    from reverge_collector.masscan import execute_scan, get_output_path

    monkeypatch.chdir(tmp_path)
    scan = make_scan(tmp_path)
    out = get_output_path(scan)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, 'w') as f:
        f.write('')
    with patch('reverge_collector.scan_utils.executor.submit') as m:
        execute_scan(scan)
        m.assert_not_called()


def test_execute_scan_empty_scope_writes_empty_output(tmp_path, monkeypatch):
    """No targets → no masscan command, but an empty output file is touched."""
    from reverge_collector.masscan import execute_scan, get_output_path

    monkeypatch.chdir(tmp_path)
    scan = make_scan(tmp_path, obj_list=[])
    with (
        patch('reverge_collector.masscan.get_default_gateway', return_value=None),
        patch('reverge_collector.scan_utils.executor.submit') as m,
    ):
        execute_scan(scan)
        m.assert_not_called()
    out = get_output_path(scan)
    assert os.path.exists(out)
    assert open(out).read() == ''


def test_execute_scan_with_subnet_submits(tmp_path, monkeypatch):
    from reverge_collector.masscan import execute_scan

    monkeypatch.chdir(tmp_path)
    obj_list = [
        {
            'type': 'subnet',
            'id': 's1',
            'data': {'subnet': '10.0.0.0', 'mask': 30},
            'tags': [data_model.RecordTag.SCOPE.value],
        },
    ]
    scan = make_scan(tmp_path, obj_list=obj_list)
    fut = MagicMock()
    fut.result.return_value = {'exit_code': 0, 'stdout': '', 'stderr': ''}
    with (
        patch('reverge_collector.masscan.get_default_gateway', return_value=None),
        patch('reverge_collector.scan_utils.executor.submit', return_value=fut) as sub,
    ):
        execute_scan(scan)
    assert sub.called
    cmd = sub.call_args.kwargs['cmd_args']
    assert 'masscan' in cmd


def test_execute_scan_failure_raises(tmp_path, monkeypatch):
    from reverge_collector.masscan import execute_scan

    monkeypatch.chdir(tmp_path)
    obj_list = [
        {
            'type': 'subnet',
            'id': 's1',
            'data': {'subnet': '10.0.0.0', 'mask': 30},
            'tags': [data_model.RecordTag.SCOPE.value],
        },
    ]
    scan = make_scan(tmp_path, obj_list=obj_list)
    bad = MagicMock()
    bad.result.return_value = {'exit_code': 2, 'stdout': '', 'stderr': 'rate-limit'}
    with (
        patch('reverge_collector.masscan.get_default_gateway', return_value=None),
        patch('reverge_collector.scan_utils.executor.submit', return_value=bad),
        pytest.raises(RuntimeError, match='exited with code 2'),
    ):
        execute_scan(scan)


def test_execute_scan_router_mac_appended_when_gateway_returns_mac(tmp_path, monkeypatch):
    """When a default gateway is reachable and ARP returns a MAC,
    '--router-mac' is appended (dashes-only formatted)."""
    from reverge_collector.masscan import execute_scan

    monkeypatch.chdir(tmp_path)
    obj_list = [
        {
            'type': 'subnet',
            'id': 's1',
            'data': {'subnet': '10.0.0.0', 'mask': 30},
            'tags': [data_model.RecordTag.SCOPE.value],
        },
    ]
    scan = make_scan(tmp_path, obj_list=obj_list)
    fut = MagicMock()
    fut.result.return_value = {'exit_code': 0, 'stdout': '', 'stderr': ''}
    with (
        patch('reverge_collector.masscan.get_default_gateway', return_value='10.0.0.1'),
        patch('reverge_collector.masscan.get_mac_address', return_value='aa:bb:cc:dd:ee:ff'),
        patch('reverge_collector.scan_utils.executor.submit', return_value=fut) as sub,
    ):
        execute_scan(scan)
    cmd = sub.call_args.kwargs['cmd_args']
    assert '--router-mac' in cmd
    assert 'aa-bb-cc-dd-ee-ff' in cmd


def test_execute_scan_interface_flag(tmp_path, monkeypatch):
    from reverge_collector.masscan import execute_scan

    monkeypatch.chdir(tmp_path)
    obj_list = [
        {
            'type': 'subnet',
            'id': 's1',
            'data': {'subnet': '10.0.0.0', 'mask': 30},
            'tags': [data_model.RecordTag.SCOPE.value],
        },
    ]
    scan = make_scan(
        tmp_path,
        obj_list=obj_list,
        selected_interface=SimpleNamespace(name=' eth1 '),
    )
    fut = MagicMock()
    fut.result.return_value = {'exit_code': 0, 'stdout': '', 'stderr': ''}
    with (
        patch('reverge_collector.masscan.get_default_gateway', return_value=None),
        patch('reverge_collector.scan_utils.executor.submit', return_value=fut) as sub,
    ):
        execute_scan(scan)
    cmd = sub.call_args.kwargs['cmd_args']
    assert '-e' in cmd
    assert cmd[cmd.index('-e') + 1] == 'eth1'
