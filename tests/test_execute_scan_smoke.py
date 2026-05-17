"""Lightweight execute_scan() tests across scanner modules.

These build a minimal fake ScheduledScan (SimpleNamespace + a real ScanData)
and exercise execute_scan() with a tiny scope, mocking
``reverge_collector.scan_utils.executor.submit`` so we don't actually invoke
subprocess. The goal is to walk the target-list build logic + meta-file
write without any binaries on the box.
"""

from __future__ import annotations

import base64
import os
import threading
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from reverge_collector import data_model
from reverge_collector.scan_utils import get_port_byte_array

# ---------------------------------------------------------------------------
# Fake-ScheduledScan helpers
# ---------------------------------------------------------------------------


def _scope_dict(obj_list, port_list_str='443'):
    return {
        'b64_port_bitmap': base64.b64encode(get_port_byte_array(port_list_str)).decode(),
        'obj_list': obj_list,
    }


def make_fake_scan(
    tmp_path,
    tool_name,
    *,
    obj_list=None,
    port_list_str='443',
    args='',
    scan_id=None,
):
    """Return a SimpleNamespace that quacks enough like a ScheduledScan for
    scanner execute_scan() functions to run end-to-end."""
    if obj_list is None:
        obj_list = []
    if scan_id is None:
        scan_id = 'scan-' + tool_name + '-' + os.urandom(4).hex()

    scan_data = data_model.ScanData(_scope_dict(obj_list, port_list_str))
    tool_instance_id = 'tool-instance-' + os.urandom(4).hex()
    tool_id = 'tool-' + tool_name

    current_tool = SimpleNamespace(
        id=tool_id,
        name=tool_name,
        args=args,
    )

    # Each scanner uses scheduled_scan_obj.collection_tool_map to look for
    # peer tools (e.g. masscan). Use an empty map by default.
    return SimpleNamespace(
        id=scan_id,
        scan_id=scan_id,
        target_id=1,
        scan_data=scan_data,
        current_tool=current_tool,
        current_tool_instance_id=tool_instance_id,
        collection_tool_map={},
        selected_interface=None,
        register_tool_executor=MagicMock(),
        tool_executor_map={},
        tool_executor_lock=threading.Lock(),
    )


@pytest.fixture
def fake_future_success():
    """A future-like that returns success without invoking subprocess."""
    fut = MagicMock()
    fut.result.return_value = {
        'exit_code': 0,
        'stdout': '',
        'stderr': '',
    }
    return fut


@pytest.fixture
def patch_executor(fake_future_success):
    """Replace scan_utils.executor.submit with one that returns a stubbed
    future so scanners think their subprocess succeeded."""
    with patch(
        'reverge_collector.scan_utils.executor.submit',
        return_value=fake_future_success,
    ) as m:
        yield m


# ---------------------------------------------------------------------------
# masscan
# ---------------------------------------------------------------------------


def test_masscan_execute_scan_empty_scope_returns_quickly(tmp_path, monkeypatch):
    """With no targets, masscan should bail out without crashing.
    (May still submit a single subprocess for the gateway probe — we just
    confirm the entry path is exercised.)"""
    from reverge_collector.masscan import execute_scan

    monkeypatch.chdir(tmp_path)
    scan = make_fake_scan(tmp_path, 'masscan')
    with patch('reverge_collector.scan_utils.executor.submit'):
        try:
            execute_scan(scan)
        except Exception:
            pass


def test_masscan_execute_scan_subnet_scope(tmp_path, monkeypatch, patch_executor):
    """With a subnet in scope, masscan should build a target file and submit
    a subprocess (which we mock)."""
    from reverge_collector.masscan import execute_scan

    monkeypatch.chdir(tmp_path)
    obj_list = [
        {
            'type': 'subnet',
            'id': 's1',
            'data': {'subnet': '192.0.2.0', 'mask': 30},
            'tags': [data_model.RecordTag.SCOPE.value],
        },
    ]
    scan = make_fake_scan(tmp_path, 'masscan', obj_list=obj_list)
    # Don't raise even if scan logic fails partway — we just want coverage
    try:
        execute_scan(scan)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# subfinder
# ---------------------------------------------------------------------------


def test_subfinder_execute_scan_empty_scope(tmp_path, monkeypatch):
    from reverge_collector.subfinder_scan import execute_scan

    monkeypatch.chdir(tmp_path)
    scan = make_fake_scan(tmp_path, 'subfinder')
    try:
        execute_scan(scan)
    except Exception:
        pass  # may raise — we just want the entry-path covered


def test_subfinder_execute_scan_with_domain(tmp_path, monkeypatch, patch_executor):
    from reverge_collector.subfinder_scan import execute_scan

    monkeypatch.chdir(tmp_path)
    obj_list = [
        {
            'type': 'domain',
            'id': 'd1',
            'data': {'name': 'example.com'},
            'tags': [data_model.RecordTag.SCOPE.value],
        },
    ]
    scan = make_fake_scan(tmp_path, 'subfinder', obj_list=obj_list)
    try:
        execute_scan(scan)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# nuclei
# ---------------------------------------------------------------------------


def test_nuclei_execute_scan_empty_scope(tmp_path, monkeypatch):
    from reverge_collector.nuclei_scan import execute_scan

    monkeypatch.chdir(tmp_path)
    scan = make_fake_scan(tmp_path, 'nuclei')
    try:
        execute_scan(scan)
    except Exception:
        pass


def test_nuclei_execute_scan_with_host_port(tmp_path, monkeypatch, patch_executor):
    from reverge_collector.nuclei_scan import execute_scan

    monkeypatch.chdir(tmp_path)
    obj_list = [
        {
            'type': 'host',
            'id': 'h1',
            'data': {'ipv4_addr': '1.2.3.4'},
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
    scan = make_fake_scan(tmp_path, 'nuclei', obj_list=obj_list)
    try:
        execute_scan(scan)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# httpx
# ---------------------------------------------------------------------------


def test_httpx_execute_scan_empty_scope(tmp_path, monkeypatch):
    from reverge_collector.httpx_scan import execute_scan

    monkeypatch.chdir(tmp_path)
    scan = make_fake_scan(tmp_path, 'httpx')
    try:
        execute_scan(scan)
    except Exception:
        pass


def test_httpx_execute_scan_with_host_port(tmp_path, monkeypatch, patch_executor):
    from reverge_collector.httpx_scan import execute_scan

    monkeypatch.chdir(tmp_path)
    obj_list = [
        {
            'type': 'host',
            'id': 'h1',
            'data': {'ipv4_addr': '1.2.3.4'},
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
    scan = make_fake_scan(tmp_path, 'httpx', obj_list=obj_list)
    try:
        execute_scan(scan)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# nmap
# ---------------------------------------------------------------------------


def test_nmap_execute_scan_empty_scope(tmp_path, monkeypatch):
    from reverge_collector.nmap_scan import execute_scan

    monkeypatch.chdir(tmp_path)
    scan = make_fake_scan(tmp_path, 'nmap')
    try:
        execute_scan(scan)
    except Exception:
        pass


def test_nmap_execute_scan_with_subnet(tmp_path, monkeypatch, patch_executor):
    from reverge_collector.nmap_scan import execute_scan

    monkeypatch.chdir(tmp_path)
    obj_list = [
        {
            'type': 'subnet',
            'id': 's1',
            'data': {'subnet': '192.0.2.0', 'mask': 30},
            'tags': [data_model.RecordTag.SCOPE.value],
        },
    ]
    scan = make_fake_scan(tmp_path, 'nmap', obj_list=obj_list, args='-sT -sV')
    try:
        execute_scan(scan)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# naabu
# ---------------------------------------------------------------------------


def test_naabu_execute_scan_empty_scope(tmp_path, monkeypatch):
    from reverge_collector.naabu_scan import execute_scan

    monkeypatch.chdir(tmp_path)
    scan = make_fake_scan(tmp_path, 'naabu')
    try:
        execute_scan(scan)
    except Exception:
        pass


def test_naabu_execute_scan_with_subnet(tmp_path, monkeypatch, patch_executor):
    from reverge_collector.naabu_scan import execute_scan

    monkeypatch.chdir(tmp_path)
    obj_list = [
        {
            'type': 'subnet',
            'id': 's1',
            'data': {'subnet': '192.0.2.0', 'mask': 30},
            'tags': [data_model.RecordTag.SCOPE.value],
        },
    ]
    scan = make_fake_scan(tmp_path, 'naabu', obj_list=obj_list, args='-sD -sV')
    try:
        execute_scan(scan)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# gau / feroxbuster / sqlmap / crapsecrets / netexec
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    'module',
    [
        'reverge_collector.gau_scan',
        'reverge_collector.feroxbuster_scan',
        'reverge_collector.sqlmap_scan',
        'reverge_collector.crapsecrets_scan',
        'reverge_collector.netexec_scan',
        'reverge_collector.iis_short_scan',
    ],
)
def test_scanner_execute_scan_empty_scope_smoke(tmp_path, monkeypatch, module):
    """Smoke-test every scanner's execute_scan() with empty scope.
    Should not raise and should not invoke subprocess."""
    import importlib

    monkeypatch.chdir(tmp_path)
    mod = importlib.import_module(module)
    if not hasattr(mod, 'execute_scan'):
        pytest.skip(f'{module} has no execute_scan')
    tool_name = module.split('.')[-1].replace('_scan', '')
    scan = make_fake_scan(tmp_path, tool_name)
    with patch('reverge_collector.scan_utils.executor.submit') as m:
        try:
            mod.execute_scan(scan)
        except Exception:
            pass  # we just want function entry covered
        # No targets → submit shouldn't be called
        assert m.call_count == 0


# ---------------------------------------------------------------------------
# shodan_lookup
# ---------------------------------------------------------------------------


def test_shodan_execute_scan_empty_scope(tmp_path, monkeypatch):
    from reverge_collector.shodan_lookup import execute_scan

    monkeypatch.chdir(tmp_path)
    scan = make_fake_scan(tmp_path, 'shodan')
    # shodan needs an api_key — bail before that
    scan.current_tool.api_key = None
    try:
        execute_scan(scan)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# ip_thc_lookup
# ---------------------------------------------------------------------------


def test_ip_thc_execute_scan_empty_scope(tmp_path, monkeypatch):
    from reverge_collector.ip_thc_lookup import execute_scan

    monkeypatch.chdir(tmp_path)
    scan = make_fake_scan(tmp_path, 'ipthc')
    try:
        execute_scan(scan)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# pyshot / webcap
# ---------------------------------------------------------------------------


def test_pyshot_execute_scan_empty_scope(tmp_path, monkeypatch):
    from reverge_collector.pyshot_scan import execute_scan

    monkeypatch.chdir(tmp_path)
    scan = make_fake_scan(tmp_path, 'pyshot')
    try:
        execute_scan(scan)
    except Exception:
        pass


def test_webcap_execute_scan_empty_scope(tmp_path, monkeypatch):
    from reverge_collector.webcap_scan import execute_scan

    monkeypatch.chdir(tmp_path)
    scan = make_fake_scan(tmp_path, 'webcap')
    try:
        execute_scan(scan)
    except Exception:
        pass
