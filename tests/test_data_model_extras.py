"""Additional data_model tests targeting the biggest uncovered blocks:
ScheduledScan.kill_scan_processes / cleanup, RevergeTool.to_jsonable,
ImportToolXOutput.{complete,import_results}, Port.get_url_list,
HttpEndpoint.get_url, HttpEndpointData.get_url,
CollectionModule.get_host_port_obj_map, and assorted record .from_jsonsable
error paths."""

from __future__ import annotations

import base64
import json
import os
import threading
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from reverge_collector import data_model
from reverge_collector.data_model import (
    CollectionModule,
    HttpEndpoint,
    HttpEndpointData,
    ImportToolXOutput,
    Port,
    RecordTag,
    RevergeTool,
    ScanData,
    ScheduledScan,
    ToolExecutor,
)
from reverge_collector.scan_utils import get_port_byte_array

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _scope(obj_list, port_list_str='443'):
    return {
        'b64_port_bitmap': base64.b64encode(get_port_byte_array(port_list_str)).decode(),
        'obj_list': obj_list,
    }


def _make_scheduled(thread_rm, *, scan_obj=None, tools=None):
    """Build a minimal ScheduledScan with no wordlists, mocked rm."""
    if tools is None:
        tools = []
    sched = SimpleNamespace(
        id='sch-1',
        scan_id='scan-1',
        target_id=1,
        collection_tools=tools,
    )
    if scan_obj is None:
        scan_obj = {'scan_id': 'scan-1', 'scope': _scope([])}
    thread_rm.get_scheduled_scan.return_value = scan_obj
    thread = SimpleNamespace(recon_manager=thread_rm)
    return ScheduledScan(thread, sched)


# ===========================================================================
# ScheduledScan.kill_scan_processes
# ===========================================================================


class TestKillScanProcesses:
    def test_kill_all_tools_clears_map(self):
        s = _make_scheduled(MagicMock())
        executor = ToolExecutor()
        executor.add_pid(99999999)  # bogus PID; os.kill will fail (caught)
        s.tool_executor_map['t1'] = executor
        with patch('reverge_collector.data_model.os.kill') as kill_mock:
            s.kill_scan_processes()
        kill_mock.assert_called_once_with(99999999, data_model.signal.SIGKILL)
        assert s.tool_executor_map == {}

    def test_kill_specified_tools_only(self):
        s = _make_scheduled(MagicMock())
        e1 = ToolExecutor()
        e1.add_pid(11111111)
        e2 = ToolExecutor()
        e2.add_pid(22222222)
        s.tool_executor_map['t1'] = e1
        s.tool_executor_map['t2'] = e2
        with patch('reverge_collector.data_model.os.kill'):
            s.kill_scan_processes(['t1'])
        # t1 removed, t2 stays
        assert 't1' not in s.tool_executor_map
        assert 't2' in s.tool_executor_map

    def test_kill_skips_unknown_tool_ids(self):
        s = _make_scheduled(MagicMock())
        s.tool_executor_map['real'] = ToolExecutor()
        with patch('reverge_collector.data_model.os.kill'):
            # No exception even when tool id not in map
            s.kill_scan_processes(['ghost'])
        assert 'real' in s.tool_executor_map

    def test_kill_cancels_futures_and_swallows_errors(self):
        s = _make_scheduled(MagicMock())
        bad_future = MagicMock()
        bad_future.cancel.side_effect = Exception('cancel-fail')
        bad_future.done.return_value = False
        e = ToolExecutor()
        e.add_future(bad_future)
        s.tool_executor_map['t1'] = e
        # Should not raise even though cancel raised
        s.kill_scan_processes()
        bad_future.cancel.assert_called_once()


# ===========================================================================
# ScheduledScan.cleanup
# ===========================================================================


def test_cleanup_removes_wordlist_files(tmp_path):
    s = _make_scheduled(MagicMock())
    wl = tmp_path / 'wl_file'
    wl.write_text('one\ntwo\n')
    fake_tool = SimpleNamespace(
        collection_tool=SimpleNamespace(wordlist_path=str(wl)),
    )
    s.collection_tool_map = {'t1': fake_tool}
    assert wl.exists()
    s.cleanup()
    assert not wl.exists()


def test_cleanup_skips_when_no_wordlist_path():
    s = _make_scheduled(MagicMock())
    s.collection_tool_map = {
        't1': SimpleNamespace(collection_tool=SimpleNamespace(wordlist_path=None)),
    }
    s.cleanup()  # no crash


# ===========================================================================
# RevergeTool.to_jsonable
# ===========================================================================


class TestRevergeToolToJsonable:
    def test_full_round_trip(self):
        t = RevergeTool()
        t.name = 'mock-tool'
        t.collector_type = data_model.CollectorType.ACTIVE.value
        t.scan_order = 5
        t.args = '--foo'
        t.description = 'desc'
        t.project_url = 'https://example.com/t'
        t.tags = ['active', 'port-scan']
        t.input_records = [data_model.ServerRecordType.HOST]
        t.output_records = [data_model.ServerRecordType.PORT]
        t.max_targets = 50
        # Module func returns one module with its own to_jsonable
        fake_mod = MagicMock()
        fake_mod.to_jsonable.return_value = {'name': 'm1'}
        t.modules_func = lambda: [fake_mod]
        out = t.to_jsonable()
        assert out['name'] == 'mock-tool'
        assert out['tool_type'] == data_model.CollectorType.ACTIVE.value
        assert out['scan_order'] == 5
        assert out['args'] == '--foo'
        assert out['tags'] == ['active', 'port-scan']
        assert out['input_records'] == ['Host']
        assert out['output_records'] == ['Port']
        assert out['modules'] == [{'name': 'm1'}]
        assert out['max_targets'] == 50

    def test_no_max_targets_field_when_unset(self):
        t = RevergeTool()
        t.modules_func = lambda: []
        out = t.to_jsonable()
        assert 'max_targets' not in out


# ===========================================================================
# ImportToolXOutput.{complete, import_results}
# ===========================================================================


class _FakeImportTask(ImportToolXOutput):
    """Minimal ImportToolXOutput subclass that lets us point output() at a tmp path."""

    def __init__(self, out_path, scan_input):
        self._out_path = out_path
        self.scan_input = scan_input

    def output(self):
        return self._out_path


def test_complete_returns_false_when_marker_missing(tmp_path):
    scan = SimpleNamespace(scan_data=MagicMock())
    task = _FakeImportTask(str(tmp_path / 'nope.json'), scan)
    assert task.complete() is False


def test_complete_returns_false_when_marker_empty(tmp_path):
    marker = tmp_path / 'empty.json'
    marker.write_text('')
    scan = SimpleNamespace(scan_data=MagicMock())
    task = _FakeImportTask(str(marker), scan)
    assert task.complete() is False


def test_complete_returns_true_and_updates_scope(tmp_path):
    marker = tmp_path / 'done.json'
    marker.write_text(
        json.dumps([{'type': 'host', 'id': 'h1', 'data': {'ipv4_addr': '1.2.3.4'}, 'tags': []}])
        + '\n'
    )
    scan_data_mock = MagicMock()
    scan = SimpleNamespace(scan_data=scan_data_mock)
    task = _FakeImportTask(str(marker), scan)
    assert task.complete() is True
    scan_data_mock.update.assert_called_once()


def test_import_results_writes_file_and_updates_scope(tmp_path):
    out_path = tmp_path / 'tool_import_json'
    rm = MagicMock()
    rm.import_data.return_value = []  # no id remappings
    scan_data = ScanData(_scope([]))
    scan_input = SimpleNamespace(
        scan_id='s1',
        scan_thread=SimpleNamespace(recon_manager=rm),
        current_tool=SimpleNamespace(id='tool-1'),
        scan_data=scan_data,
    )
    task = _FakeImportTask(str(out_path), scan_input)
    host = data_model.Host()
    host.ipv4_addr = '10.0.0.1'
    task.import_results(scan_input, [host])
    assert out_path.exists()
    body = json.loads(out_path.read_text())
    assert isinstance(body, list)
    assert len(body) == 1
    rm.import_data.assert_called_once()


def test_import_results_no_op_when_empty():
    rm = MagicMock()
    scan_input = SimpleNamespace(
        scan_id='s2',
        scan_thread=SimpleNamespace(recon_manager=rm),
        current_tool=SimpleNamespace(id='tool-2'),
    )
    task = _FakeImportTask('/tmp/never-written', scan_input)
    task.import_results(scan_input, [])
    rm.import_data.assert_not_called()


# ===========================================================================
# Port.get_url_list
# ===========================================================================


def test_port_get_url_list_with_domain_and_cert():
    obj_list = [
        {
            'type': 'host',
            'id': 'h1',
            'data': {'ipv4_addr': '10.0.0.1'},
            'tags': [RecordTag.SCOPE.value],
        },
        {
            'type': 'port',
            'id': 'p1',
            'parent': {'type': 'host', 'id': 'h1'},
            'data': {'port': '443', 'proto': 0, 'secure': True},
            'tags': [RecordTag.SCOPE.value],
        },
        {
            'type': 'domain',
            'id': 'd1',
            'parent': {'type': 'host', 'id': 'h1'},
            'data': {'name': 'example.com'},
            'tags': [RecordTag.SCOPE.value],
        },
    ]
    sd = ScanData(_scope(obj_list))
    port_obj = sd.port_map['p1']
    urls = port_obj.get_url_list(sd)
    # Both IP-based and domain-based URLs
    assert any('10.0.0.1' in u for u in urls)
    assert any('example.com' in u for u in urls)


def test_port_get_url_list_loopback_returns_empty():
    obj_list = [
        {
            'type': 'host',
            'id': 'h1',
            'data': {'ipv4_addr': '127.0.0.1'},
            'tags': [RecordTag.SCOPE.value],
        },
        {
            'type': 'port',
            'id': 'p1',
            'parent': {'type': 'host', 'id': 'h1'},
            'data': {'port': '8080', 'proto': 0, 'secure': False},
            'tags': [RecordTag.SCOPE.value],
        },
    ]
    sd = ScanData(_scope(obj_list, port_list_str='8080'))
    port_obj = sd.port_map['p1']
    assert port_obj.get_url_list(sd) == []


def test_port_get_url_list_returns_empty_when_host_missing():
    """Port whose parent host id isn't in scope_obj.host_map returns []."""
    p = Port(parent_id='ghost-host')
    p.port = '443'
    sd = ScanData(_scope([]))
    assert p.get_url_list(sd) == []


# ===========================================================================
# HttpEndpoint.get_url
# ===========================================================================


def test_http_endpoint_get_url_prefers_domain_from_endpoint_data():
    obj_list = [
        {
            'type': 'host',
            'id': 'h1',
            'data': {'ipv4_addr': '10.0.0.5'},
            'tags': [RecordTag.SCOPE.value],
        },
        {
            'type': 'port',
            'id': 'p1',
            'parent': {'type': 'host', 'id': 'h1'},
            'data': {'port': '443', 'proto': 0, 'secure': True},
            'tags': [RecordTag.SCOPE.value],
        },
        {
            'type': 'domain',
            'id': 'd1',
            'parent': {'type': 'host', 'id': 'h1'},
            'data': {'name': 'example.com'},
            'tags': [RecordTag.SCOPE.value],
        },
        {
            'type': 'listitem',
            'id': 'path-admin',
            'data': {'path': '/admin', 'path_hash': 'h-admin'},
            'tags': [RecordTag.SCOPE.value],
        },
        {
            'type': 'httpendpoint',
            'id': 'ep1',
            'parent': {'type': 'port', 'id': 'p1'},
            'data': {'web_path_id': 'path-admin'},
            'tags': [RecordTag.SCOPE.value],
        },
        {
            'type': 'httpendpointdata',
            'id': 'epd1',
            'parent': {'type': 'httpendpoint', 'id': 'ep1'},
            'data': {'status': 200, 'domain_id': 'd1'},
            'tags': [RecordTag.SCOPE.value],
        },
    ]
    sd = ScanData(_scope(obj_list))
    ep_obj = sd.http_endpoint_map['ep1']
    url = ep_obj.get_url()
    assert 'example.com' in url
    assert '/admin' in url


def test_http_endpoint_get_url_ip_when_no_endpoint_data():
    obj_list = [
        {
            'type': 'host',
            'id': 'h1',
            'data': {'ipv4_addr': '10.0.0.5'},
            'tags': [RecordTag.SCOPE.value],
        },
        {
            'type': 'port',
            'id': 'p1',
            'parent': {'type': 'host', 'id': 'h1'},
            'data': {'port': '443', 'proto': 0, 'secure': True},
            'tags': [RecordTag.SCOPE.value],
        },
        {
            'type': 'httpendpoint',
            'id': 'ep1',
            'parent': {'type': 'port', 'id': 'p1'},
            'data': {},
            'tags': [RecordTag.SCOPE.value],
        },
    ]
    sd = ScanData(_scope(obj_list))
    ep_obj = sd.http_endpoint_map['ep1']
    url = ep_obj.get_url()
    assert '10.0.0.5' in url


def test_http_endpoint_get_port():
    obj_list = [
        {
            'type': 'host',
            'id': 'h1',
            'data': {'ipv4_addr': '10.0.0.5'},
            'tags': [RecordTag.SCOPE.value],
        },
        {
            'type': 'port',
            'id': 'p1',
            'parent': {'type': 'host', 'id': 'h1'},
            'data': {'port': '8443', 'proto': 0, 'secure': True},
            'tags': [RecordTag.SCOPE.value],
        },
        {
            'type': 'httpendpoint',
            'id': 'ep1',
            'parent': {'type': 'port', 'id': 'p1'},
            'data': {},
            'tags': [RecordTag.SCOPE.value],
        },
    ]
    sd = ScanData(_scope(obj_list, port_list_str='8443'))
    ep_obj = sd.http_endpoint_map['ep1']
    assert ep_obj.get_port() == '8443'


def test_http_endpoint_get_port_returns_empty_when_port_missing():
    ep = HttpEndpoint(parent_id='ghost-port')
    ep.scan_data = ScanData(_scope([]))
    assert ep.get_port() == ''


# ===========================================================================
# HttpEndpointData.get_url
# ===========================================================================


def test_http_endpoint_data_get_url_with_domain_override():
    obj_list = [
        {
            'type': 'host',
            'id': 'h1',
            'data': {'ipv4_addr': '10.0.0.5'},
            'tags': [RecordTag.SCOPE.value],
        },
        {
            'type': 'port',
            'id': 'p1',
            'parent': {'type': 'host', 'id': 'h1'},
            'data': {'port': '443', 'proto': 0, 'secure': True},
            'tags': [RecordTag.SCOPE.value],
        },
        {
            'type': 'domain',
            'id': 'd1',
            'parent': {'type': 'host', 'id': 'h1'},
            'data': {'name': 'example.com'},
            'tags': [RecordTag.SCOPE.value],
        },
        {
            'type': 'listitem',
            'id': 'path-api',
            'data': {'path': '/api', 'path_hash': 'h-api'},
            'tags': [RecordTag.SCOPE.value],
        },
        {
            'type': 'httpendpoint',
            'id': 'ep1',
            'parent': {'type': 'port', 'id': 'p1'},
            'data': {'web_path_id': 'path-api'},
            'tags': [RecordTag.SCOPE.value],
        },
        {
            'type': 'httpendpointdata',
            'id': 'epd1',
            'parent': {'type': 'httpendpoint', 'id': 'ep1'},
            'data': {'status': 200, 'domain_id': 'd1'},
            'tags': [RecordTag.SCOPE.value],
        },
    ]
    sd = ScanData(_scope(obj_list))
    epd_obj = next(iter(sd.endpoint_data_endpoint_id_map['ep1']))
    url = epd_obj.get_url()
    assert 'example.com' in url
    assert '/api' in url


def test_http_endpoint_data_get_url_falls_back_to_ip():
    obj_list = [
        {
            'type': 'host',
            'id': 'h1',
            'data': {'ipv4_addr': '10.0.0.5'},
            'tags': [RecordTag.SCOPE.value],
        },
        {
            'type': 'port',
            'id': 'p1',
            'parent': {'type': 'host', 'id': 'h1'},
            'data': {'port': '443', 'proto': 0, 'secure': True},
            'tags': [RecordTag.SCOPE.value],
        },
        {
            'type': 'httpendpoint',
            'id': 'ep1',
            'parent': {'type': 'port', 'id': 'p1'},
            'data': {},
            'tags': [RecordTag.SCOPE.value],
        },
        {
            'type': 'httpendpointdata',
            'id': 'epd1',
            'parent': {'type': 'httpendpoint', 'id': 'ep1'},
            'data': {'status': 200},
            'tags': [RecordTag.SCOPE.value],
        },
    ]
    sd = ScanData(_scope(obj_list))
    epd_obj = next(iter(sd.endpoint_data_endpoint_id_map['ep1']))
    url = epd_obj.get_url()
    assert '10.0.0.5' in url


# ===========================================================================
# CollectionModule.get_host_port_obj_map
# ===========================================================================


def test_collection_module_get_host_port_obj_map_returns_empty_when_no_bindings():
    m = CollectionModule()
    m.bindings = None
    m.scan_data = ScanData(_scope([]))
    assert m.get_host_port_obj_map() == {}


def test_collection_module_get_host_port_obj_map_with_binding():
    """When the module's binding component name maps to a known port,
    that port shows up in the returned host_port map."""
    obj_list = [
        {
            'type': 'host',
            'id': 'h1',
            'data': {'ipv4_addr': '10.0.0.5'},
            'tags': [RecordTag.SCOPE.value],
        },
        {
            'type': 'port',
            'id': 'p1',
            'parent': {'type': 'host', 'id': 'h1'},
            'data': {'port': '8080', 'proto': 0, 'secure': False},
            'tags': [RecordTag.SCOPE.value],
        },
        {
            # Cpe (formerly WebComponent) record names a port via component_*_maps
            'type': 'cpe',
            'id': 'comp-nginx',
            'parent': {'type': 'port', 'id': 'p1'},
            'data': {'name': 'nginx', 'vendor': 'nginx', 'product': 'nginx'},
            'tags': [RecordTag.SCOPE.value],
        },
    ]
    sd = ScanData(_scope(obj_list, port_list_str='8080'))
    m = CollectionModule()
    m.scan_data = sd
    m.bindings = ['comp-nginx']
    host_port_map = m.get_host_port_obj_map()
    assert len(host_port_map) >= 1


def test_collection_module_get_host_port_obj_map_unknown_component_logs_and_returns_empty():
    m = CollectionModule()
    m.scan_data = ScanData(_scope([]))
    m.bindings = ['nonexistent-component-id']
    # No crash; no entries either
    assert m.get_host_port_obj_map() == {}
