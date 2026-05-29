"""Tests for iis_short_scan.iis_short_scan_wrap and execute_scan branches."""

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


def make_scan(tmp_path, *, obj_list=None, args=''):
    if obj_list is None:
        obj_list = []
    scan_id = 'iis-' + os.urandom(3).hex()
    scan_data = data_model.ScanData(_scope(obj_list))
    return SimpleNamespace(
        id=scan_id,
        scan_id=scan_id,
        target_id=1,
        scan_data=scan_data,
        current_tool=SimpleNamespace(id='tool-iis', name='iis_short_scan', args=args),
        current_tool_instance_id='inst-' + os.urandom(3).hex(),
        collection_tool_map={},
        selected_interface=None,
        register_tool_executor=MagicMock(),
        tool_executor_map={},
        tool_executor_lock=threading.Lock(),
    )


# ===========================================================================
# iis_short_scan_wrap
# ===========================================================================


def _make_scanner(is_vuln, files=None, dirs=None, raises=None):
    """Build a fake Scanner context manager."""
    inst = MagicMock()
    if raises is not None:
        inst.is_vulnerable.side_effect = raises
    else:
        inst.is_vulnerable.return_value = is_vuln
        inst.files = files or []
        inst.dirs = dirs or []
    ctx = MagicMock()
    ctx.__enter__ = MagicMock(return_value=inst)
    ctx.__exit__ = MagicMock(return_value=False)
    return ctx


class TestIisShortScanWrap:
    def test_returns_non_vulnerable_when_scanner_says_no(self):
        from reverge_collector.iis_short_scan import iis_short_scan_wrap

        scanner = _make_scanner(is_vuln=False)
        with patch('reverge_collector.iis_short_scan.Scanner', return_value=scanner):
            out = iis_short_scan_wrap(['https://t/'])
        assert out == [{'target': 'https://t/', 'vulnerable': False, 'files': [], 'dirs': []}]
        scanner.__enter__.return_value.run.assert_not_called()

    def test_returns_vulnerable_with_files_and_dirs(self):
        from reverge_collector.iis_short_scan import iis_short_scan_wrap

        scanner = _make_scanner(is_vuln=True, files=['admin~1.asp'], dirs=['scripts~1'])
        with patch('reverge_collector.iis_short_scan.Scanner', return_value=scanner):
            out = iis_short_scan_wrap(['https://t/'])
        assert len(out) == 1
        assert out[0]['vulnerable'] is True
        assert 'admin~1.asp' in out[0]['files']
        assert 'scripts~1' in out[0]['dirs']
        scanner.__enter__.return_value.run.assert_called_once()

    def test_catches_per_target_exception(self):
        from reverge_collector.iis_short_scan import iis_short_scan_wrap

        scanner = _make_scanner(is_vuln=False, raises=RuntimeError('boom'))
        with patch('reverge_collector.iis_short_scan.Scanner', return_value=scanner):
            out = iis_short_scan_wrap(['https://t/'])
        assert out[0]['vulnerable'] is False
        assert 'boom' in out[0]['error']


# ===========================================================================
# execute_scan
# ===========================================================================


def test_execute_scan_skips_when_output_exists(tmp_path, monkeypatch):
    from reverge_collector.iis_short_scan import execute_scan, get_output_path

    monkeypatch.chdir(tmp_path)
    scan = make_scan(tmp_path)
    out = get_output_path(scan)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, 'w') as f:
        f.write('{}')
    with patch('reverge_collector.scan_utils.executor.submit') as m:
        execute_scan(scan)
        m.assert_not_called()


def test_execute_scan_raises_when_no_urls(tmp_path, monkeypatch):
    """When the scope produces no URLs (empty obj_list, no ports) the
    function raises RuntimeError per the else branch."""
    from reverge_collector.iis_short_scan import execute_scan

    monkeypatch.chdir(tmp_path)
    scan = make_scan(tmp_path, obj_list=[])
    with pytest.raises(RuntimeError, match='No ports'):
        execute_scan(scan)


def test_execute_scan_with_endpoints_submits_per_port(tmp_path, monkeypatch):
    """A scope with host:port → submit is invoked; the resulting JSON
    file is written."""
    from reverge_collector.iis_short_scan import execute_scan, get_output_path

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

    # Capture the target list, return matching results
    submitted_targets = []

    def _submit(*args, **kwargs):
        submitted_targets.extend(kwargs['target_url_list'])
        f = MagicMock()
        f.result.return_value = [
            {'target': t, 'vulnerable': True, 'files': ['admin~1.asp'], 'dirs': []}
            for t in kwargs['target_url_list']
        ]
        return f

    with patch('reverge_collector.scan_utils.executor.submit', side_effect=_submit) as sub:
        execute_scan(scan)
    assert sub.called
    assert submitted_targets  # at least one URL submitted
    out = get_output_path(scan)
    body = json.loads(open(out).read())
    # Output written, even if empty when target URL doesn't match port mapping
    assert isinstance(body, dict)


def test_execute_scan_skips_url_without_port_id(tmp_path, monkeypatch):
    """A URL with no port_id is logged and skipped without crashing."""
    from reverge_collector.iis_short_scan import execute_scan

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
    # Force get_url_metadata_map to return an entry without port_id
    with (
        patch.object(
            scan.scan_data,
            'get_url_metadata_map',
            return_value={'https://10.0.0.1/': {'path': '/', 'port_id': None}},
        ),
        patch('reverge_collector.scan_utils.executor.submit') as sub,
    ):
        execute_scan(scan)
    # No port_id means no scan submitted
    sub.assert_not_called()
