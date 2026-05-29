"""More tests for pyshot_scan: queue_scan, pyshot_wrapper, pyshot_import."""

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


def make_scan(tmp_path, *, obj_list=None, args=''):
    if obj_list is None:
        obj_list = []
    scan_id = 'pyshot-' + os.urandom(3).hex()
    scan_data = data_model.ScanData(_scope(obj_list))
    return SimpleNamespace(
        id=scan_id,
        scan_id=scan_id,
        target_id=1,
        scan_data=scan_data,
        current_tool=SimpleNamespace(id='tool-pyshot', name='pyshot', args=args),
        current_tool_instance_id='inst-' + os.urandom(3).hex(),
        collection_tool_map={},
        selected_interface=None,
        register_tool_executor=MagicMock(),
        tool_executor_map={},
        tool_executor_lock=threading.Lock(),
    )


# ===========================================================================
# pyshot_wrapper
# ===========================================================================


def test_pyshot_wrapper_invokes_take_screenshot():
    """pyshot_wrapper should call pyshot.take_screenshot with the args."""
    from reverge_collector import pyshot_scan as mod

    fake_lib = MagicMock()
    with patch.dict(
        'sys.modules', {'pyshot.pyshot': fake_lib, 'pyshot': MagicMock(pyshot=fake_lib)}
    ):
        out = mod.pyshot_wrapper(
            ip_addr='10.0.0.1',
            port='80',
            dir_path='/tmp/x',
            ssl_val=False,
            port_id=1,
            query_arg='/login',
            domain='example.com',
            http_endpoint_data_id='ep1',
        )
    assert out == ''
    fake_lib.take_screenshot.assert_called_once()
    kwargs = fake_lib.take_screenshot.call_args.kwargs
    assert kwargs['host'] == '10.0.0.1'
    assert kwargs['port_arg'] == '80'
    assert kwargs['query_arg'] == '/login'
    assert kwargs['secure'] is False
    assert kwargs['domain'] == 'example.com'
    assert kwargs['endpoint_id'] == 'ep1'


# ===========================================================================
# queue_scan
# ===========================================================================


def test_queue_scan_skips_when_construct_url_returns_none():
    """When construct_url returns None, the function bails without
    touching future_map."""
    from reverge_collector import pyshot_scan as mod

    mod.future_map = {}
    with patch.object(mod.scan_utils, 'construct_url', return_value=None):
        mod.queue_scan('h', '80', '/d', False, 1)
    assert mod.future_map == {}


def test_queue_scan_adds_new_url_to_map():
    from reverge_collector import pyshot_scan as mod

    mod.future_map = {}
    with patch.object(mod.scan_utils, 'construct_url', return_value='http://x/'):
        mod.queue_scan('h', '80', '/d', False, 1, http_endpoint_data_id='ep1')
    assert 'http://x/' in mod.future_map
    prev_id, _scan_tuple = mod.future_map['http://x/']
    assert prev_id == 'ep1'


def test_queue_scan_upgrades_when_new_endpoint_id_present():
    """An existing entry with prev_id=None should be replaced when a new
    request carries a non-None endpoint id."""
    from reverge_collector import pyshot_scan as mod

    mod.future_map = {}
    with patch.object(mod.scan_utils, 'construct_url', return_value='http://x/'):
        mod.queue_scan('h', '80', '/d', False, 1)  # no endpoint id
        mod.queue_scan('h', '80', '/d', False, 1, http_endpoint_data_id='ep1')
    prev_id, _ = mod.future_map['http://x/']
    assert prev_id == 'ep1'


def test_queue_scan_uses_domain_as_target_when_provided():
    from reverge_collector import pyshot_scan as mod

    mod.future_map = {}
    captured_args = {}

    def _construct_url(host, port, secure, qa):
        captured_args['host'] = host
        return 'http://h/'

    with patch.object(mod.scan_utils, 'construct_url', side_effect=_construct_url):
        mod.queue_scan('10.0.0.1', '80', '/d', False, 1, domain_str='example.com')
    assert captured_args['host'] == 'example.com'


# ===========================================================================
# pyshot_import
# ===========================================================================


def test_pyshot_import_returns_true_when_output_missing(tmp_path, monkeypatch):
    from reverge_collector import pyshot_scan as mod

    monkeypatch.chdir(tmp_path)
    scan = make_scan(tmp_path)
    # Output path doesn't exist → returns True without calling parser
    with patch.object(mod, 'parse_pyshot_output') as p:
        assert mod.pyshot_import(scan) is True
        p.assert_not_called()


def test_pyshot_import_reraises_on_error(tmp_path, monkeypatch):
    from reverge_collector import pyshot_scan as mod

    monkeypatch.chdir(tmp_path)
    scan = make_scan(tmp_path)
    with patch.object(mod, 'get_output_path', side_effect=RuntimeError('boom')):
        with pytest.raises(RuntimeError, match='boom'):
            mod.pyshot_import(scan)
