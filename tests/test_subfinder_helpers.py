"""Tests for subfinder_scan.update_config_file and get_subfinder_input.

These cover the YAML-config update + scope-file write paths that the
existing route test exercises only at a happy-path level.
"""

from __future__ import annotations

import base64
import os
import threading
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
import yaml
from reverge_collector import data_model
from reverge_collector.scan_utils import get_port_byte_array


def _scope(obj_list, port_list_str='80'):
    return {
        'b64_port_bitmap': base64.b64encode(get_port_byte_array(port_list_str)).decode(),
        'obj_list': obj_list,
    }


def make_scan(tmp_path, *, obj_list=None, args=''):
    if obj_list is None:
        obj_list = []
    scan_id = 'sub-' + os.urandom(3).hex()
    scan_data = data_model.ScanData(_scope(obj_list))
    return SimpleNamespace(
        id=scan_id,
        scan_id=scan_id,
        target_id=1,
        scan_data=scan_data,
        current_tool=SimpleNamespace(id='tool-sub', name='subfinder', args=args),
        current_tool_instance_id='inst-' + os.urandom(3).hex(),
        collection_tool_map={},
        selected_interface=None,
        register_tool_executor=MagicMock(),
        tool_executor_map={},
        tool_executor_lock=threading.Lock(),
    )


# ===========================================================================
# get_subfinder_input
# ===========================================================================


def test_get_subfinder_input_writes_one_domain_per_line(tmp_path, monkeypatch):
    from reverge_collector.subfinder_scan import get_subfinder_input

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
        {
            'type': 'domain',
            'id': 'd2',
            'parent': {'type': 'host', 'id': 'h1'},
            'data': {'name': 'other.com'},
            'tags': [data_model.RecordTag.SCOPE.value],
        },
    ]
    scan = make_scan(tmp_path, obj_list=obj_list)
    out = get_subfinder_input(scan)
    assert os.path.exists(out['input_path'])
    body = open(out['input_path']).read()
    assert 'example.com' in body
    assert 'other.com' in body


def test_get_subfinder_input_writes_empty_when_no_domains(tmp_path, monkeypatch):
    from reverge_collector.subfinder_scan import get_subfinder_input

    monkeypatch.chdir(tmp_path)
    scan = make_scan(tmp_path, obj_list=[])
    out = get_subfinder_input(scan)
    assert os.path.exists(out['input_path'])
    assert open(out['input_path']).read() == ''


# ===========================================================================
# update_config_file
# ===========================================================================


def test_update_config_file_creates_template_when_missing(tmp_path, monkeypatch):
    from reverge_collector import subfinder_scan as mod

    home = tmp_path / 'home'
    cfg_dir = home / '.config' / 'subfinder'
    cfg_dir.mkdir(parents=True)
    cfg_path = cfg_dir / 'provider-config.yaml'
    cfg_path.write_text(yaml.dump({'chaos': [], 'shodan': []}))

    monkeypatch.setenv('HOME', str(home))
    monkeypatch.setattr(os.path, 'expanduser', lambda p: str(home) if p == '~' else p)

    # Force the "config missing" branch: file exists check is patched off
    # Reset on second call (already True after creation), but the production
    # code only checks once and falls through to the read step regardless.
    fake_future = MagicMock()
    fake_future.result.return_value = None
    with patch.object(mod.scan_utils.executor, 'submit', return_value=fake_future):
        mod.update_config_file(collection_tools=None, my_env=os.environ.copy())

    # Re-read config: should still have empty chaos/shodan entries
    body = yaml.safe_load(cfg_path.read_text())
    assert body.get('chaos') == []
    assert body.get('shodan') == []


def test_update_config_file_writes_api_keys_from_tools(tmp_path, monkeypatch):
    from reverge_collector import subfinder_scan as mod

    home = tmp_path / 'home'
    cfg_dir = home / '.config' / 'subfinder'
    cfg_dir.mkdir(parents=True)
    cfg_path = cfg_dir / 'provider-config.yaml'
    cfg_path.write_text(yaml.dump({'chaos': [], 'shodan': []}))

    monkeypatch.setattr(os.path, 'expanduser', lambda p: str(home) if p == '~' else p)

    chaos_tool = SimpleNamespace(
        collection_tool=SimpleNamespace(name='chaos'),
        api_key='chaos-key-123',
    )
    shodan_tool = SimpleNamespace(
        collection_tool=SimpleNamespace(name='shodan'),
        api_key='shodan-key-456',
    )
    # A non-relevant tool name is ignored
    other_tool = SimpleNamespace(
        collection_tool=SimpleNamespace(name='unrelated'),
        api_key='ignored',
    )

    mod.update_config_file(
        [chaos_tool, shodan_tool, other_tool],
        os.environ.copy(),
    )

    body = yaml.safe_load(cfg_path.read_text())
    assert body['chaos'] == ['chaos-key-123']
    assert body['shodan'] == ['shodan-key-456']
    assert 'unrelated' not in body
