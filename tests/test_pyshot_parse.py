"""Tests for pyshot_scan.parse_pyshot_output and helpers."""

from __future__ import annotations

import json
import os
from unittest.mock import patch

import pytest


def _write_meta(tmp_path, entries):
    """Write a JSONL meta file (one screenshot per line)."""
    p = tmp_path / 'meta.json'
    with open(p, 'w') as f:
        for entry in entries:
            f.write(json.dumps(entry) + '\n')
    return str(p)


def _write_image(tmp_path, name='shot.png', content=b'PNG-BYTES'):
    img = tmp_path / name
    img.write_bytes(content)
    return str(img)


def test_parse_returns_empty_when_meta_missing(tmp_path):
    from reverge_collector.pyshot_scan import parse_pyshot_output

    assert parse_pyshot_output(str(tmp_path / 'nope'), 'ti') == []


def test_parse_skips_lines_whose_image_doesnt_exist(tmp_path):
    from reverge_collector.pyshot_scan import parse_pyshot_output

    meta = _write_meta(
        tmp_path,
        [
            {
                'file_path': str(tmp_path / 'missing.png'),
                'path': '/',
                'port_id': 'p1',
                'status_code': 200,
                'endpoint_id': None,
            }
        ],
    )
    assert parse_pyshot_output(meta, 'ti') == []


def test_parse_builds_full_record_chain(tmp_path):
    from reverge_collector.pyshot_scan import parse_pyshot_output

    img = _write_image(tmp_path)
    meta = _write_meta(
        tmp_path,
        [
            {
                'file_path': img,
                'path': '/admin',
                'port_id': 'p1',
                'status_code': 200,
                'endpoint_id': None,
                'domain': 'example.com',
            }
        ],
    )
    records = parse_pyshot_output(meta, 'ti')
    types = [type(r).__name__ for r in records]
    assert 'Screenshot' in types
    assert 'Domain' in types
    assert 'ListItem' in types
    assert 'HttpEndpoint' in types
    assert 'HttpEndpointData' in types


def test_parse_dedups_screenshots_with_same_hash(tmp_path):
    """Two meta entries pointing at the same image bytes → one Screenshot
    (deduped via image_hash_str)."""
    from reverge_collector.pyshot_scan import parse_pyshot_output

    img = _write_image(tmp_path)
    meta = _write_meta(
        tmp_path,
        [
            {
                'file_path': img,
                'path': '/a',
                'port_id': 'p1',
                'status_code': 200,
                'endpoint_id': None,
            },
            {
                'file_path': img,
                'path': '/b',
                'port_id': 'p1',
                'status_code': 200,
                'endpoint_id': None,
            },
        ],
    )
    records = parse_pyshot_output(meta, 'ti')
    # Two appends per entry, but unique screenshot objects = 1
    unique_screenshots = {id(r) for r in records if type(r).__name__ == 'Screenshot'}
    assert len(unique_screenshots) == 1


def test_parse_dedups_paths_and_domains(tmp_path):
    from reverge_collector.pyshot_scan import parse_pyshot_output

    img = _write_image(tmp_path)
    meta = _write_meta(
        tmp_path,
        [
            {
                'file_path': img,
                'path': '/',
                'port_id': 'p1',
                'status_code': 200,
                'endpoint_id': None,
                'domain': 'x.example.com',
            },
            {
                'file_path': img,
                'path': '/',
                'port_id': 'p2',
                'status_code': 200,
                'endpoint_id': None,
                'domain': 'x.example.com',
            },
        ],
    )
    records = parse_pyshot_output(meta, 'ti')
    paths = {id(r) for r in records if type(r).__name__ == 'ListItem'}
    domains = {id(r) for r in records if type(r).__name__ == 'Domain'}
    assert len(paths) == 1
    assert len(domains) == 1


def test_parse_keeps_endpoint_data_id_when_provided(tmp_path):
    from reverge_collector.pyshot_scan import parse_pyshot_output

    img = _write_image(tmp_path)
    meta = _write_meta(
        tmp_path,
        [
            {
                'file_path': img,
                'path': '/',
                'port_id': 'p1',
                'status_code': 200,
                'endpoint_id': 'epd-fixed',
            }
        ],
    )
    records = parse_pyshot_output(meta, 'ti')
    epds = [r for r in records if type(r).__name__ == 'HttpEndpointData']
    assert epds and epds[0].id == 'epd-fixed'


def test_pyshot_scan_func_returns_true_on_success(tmp_path, monkeypatch):
    from reverge_collector import pyshot_scan as mod

    with patch.object(mod, 'execute_scan', return_value=None):
        assert mod.pyshot_scan_func(object()) is True


def test_pyshot_scan_func_reraises_on_error():
    from reverge_collector import pyshot_scan as mod

    with patch.object(mod, 'execute_scan', side_effect=RuntimeError('boom')):
        with pytest.raises(RuntimeError, match='boom'):
            mod.pyshot_scan_func(object())
