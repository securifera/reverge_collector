"""Tests for tool_utils._load_session_key, _save_session_key, get_session_key,
and parse_nmap_xml_to_jsonable wrapper."""

from __future__ import annotations

import binascii
import os
from unittest.mock import MagicMock, patch

import pytest


# ===========================================================================
# _load_session_key / _save_session_key
# ===========================================================================


def test_load_session_key_returns_none_when_missing(tmp_path, monkeypatch):
    from reverge_collector import tool_utils

    monkeypatch.setattr(tool_utils, '_SESSION_FILE', str(tmp_path / 'session'))
    assert tool_utils._load_session_key() is None


def test_load_session_key_returns_bytes_when_present(tmp_path, monkeypatch):
    from reverge_collector import tool_utils

    fpath = tmp_path / 'session'
    fpath.write_text(binascii.hexlify(b'A' * 32).decode())
    monkeypatch.setattr(tool_utils, '_SESSION_FILE', str(fpath))
    assert tool_utils._load_session_key() == b'A' * 32


def test_load_session_key_returns_none_on_decode_error(tmp_path, monkeypatch):
    from reverge_collector import tool_utils

    fpath = tmp_path / 'session'
    fpath.write_text('not-valid-hex!!')
    monkeypatch.setattr(tool_utils, '_SESSION_FILE', str(fpath))
    assert tool_utils._load_session_key() is None


def test_save_session_key_writes_hex(tmp_path, monkeypatch):
    from reverge_collector import tool_utils

    fpath = tmp_path / 'session'
    monkeypatch.setattr(tool_utils, '_SESSION_FILE', str(fpath))
    tool_utils._save_session_key(b'\x01\x02\x03')
    assert fpath.read_text() == '010203'


def test_save_session_key_swallows_write_failures(tmp_path, monkeypatch):
    from reverge_collector import tool_utils

    monkeypatch.setattr(tool_utils, '_SESSION_FILE', str(tmp_path / 'session'))
    with patch('reverge_collector.tool_utils.os.open', side_effect=OSError('readonly')):
        # Should not raise — the warning is logged but execution continues
        tool_utils._save_session_key(b'\x00\x01')


# ===========================================================================
# get_session_key (cache hit)
# ===========================================================================


def test_get_session_key_returns_cached_when_use_cached_true(tmp_path, monkeypatch):
    from reverge_collector import tool_utils

    monkeypatch.setattr(tool_utils, '_SESSION_FILE',
                        str(tmp_path / 'session'))
    cached = b'\xaa' * 32
    with patch.object(tool_utils, '_load_session_key', return_value=cached):
        out = tool_utils.get_session_key('https://server', {'Authorization': 't'})
    assert out == cached


def test_get_session_key_raises_when_http_non_200(tmp_path, monkeypatch):
    from reverge_collector import tool_utils

    monkeypatch.setattr(tool_utils, '_SESSION_FILE',
                        str(tmp_path / 'no-cache'))
    resp = MagicMock()
    resp.status_code = 500
    with patch('reverge_collector.tool_utils.requests.post', return_value=resp):
        with pytest.raises(RuntimeError, match='HTTP 500'):
            tool_utils.get_session_key('https://server', {'Authorization': 't'})


def test_get_session_key_raises_when_no_data_in_response(tmp_path, monkeypatch):
    from reverge_collector import tool_utils

    monkeypatch.setattr(tool_utils, '_SESSION_FILE',
                        str(tmp_path / 'no-cache'))
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {'other': 'value'}
    with patch('reverge_collector.tool_utils.requests.post', return_value=resp):
        with pytest.raises(RuntimeError, match='did not return'):
            tool_utils.get_session_key('https://server', {'Authorization': 't'})


# ===========================================================================
# parse_nmap_xml_to_jsonable
# ===========================================================================


def test_parse_nmap_xml_to_jsonable_calls_record_to_jsonable():
    from reverge_collector import tool_utils

    fake_rec = MagicMock()
    fake_rec.to_jsonable.return_value = {'type': 'host', 'data': {}}
    with patch('reverge_collector.nmap_scan.parse_nmap_xml', return_value=[fake_rec]):
        out = tool_utils.parse_nmap_xml_to_jsonable('/x/y.xml')
    assert out == [{'type': 'host', 'data': {}}]
