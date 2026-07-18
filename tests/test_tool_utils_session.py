"""Tests for tool_utils._load_session_key, _save_session_key, get_session_key,
and parse_nmap_xml_to_jsonable wrapper."""

from __future__ import annotations

import base64
import binascii
import os
from unittest.mock import MagicMock, patch

import pytest
import requests
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.PublicKey import RSA

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

    monkeypatch.setattr(tool_utils, '_SESSION_FILE', str(tmp_path / 'session'))
    cached = b'\xaa' * 32
    with patch.object(tool_utils, '_load_session_key', return_value=cached):
        out = tool_utils.get_session_key('https://server', {'Authorization': 't'})
    assert out == cached


def test_get_session_key_raises_when_http_non_200(tmp_path, monkeypatch):
    from reverge_collector import tool_utils

    monkeypatch.setattr(tool_utils, '_SESSION_FILE', str(tmp_path / 'no-cache'))
    resp = MagicMock()
    resp.status_code = 500
    with patch('reverge_collector.tool_utils.requests.post', return_value=resp):
        with pytest.raises(RuntimeError, match='HTTP 500'):
            tool_utils.get_session_key('https://server', {'Authorization': 't'})


def test_get_session_key_raises_when_no_data_in_response(tmp_path, monkeypatch):
    from reverge_collector import tool_utils

    monkeypatch.setattr(tool_utils, '_SESSION_FILE', str(tmp_path / 'no-cache'))
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {'other': 'value'}
    with patch('reverge_collector.tool_utils.requests.post', return_value=resp):
        with pytest.raises(RuntimeError, match='did not return'):
            tool_utils.get_session_key('https://server', {'Authorization': 't'})


# ===========================================================================
# get_session_key (transient connection errors -> retry, not crash)
# ===========================================================================


def _encrypted_session_key_response(rsa_key, session_key):
    """Build a MagicMock 200 response carrying an RSA-encrypted session key."""
    enc = PKCS1_OAEP.new(rsa_key.publickey()).encrypt(session_key)
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {'data': base64.b64encode(enc).decode()}
    return resp


def test_get_session_key_retries_on_connection_error_then_succeeds(tmp_path, monkeypatch):
    """A transient RST during the handshake must be retried, not propagated.

    Regression for a ConnectionResetError(104) during POST /api/session that
    crashed the whole registration on the first failure.
    """
    from reverge_collector import tool_utils

    monkeypatch.setattr(tool_utils, '_SESSION_FILE', str(tmp_path / 'no-cache'))

    # Pin the key so the crafted success response decrypts to a known value.
    fixed_key = RSA.generate(2048)
    monkeypatch.setattr(tool_utils.RSA, 'generate', lambda _bits: fixed_key)

    session_key = b'\x11' * 32
    good = _encrypted_session_key_response(fixed_key, session_key)

    post = MagicMock(
        side_effect=[
            requests.ConnectionError('reset by peer'),
            requests.ConnectionError('reset by peer'),
            good,
        ]
    )
    with patch('reverge_collector.tool_utils.requests.post', post):
        with patch('reverge_collector.tool_utils.time.sleep'):
            out = tool_utils.get_session_key(
                'https://server',
                {'Authorization': 't'},
                use_cached=False,
                persist=False,
            )

    assert out == session_key
    assert post.call_count == 3


def test_get_session_key_raises_after_exhausting_retries(tmp_path, monkeypatch):
    """When the server stays unreachable, give up after the retry ladder and
    raise RuntimeError (a clean, catchable failure) rather than leaking the raw
    ConnectionError."""
    from reverge_collector import tool_utils

    monkeypatch.setattr(tool_utils, '_SESSION_FILE', str(tmp_path / 'no-cache'))
    # Pin a pre-generated key so the failure path doesn't pay for RSA keygen on
    # every one of the retry attempts.
    fixed_key = RSA.generate(2048)
    monkeypatch.setattr(tool_utils.RSA, 'generate', lambda _bits: fixed_key)

    post = MagicMock(side_effect=requests.ConnectionError('reset by peer'))
    with patch('reverge_collector.tool_utils.requests.post', post):
        with patch('reverge_collector.tool_utils.time.sleep'):
            with pytest.raises(RuntimeError, match='session key exchange failed'):
                tool_utils.get_session_key(
                    'https://server',
                    {'Authorization': 't'},
                    use_cached=False,
                    persist=False,
                )

    assert post.call_count == tool_utils._SESSION_MAX_RETRIES + 1


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
