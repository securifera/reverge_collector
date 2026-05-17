"""Tests for the small Metasploit helper functions:
_read_msf_token, _fingerprint (RPC + binary-hash fallback),
metasploit_modules (cache wrapper)."""

from __future__ import annotations

import hashlib
import os
from unittest.mock import MagicMock, patch

import pytest


# ===========================================================================
# _read_msf_token
# ===========================================================================


class TestReadMsfToken:
    def test_reads_env_var_when_set(self, monkeypatch):
        from reverge_collector.metasploit_scan import Metasploit

        monkeypatch.setenv('MSF_JSON_RPC_TOKEN', 'env-tok')
        assert Metasploit._read_msf_token() == 'env-tok'

    def test_reads_token_file_when_env_unset(self, tmp_path, monkeypatch):
        from reverge_collector.metasploit_scan import Metasploit

        monkeypatch.delenv('MSF_JSON_RPC_TOKEN', raising=False)
        tok_file = tmp_path / 'token'
        tok_file.write_text('file-tok\n')
        real_open = open

        def _open_redirect(p, *a, **kw):
            if p == '/opt/collector/msf_rpc_token':
                return real_open(str(tok_file), *a, **kw)
            return real_open(p, *a, **kw)

        with (
            patch('reverge_collector.metasploit_scan.os.path.exists', return_value=True),
            patch('builtins.open', side_effect=_open_redirect),
        ):
            assert Metasploit._read_msf_token() == 'file-tok'

    def test_returns_empty_when_nothing_available(self, monkeypatch):
        from reverge_collector.metasploit_scan import Metasploit

        monkeypatch.delenv('MSF_JSON_RPC_TOKEN', raising=False)
        # Patch os.path.exists to claim the token file is missing
        with patch('reverge_collector.metasploit_scan.os.path.exists', return_value=False):
            assert Metasploit._read_msf_token() == ''


# ===========================================================================
# _fingerprint
# ===========================================================================


class TestFingerprint:
    def test_uses_core_version_when_rpc_succeeds(self):
        from reverge_collector.metasploit_scan import Metasploit

        resp = MagicMock()
        resp.raise_for_status = MagicMock()
        resp.json.return_value = {'result': {'version': '6.4.10'}}
        with patch('reverge_collector.metasploit_scan.requests.post', return_value=resp):
            assert Metasploit._fingerprint(bearer_token='t') == '6.4.10'

    def test_uses_framework_field_when_version_missing(self):
        from reverge_collector.metasploit_scan import Metasploit

        resp = MagicMock()
        resp.raise_for_status = MagicMock()
        resp.json.return_value = {'result': {'framework': '6.5'}}
        with patch('reverge_collector.metasploit_scan.requests.post', return_value=resp):
            assert Metasploit._fingerprint(bearer_token='t') == '6.5'

    def test_falls_back_to_binary_hash_when_rpc_fails(self, tmp_path):
        from reverge_collector.metasploit_scan import Metasploit

        # Make rpc throw, then point shutil.which at a real file we control
        fake_bin = tmp_path / 'msfconsole'
        fake_bin.write_bytes(b'fake-binary-content')
        expected_hash = hashlib.sha256(b'fake-binary-content').hexdigest()
        with (
            patch('reverge_collector.metasploit_scan.requests.post',
                  side_effect=Exception('rpc-down')),
            patch('shutil.which', return_value=str(fake_bin)),
        ):
            out = Metasploit._fingerprint(bearer_token='t')
        assert out == expected_hash

    def test_returns_none_when_rpc_fails_and_no_binary(self):
        from reverge_collector.metasploit_scan import Metasploit

        with (
            patch('reverge_collector.metasploit_scan.requests.post',
                  side_effect=Exception('rpc-down')),
            patch('shutil.which', return_value=None),
        ):
            assert Metasploit._fingerprint(bearer_token='t') is None

    def test_returns_none_when_rpc_returns_empty_result(self, tmp_path):
        """No version in result + no binary → None."""
        from reverge_collector.metasploit_scan import Metasploit

        resp = MagicMock()
        resp.raise_for_status = MagicMock()
        resp.json.return_value = {'result': {}}
        with (
            patch('reverge_collector.metasploit_scan.requests.post', return_value=resp),
            patch('shutil.which', return_value=None),
        ):
            assert Metasploit._fingerprint(bearer_token='t') is None


# ===========================================================================
# metasploit_modules (cache wrapper)
# ===========================================================================


def test_metasploit_modules_delegates_to_cache(monkeypatch):
    """The static metasploit_modules method just wraps get_cached_modules
    with the right env-derived parameters and the two callables."""
    from reverge_collector.metasploit_scan import Metasploit

    monkeypatch.setenv('MSF_JSON_RPC_HOST', '1.2.3.4')
    monkeypatch.setenv('MSF_JSON_RPC_PORT', '4444')
    monkeypatch.setenv('MSF_JSON_RPC_TOKEN', 't')
    monkeypatch.setenv('MSF_JSON_RPC_SSL', 'true')

    sentinel = [MagicMock(name='module-1')]
    with patch(
        'reverge_collector.module_cache.get_cached_modules',
        return_value=sentinel,
    ) as cache_mock:
        out = Metasploit.metasploit_modules()
    assert out is sentinel
    args, kwargs = cache_mock.call_args
    # name + fp_func + gen_func
    assert args[0] == 'metasploit'
    assert callable(args[1])
    assert callable(args[2])
