"""Tests for metasploit_scan.execute_msfrpc_commands and
Metasploit._generate_metasploit_modules.

The RPC layer is the single biggest uncovered branch tree in
metasploit_scan. We mock ``requests.post`` and pump the staged JSON
responses the function expects so we can walk the create → drain →
write → read → destroy lifecycle without a live msfrpc daemon.
"""

from __future__ import annotations

import json
import os
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Helpers — build the JSON-RPC payloads the function consumes
# ---------------------------------------------------------------------------


def _rpc_resp(result=None, error=None):
    """Build a Response-like MagicMock that returns the supplied result."""
    body = {'jsonrpc': '2.0', 'id': 'x'}
    if error is not None:
        body['error'] = error
    else:
        body['result'] = result if result is not None else {}
    resp = MagicMock()
    resp.json.return_value = body
    resp.raise_for_status = MagicMock()
    return resp


def _create_ok(console_id='c-1'):
    return _rpc_resp({'id': console_id})


def _read(data='', busy=False):
    return _rpc_resp({'data': data, 'busy': busy})


def _write_ok():
    return _rpc_resp({'wrote': 1})


def _destroy_ok():
    return _rpc_resp({'result': 'success'})


# ===========================================================================
# execute_msfrpc_commands — happy paths
# ===========================================================================


class TestExecuteMsfrpcHappyPath:
    def test_basic_run_writes_output(self, tmp_path):
        from reverge_collector.metasploit_scan import execute_msfrpc_commands

        out_file = tmp_path / 'msf_out.txt'

        # Order: create → 10 banner drains → write(use module) → write(set RHOSTS)
        # → write(run) → read(busy=True data) → read(busy=False, no data)
        # → 20 trailing drains → destroy
        # Build with a counter
        responses = [
            _create_ok('c-1'),
        ]
        # The banner drain loops up to 10 times — each read returns busy=False to break early
        responses.append(_read(data='banner', busy=False))
        # write 'use ...'
        responses.append(_write_ok())
        # write 'set RHOSTS ...'
        responses.append(_write_ok())
        # write 'run'
        responses.append(_write_ok())
        # First main poll: produce data, busy still True
        responses.append(_read(data='SCANNING TARGETS\n', busy=True))
        # Second main poll: busy=False (clean finish)
        responses.append(_read(data='', busy=False))
        # Trailing drain: just one empty + busy=False to break
        responses.append(_read(data='', busy=False))
        # console.destroy
        responses.append(_destroy_ok())

        with patch(
            'reverge_collector.metasploit_scan.requests.post',
            side_effect=responses,
        ):
            out = execute_msfrpc_commands(
                ip_list=['10.0.0.1', '10.0.0.2'],
                module_path='auxiliary/scanner/smb/smb_version',
                output_file=str(out_file),
                bearer_token='tok',
                poll_interval=0,
                max_wait=10,
            )

        assert 'SCANNING TARGETS' in out
        assert out_file.read_text().strip() == 'SCANNING TARGETS'

    def test_session_opened_stops_polling_and_skips_destroy(self, tmp_path):
        from reverge_collector.metasploit_scan import execute_msfrpc_commands

        out_file = tmp_path / 'msf_out.txt'

        responses = [
            _create_ok('c-1'),
            _read(data='banner', busy=False),  # banner drain
            _write_ok(),  # use ...
            _write_ok(),  # set RHOSTS
            _write_ok(),  # run (exploit module → 'check')
            # The poll loop encounters "session opened" marker → break, no destroy
            _read(data='[*] Meterpreter session 1 opened (10.0.0.1)\n', busy=True),
        ]

        with patch(
            'reverge_collector.metasploit_scan.requests.post',
            side_effect=responses,
        ) as post_mock:
            out = execute_msfrpc_commands(
                ip_list=['10.0.0.1'],
                module_path='exploit/windows/smb/ms17_010_eternalblue',
                output_file=str(out_file),
                bearer_token='tok',
                poll_interval=0,
                max_wait=10,
            )

        assert 'Meterpreter session 1 opened' in out
        # Destroy should NOT have been called — verify no console.destroy in the calls
        for call in post_mock.call_args_list:
            payload = call.kwargs.get('json') or (call.args[1] if len(call.args) > 1 else None)
            if isinstance(payload, dict):
                assert payload.get('method') != 'console.destroy'

    def test_exploit_uses_check_and_aborted_breaks(self, tmp_path):
        from reverge_collector.metasploit_scan import execute_msfrpc_commands

        out_file = tmp_path / 'msf_out.txt'

        responses = [
            _create_ok('c-2'),
            _read(data='', busy=False),  # banner drain
            _write_ok(),  # use
            _write_ok(),  # set RHOSTS
            _write_ok(),  # check (exploit-module branch)
            # data contains Exploit aborted + busy=False → matches abort + not busy
            _read(data='Exploit aborted due to failure: no-target\n', busy=False),
            # Trailing drain
            _read(data='', busy=False),
            _destroy_ok(),
        ]

        write_calls = []

        def _capture(*args, **kwargs):
            payload = kwargs.get('json') or (args[1] if len(args) > 1 else None)
            if isinstance(payload, dict) and payload.get('method') == 'console.write':
                write_calls.append(payload['params'][1])
            return responses.pop(0)

        with patch(
            'reverge_collector.metasploit_scan.requests.post',
            side_effect=_capture,
        ):
            execute_msfrpc_commands(
                ip_list=['10.0.0.1'],
                module_path='exploit/multi/test',
                output_file=str(out_file),
                bearer_token='t',
                poll_interval=0,
                max_wait=10,
            )

        # Exploit module → should have used 'check\n', not 'run\n'
        assert any(s.strip() == 'check' for s in write_calls)


# ===========================================================================
# execute_msfrpc_commands — error / edge cases
# ===========================================================================


class TestExecuteMsfrpcErrors:
    def test_console_create_error_returns_empty(self, tmp_path):
        from reverge_collector.metasploit_scan import execute_msfrpc_commands

        out_file = tmp_path / 'out.txt'
        with patch(
            'reverge_collector.metasploit_scan.requests.post',
            return_value=_rpc_resp(error={'code': -1, 'message': 'no-console'}),
        ):
            out = execute_msfrpc_commands(
                ip_list=['1.1.1.1'],
                module_path='auxiliary/x',
                output_file=str(out_file),
                bearer_token='t',
                poll_interval=0,
                max_wait=1,
            )
        assert out == ''

    def test_console_create_returns_no_id(self, tmp_path):
        from reverge_collector.metasploit_scan import execute_msfrpc_commands

        out_file = tmp_path / 'out.txt'
        with patch(
            'reverge_collector.metasploit_scan.requests.post',
            return_value=_rpc_resp({'no_id_field': True}),
        ):
            out = execute_msfrpc_commands(
                ip_list=['1.1.1.1'],
                module_path='auxiliary/x',
                output_file=str(out_file),
                bearer_token='t',
                poll_interval=0,
                max_wait=1,
            )
        assert out == ''

    def test_rpc_exception_writes_empty_and_returns(self, tmp_path):
        """An exception mid-run is swallowed; the final write still happens."""
        from reverge_collector.metasploit_scan import execute_msfrpc_commands

        out_file = tmp_path / 'out.txt'

        # Create succeeds, then the very next call blows up
        seq = [_create_ok('c-3'), Exception('rpc-down')]

        def _side(*args, **kwargs):
            x = seq.pop(0)
            if isinstance(x, Exception):
                raise x
            return x

        with patch(
            'reverge_collector.metasploit_scan.requests.post',
            side_effect=_side,
        ):
            out = execute_msfrpc_commands(
                ip_list=['1.1.1.1'],
                module_path='auxiliary/x',
                output_file=str(out_file),
                bearer_token='t',
                poll_interval=0,
                max_wait=1,
            )

        assert out == ''
        # File still written (empty)
        assert os.path.exists(out_file)

    def test_additional_options_merged_into_set_commands(self, tmp_path):
        """Extra datastore options should appear in the console.write stream."""
        from reverge_collector.metasploit_scan import execute_msfrpc_commands

        out_file = tmp_path / 'out.txt'

        responses = [
            _create_ok('c-4'),
            _read(data='', busy=False),
            _write_ok(),  # use
            _write_ok(),  # set RHOSTS
            _write_ok(),  # set SMBUser
            _write_ok(),  # set SMBPass
            _write_ok(),  # run
            _read(data='', busy=False),  # busy clears
            _read(data='', busy=False),  # trailing
            _destroy_ok(),
        ]

        captured_writes = []

        def _side(*args, **kwargs):
            payload = kwargs.get('json') or (args[1] if len(args) > 1 else None)
            if isinstance(payload, dict) and payload.get('method') == 'console.write':
                captured_writes.append(payload['params'][1])
            return responses.pop(0)

        with patch(
            'reverge_collector.metasploit_scan.requests.post',
            side_effect=_side,
        ):
            execute_msfrpc_commands(
                ip_list=['1.1.1.1'],
                module_path='auxiliary/scanner/smb/smb_login',
                output_file=str(out_file),
                additional_options={'SMBUser': 'guest', 'SMBPass': 'pwn'},
                bearer_token='t',
                poll_interval=0,
                max_wait=10,
            )

        joined = ''.join(captured_writes)
        assert 'set SMBUser guest' in joined
        assert 'set SMBPass pwn' in joined
        assert 'set RHOSTS 1.1.1.1' in joined


# ===========================================================================
# Metasploit._generate_metasploit_modules
# ===========================================================================


class TestGenerateMetasploitModules:
    def test_returns_collection_modules_for_search_results(self):
        from reverge_collector.metasploit_scan import Metasploit

        # search returns module names; info returns description / options
        def _post_side(url, **kwargs):
            payload = kwargs.get('json', {})
            method = payload.get('method')
            params = payload.get('params', [])
            resp = MagicMock()
            resp.raise_for_status = MagicMock()
            if method == 'module.search':
                mtype_filter = params[0] if params else ''
                if 'auxiliary' in mtype_filter:
                    resp.json.return_value = {
                        'result': [{'fullname': 'auxiliary/scanner/smb/smb_version'}]
                    }
                else:
                    resp.json.return_value = {'result': []}
                return resp
            if method == 'module.info':
                resp.json.return_value = {
                    'result': {
                        'fullname': 'auxiliary/scanner/smb/smb_version',
                        'description': 'Probe SMB version banner',
                        'options': {
                            'RHOSTS': {'required': True, 'advanced': False, 'default': None},
                            'THREADS': {
                                'required': True,
                                'advanced': False,
                                'default': 1,
                            },
                            'SMBUser': {
                                'required': False,
                                'advanced': False,
                                'default': None,
                            },
                        },
                        'cpe': 'cpe:2.3:a:samba:smbd:*',
                    }
                }
                return resp
            resp.json.return_value = {}
            return resp

        with patch('reverge_collector.metasploit_scan.requests.post', side_effect=_post_side):
            mods = Metasploit._generate_metasploit_modules(
                msf_host='127.0.0.1',
                msf_port=8081,
                bearer_token='t',
                use_ssl=False,
                info_workers=2,
            )

        assert len(mods) == 1
        m = mods[0]
        assert m.name == 'auxiliary/scanner/smb/smb_version'
        assert m.description == 'Probe SMB version banner'
        # RHOSTS is auto-excluded; THREADS required+default → included with default 1
        assert 'THREADS=1' in m.args
        assert 'RHOSTS' not in m.args.split(' ', 1)[1] if ' ' in m.args else True
        # CPE is attached
        assert m.cpe == 'cpe:2.3:a:samba:smbd:*'

    def test_search_error_yields_no_modules_for_that_type(self):
        from reverge_collector.metasploit_scan import Metasploit

        def _side(url, **kwargs):
            payload = kwargs.get('json', {})
            resp = MagicMock()
            resp.raise_for_status = MagicMock()
            if payload.get('method') == 'module.search':
                resp.json.return_value = {'error': {'code': -1, 'message': 'broken'}}
            else:
                resp.json.return_value = {}
            return resp

        with patch('reverge_collector.metasploit_scan.requests.post', side_effect=_side):
            mods = Metasploit._generate_metasploit_modules(
                msf_host='127.0.0.1',
                msf_port=8081,
                bearer_token='t',
                use_ssl=False,
                info_workers=1,
            )
        assert mods == []

    def test_module_info_error_skips_that_module(self):
        from reverge_collector.metasploit_scan import Metasploit

        def _side(url, **kwargs):
            payload = kwargs.get('json', {})
            method = payload.get('method')
            params = payload.get('params', [])
            resp = MagicMock()
            resp.raise_for_status = MagicMock()
            if method == 'module.search':
                if 'auxiliary' in (params[0] if params else ''):
                    resp.json.return_value = {
                        'result': [
                            {'fullname': 'auxiliary/a/ok'},
                            {'fullname': 'auxiliary/a/broken'},
                        ]
                    }
                else:
                    resp.json.return_value = {'result': []}
                return resp
            if method == 'module.info':
                name = params[1] if len(params) > 1 else ''
                if 'broken' in name:
                    resp.json.return_value = {'error': {'code': -1, 'message': 'gone'}}
                else:
                    resp.json.return_value = {
                        'result': {
                            'fullname': 'auxiliary/a/ok',
                            'description': 'ok',
                            'options': {},
                        }
                    }
                return resp
            resp.json.return_value = {}
            return resp

        with patch('reverge_collector.metasploit_scan.requests.post', side_effect=_side):
            mods = Metasploit._generate_metasploit_modules(
                msf_host='127.0.0.1',
                msf_port=8081,
                bearer_token='t',
                use_ssl=False,
                info_workers=2,
            )
        # broken one skipped; ok one made it through
        names = [m.name for m in mods]
        assert 'auxiliary/a/ok' in names
        assert all('broken' not in n for n in names)

    def test_search_dict_result_unwrap(self):
        """module.search may return {'modules': [...]} instead of a list — both must work."""
        from reverge_collector.metasploit_scan import Metasploit

        def _side(url, **kwargs):
            payload = kwargs.get('json', {})
            method = payload.get('method')
            resp = MagicMock()
            resp.raise_for_status = MagicMock()
            if method == 'module.search':
                if 'auxiliary' in payload['params'][0]:
                    resp.json.return_value = {
                        'result': {'modules': [{'fullname': 'auxiliary/x/y'}]}
                    }
                else:
                    resp.json.return_value = {'result': {'modules': []}}
                return resp
            if method == 'module.info':
                resp.json.return_value = {
                    'result': {'fullname': 'auxiliary/x/y', 'description': 'd', 'options': {}}
                }
                return resp
            resp.json.return_value = {}
            return resp

        with patch('reverge_collector.metasploit_scan.requests.post', side_effect=_side):
            mods = Metasploit._generate_metasploit_modules(
                msf_host='127.0.0.1',
                msf_port=8081,
                bearer_token='t',
                use_ssl=False,
                info_workers=1,
            )
        assert len(mods) == 1
        assert mods[0].name == 'auxiliary/x/y'

    def test_search_non_list_non_dict_yields_nothing(self):
        from reverge_collector.metasploit_scan import Metasploit

        def _side(url, **kwargs):
            payload = kwargs.get('json', {})
            resp = MagicMock()
            resp.raise_for_status = MagicMock()
            if payload.get('method') == 'module.search':
                resp.json.return_value = {'result': 'unexpected-string'}
            else:
                resp.json.return_value = {}
            return resp

        with patch('reverge_collector.metasploit_scan.requests.post', side_effect=_side):
            mods = Metasploit._generate_metasploit_modules(
                msf_host='127.0.0.1',
                msf_port=8081,
                bearer_token='t',
                use_ssl=False,
                info_workers=1,
            )
        assert mods == []

    def test_short_name_used_when_fullname_missing(self):
        from reverge_collector.metasploit_scan import Metasploit

        def _side(url, **kwargs):
            payload = kwargs.get('json', {})
            method = payload.get('method')
            resp = MagicMock()
            resp.raise_for_status = MagicMock()
            if method == 'module.search':
                if 'auxiliary' in payload['params'][0]:
                    resp.json.return_value = {'result': [{'name': 'short_only'}]}
                else:
                    resp.json.return_value = {'result': []}
                return resp
            if method == 'module.info':
                resp.json.return_value = {
                    'result': {
                        'description': 'd',
                        'options': {},
                    }
                }
                return resp
            resp.json.return_value = {}
            return resp

        with patch('reverge_collector.metasploit_scan.requests.post', side_effect=_side):
            mods = Metasploit._generate_metasploit_modules(
                msf_host='127.0.0.1',
                msf_port=8081,
                bearer_token='t',
                use_ssl=False,
                info_workers=1,
            )
        # falls back to '<mtype>/<name>' as the fullname
        assert any(m.name == 'auxiliary/short_only' for m in mods)
