"""Tests for crapsecrets_scan.request_wrapper and parse_crapsecrets_output."""

from __future__ import annotations

import json
import os
from unittest.mock import MagicMock, patch

import pytest


# ===========================================================================
# request_wrapper
# ===========================================================================


class TestRequestWrapper:
    def test_returns_parsed_json_on_success(self):
        from reverge_collector.crapsecrets_scan import request_wrapper

        with patch(
            'reverge_collector.crapsecrets_scan.process_wrapper',
            return_value={'exit_code': 0,
                          'stdout': json.dumps([{'secret_type': 'aws_key',
                                                  'secret': 'AKIA...'}]),
                          'stderr': ''},
        ):
            out = request_wrapper({'url': 'https://target/'})
        assert out['url'] == 'https://target/'
        assert isinstance(out['output'], list)
        assert out['output'][0]['secret_type'] == 'aws_key'

    def test_returns_raw_when_stdout_not_json(self):
        from reverge_collector.crapsecrets_scan import request_wrapper

        with patch(
            'reverge_collector.crapsecrets_scan.process_wrapper',
            return_value={'exit_code': 0, 'stdout': 'plain text not json',
                          'stderr': ''},
        ):
            out = request_wrapper({'url': 'https://target/'})
        assert out['output'] == [{'raw_output': 'plain text not json'}]

    def test_logs_and_returns_empty_when_stderr(self):
        from reverge_collector.crapsecrets_scan import request_wrapper

        with patch(
            'reverge_collector.crapsecrets_scan.process_wrapper',
            return_value={'exit_code': 0, 'stdout': '', 'stderr': 'bad cert'},
        ):
            out = request_wrapper({'url': 'https://target/'})
        assert out['output'] == []

    def test_includes_custom_args(self):
        from reverge_collector.crapsecrets_scan import request_wrapper

        with patch(
            'reverge_collector.crapsecrets_scan.process_wrapper',
            return_value={'exit_code': 0, 'stdout': '[]', 'stderr': ''},
        ) as pw:
            request_wrapper({'url': 'https://target/', 'custom_args': ['-x', 'extra']})
        cmd = pw.call_args.kwargs['cmd_args']
        assert '-x' in cmd
        assert 'extra' in cmd

    def test_retries_on_exception_then_gives_up(self):
        from reverge_collector.crapsecrets_scan import request_wrapper

        # process_wrapper raises every time → loop hits count > 2 → break
        with (
            patch(
                'reverge_collector.crapsecrets_scan.process_wrapper',
                side_effect=RuntimeError('subprocess error'),
            ),
            patch('time.sleep'),
        ):
            out = request_wrapper({'url': 'https://target/'})
        # output stays empty after all retries
        assert out['output'] == []


# ===========================================================================
# parse_crapsecrets_output
# ===========================================================================


class TestParseCrapsecretsOutput:
    def test_returns_empty_when_meta_empty(self, tmp_path):
        from reverge_collector.crapsecrets_scan import parse_crapsecrets_output

        p = tmp_path / 'cs.json'
        p.write_text('')
        assert parse_crapsecrets_output(str(p), 'ti', 'td') == []

    def test_empty_output_list_returns_empty(self, tmp_path):
        from reverge_collector.crapsecrets_scan import parse_crapsecrets_output

        p = tmp_path / 'cs.json'
        p.write_text(json.dumps({'output_list': []}))
        assert parse_crapsecrets_output(str(p), 'ti', 'td') == []

    def test_entry_with_no_output_is_skipped(self, tmp_path):
        from reverge_collector.crapsecrets_scan import parse_crapsecrets_output

        p = tmp_path / 'cs.json'
        p.write_text(json.dumps({'output_list': [
            {'output': None, 'http_endpoint_id': 'ep1', 'port_id': 'p1'},
        ]}))
        assert parse_crapsecrets_output(str(p), 'ti', 'td') == []

    def test_dict_output_with_results_key(self, tmp_path):
        from reverge_collector.crapsecrets_scan import parse_crapsecrets_output

        p = tmp_path / 'cs.json'
        p.write_text(json.dumps({'output_list': [
            {
                'output': {
                    'target': 'https://target/',
                    'results': [{'secret_type': 'aws_key', 'secret': 'AKIA...'}],
                },
                'http_endpoint_id': 'ep1',
                'port_id': 'p1',
            }
        ]}))
        records = parse_crapsecrets_output(str(p), 'ti', 'td')
        types = {type(r).__name__ for r in records}
        assert 'Vuln' in types
        assert 'CollectionModule' in types
        assert 'CollectionModuleOutput' in types

    def test_list_output_legacy_format(self, tmp_path):
        from reverge_collector.crapsecrets_scan import parse_crapsecrets_output

        p = tmp_path / 'cs.json'
        p.write_text(json.dumps({'output_list': [
            {
                'output': [{'secret_type': 'github_token', 'secret': 'ghp_...'}],
                'http_endpoint_id': 'ep1',
                'port_id': 'p1',
            }
        ]}))
        records = parse_crapsecrets_output(str(p), 'ti', 'td')
        vulns = [r for r in records if type(r).__name__ == 'Vuln']
        assert vulns and vulns[0].name == 'github_token'

    def test_finding_without_secret_skips_vuln(self, tmp_path):
        """Finding dict without a 'secret' field → only CollectionModule +
        Output (no Vuln record)."""
        from reverge_collector.crapsecrets_scan import parse_crapsecrets_output

        p = tmp_path / 'cs.json'
        p.write_text(json.dumps({'output_list': [
            {
                'output': [{'secret_type': 'aws_key'}],
                'http_endpoint_id': 'ep1',
                'port_id': 'p1',
            }
        ]}))
        records = parse_crapsecrets_output(str(p), 'ti', 'td')
        vulns = [r for r in records if type(r).__name__ == 'Vuln']
        assert not vulns

    def test_non_dict_finding_is_swallowed(self, tmp_path):
        """A finding that isn't a dict skips the Vuln/Module path entirely."""
        from reverge_collector.crapsecrets_scan import parse_crapsecrets_output

        p = tmp_path / 'cs.json'
        p.write_text(json.dumps({'output_list': [
            {
                'output': ['just a string', {'secret_type': 'ok', 'secret': 'x'}],
                'http_endpoint_id': 'ep1',
                'port_id': 'p1',
            }
        ]}))
        records = parse_crapsecrets_output(str(p), 'ti', 'td')
        # Only the second (dict) finding produces records
        vulns = [r for r in records if type(r).__name__ == 'Vuln']
        assert len(vulns) == 1
