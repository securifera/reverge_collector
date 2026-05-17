"""Tests for subfinder_scan.subfinder_wrapper success/error branches."""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest


def _make_scan():
    return SimpleNamespace(
        id='scan-1',
        register_tool_executor=MagicMock(),
        current_tool_instance_id='inst-1',
    )


def test_subfinder_wrapper_returns_parsed_results(tmp_path):
    from reverge_collector.subfinder_scan import subfinder_wrapper

    out_file = tmp_path / 'subfinder.json'
    with open(out_file, 'w') as f:
        f.write(json.dumps({'host': 'a.example.com', 'ip': '10.0.0.1'}) + '\n')
        f.write(json.dumps({'host': 'b.example.com', 'ip': '10.0.0.2'}) + '\n')

    with patch(
        'reverge_collector.subfinder_scan.process_wrapper',
        return_value={'exit_code': 0, 'stdout': '', 'stderr': ''},
    ):
        out = subfinder_wrapper(_make_scan(), str(out_file), ['subfinder'], False, {})
    assert {'ip': '10.0.0.1', 'domain': 'a.example.com'} in out
    assert {'ip': '10.0.0.2', 'domain': 'b.example.com'} in out


def test_subfinder_wrapper_skips_entries_missing_host_or_ip(tmp_path):
    from reverge_collector.subfinder_scan import subfinder_wrapper

    out_file = tmp_path / 'subfinder.json'
    with open(out_file, 'w') as f:
        f.write(json.dumps({'host': 'a.example.com'}) + '\n')  # no ip
        f.write(json.dumps({'ip': '10.0.0.2'}) + '\n')  # no host
        f.write(json.dumps({'host': 'c.example.com', 'ip': '10.0.0.3'}) + '\n')

    with patch(
        'reverge_collector.subfinder_scan.process_wrapper',
        return_value={'exit_code': 0, 'stdout': '', 'stderr': ''},
    ):
        out = subfinder_wrapper(_make_scan(), str(out_file), ['subfinder'], False, {})
    # Only the third entry survives
    assert len(out) == 1
    assert out[0]['domain'] == 'c.example.com'


def test_subfinder_wrapper_raises_on_nonzero_exit(tmp_path):
    from reverge_collector.subfinder_scan import subfinder_wrapper

    out_file = tmp_path / 'subfinder.json'
    out_file.write_text('')
    with patch(
        'reverge_collector.subfinder_scan.process_wrapper',
        return_value={'exit_code': 2, 'stdout': '', 'stderr': 'api key invalid'},
    ):
        with pytest.raises(RuntimeError, match='exited with code 2'):
            subfinder_wrapper(_make_scan(), str(out_file), ['subfinder'], False, {})


def test_subfinder_wrapper_handles_empty_ret_dict(tmp_path):
    """process_wrapper returning None / missing exit_code → no raise."""
    from reverge_collector.subfinder_scan import subfinder_wrapper

    out_file = tmp_path / 'subfinder.json'
    out_file.write_text('')
    with patch(
        'reverge_collector.subfinder_scan.process_wrapper',
        return_value=None,
    ):
        out = subfinder_wrapper(_make_scan(), str(out_file), ['subfinder'], False, {})
    assert out == []
