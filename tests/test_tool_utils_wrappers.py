"""Tests for the parse_X_to_jsonable wrappers in tool_utils.py.

Each wrapper is a thin shim around a scanner module's parse function.
Test that each wrapper invokes the underlying parser and returns the
JSON-serialised records.
"""

from __future__ import annotations

import json

import pytest


def test_parse_masscan_xml_to_jsonable_passes_through(tmp_path):
    from reverge_collector.tool_utils import parse_masscan_xml_to_jsonable

    f = tmp_path / 'm.xml'
    f.write_text(
        '<?xml version="1.0"?><nmaprun>'
        '<host><address addr="1.2.3.4" addrtype="ipv4"/>'
        '<ports><port protocol="tcp" portid="80"/></ports></host>'
        '</nmaprun>'
    )
    out = parse_masscan_xml_to_jsonable(str(f), 'tid')
    assert isinstance(out, list)
    assert all('type' in d for d in out)


def test_parse_nmap_xml_to_jsonable_passes_through(tmp_path):
    from reverge_collector.tool_utils import parse_nmap_xml_to_jsonable

    f = tmp_path / 'n.xml'
    f.write_text(
        '<?xml version="1.0"?><!DOCTYPE nmaprun><nmaprun scanner="nmap">'
        '<host><status state="up"/><address addr="1.2.3.4" addrtype="ipv4"/>'
        '<hostnames/>'
        '<ports><port protocol="tcp" portid="80"><state state="open"/>'
        '<service name="http"/></port></ports></host></nmaprun>'
    )
    out = parse_nmap_xml_to_jsonable(str(f), None, 'tid', 'toolid')
    assert isinstance(out, list)


def test_parse_httpx_output_to_jsonable_passes_through(tmp_path):
    from reverge_collector.tool_utils import parse_httpx_output_to_jsonable

    f = tmp_path / 'h.json'
    f.write_text(
        json.dumps(
            {
                'input': '1.2.3.4',
                'host_ip': '1.2.3.4',
                'port': '80',
                'url': 'http://1.2.3.4',
                'scheme': 'http',
            }
        )
        + '\n'
    )
    out = parse_httpx_output_to_jsonable(str(f), 'tid', 'toolid')
    assert isinstance(out, list)


def test_parse_nuclei_output_to_jsonable_passes_through(tmp_path):
    from reverge_collector.tool_utils import parse_nuclei_output_to_jsonable

    f = tmp_path / 'n.jsonl'
    f.write_text(
        json.dumps(
            {'template-id': 'x', 'url': 'http://1.1.1.1', 'info': {}}
        )
        + '\n'
    )
    out = parse_nuclei_output_to_jsonable(str(f), 'tid', 'toolid')
    assert isinstance(out, list)


def test_parse_shodan_output_to_jsonable_passes_through(tmp_path):
    from reverge_collector.tool_utils import parse_shodan_output_to_jsonable

    f = tmp_path / 's.json'
    f.write_text('')  # empty → empty list
    out = parse_shodan_output_to_jsonable(str(f), 'tid')
    assert out == []


def test_parse_feroxbuster_output_to_jsonable_passes_through(tmp_path):
    from reverge_collector.tool_utils import parse_feroxbuster_output_to_jsonable

    meta = tmp_path / 'f.meta'
    meta.write_text('')
    out = parse_feroxbuster_output_to_jsonable(str(meta), 'tid')
    assert out == []


def test_parse_subfinder_output_to_jsonable_passes_through(tmp_path):
    from reverge_collector.tool_utils import parse_subfinder_output_to_jsonable

    f = tmp_path / 's.json'
    f.write_text('')
    out = parse_subfinder_output_to_jsonable(str(f), 'tid')
    assert out == []


def test_parse_iis_short_scan_output_to_jsonable_passes_through(tmp_path):
    from reverge_collector.tool_utils import parse_iis_short_scan_output_to_jsonable

    f = tmp_path / 'i.json'
    f.write_text('')
    out = parse_iis_short_scan_output_to_jsonable(str(f), 'tid', 'toolid')
    assert out == []


def test_parse_ip_thc_output_to_jsonable_passes_through(tmp_path):
    from reverge_collector.tool_utils import parse_ip_thc_output_to_jsonable

    f = tmp_path / 'i.json'
    f.write_text('')
    out = parse_ip_thc_output_to_jsonable(str(f), 'tid')
    assert out == []


def test_parse_gau_output_to_jsonable_passes_through(tmp_path):
    from reverge_collector.tool_utils import parse_gau_output_to_jsonable

    f = tmp_path / 'g.meta'
    f.write_text('')
    out = parse_gau_output_to_jsonable(str(f), 'tid')
    assert out == []


def test_parse_crapsecrets_output_to_jsonable_passes_through(tmp_path):
    from reverge_collector.tool_utils import parse_crapsecrets_output_to_jsonable

    f = tmp_path / 'c.json'
    f.write_text('')
    out = parse_crapsecrets_output_to_jsonable(str(f), 'tid', 'toolid')
    assert out == []


def test_parse_webcap_output_to_jsonable_passes_through(tmp_path):
    from reverge_collector.tool_utils import parse_webcap_output_to_jsonable

    out = parse_webcap_output_to_jsonable(str(tmp_path / 'nope.json'), 'tid')
    assert out == []


def test_parse_netexec_output_to_jsonable_passes_through(tmp_path):
    from reverge_collector.tool_utils import parse_netexec_output_to_jsonable

    out = parse_netexec_output_to_jsonable(
        str(tmp_path / 'nope.json'), 'tid', 'toolid'
    )
    assert out == []


def test_parse_python_scan_output_to_jsonable_passes_through(tmp_path):
    from reverge_collector.tool_utils import parse_python_scan_output_to_jsonable

    f = tmp_path / 'p.json'
    f.write_text('')
    out = parse_python_scan_output_to_jsonable(str(f), 'tid', 'toolid')
    assert out == []


# ---------------------------------------------------------------------------
# Session key helpers
# ---------------------------------------------------------------------------


def test_load_session_key_returns_none_when_file_missing(monkeypatch, tmp_path):
    from reverge_collector import tool_utils

    monkeypatch.setattr(tool_utils, '_SESSION_FILE', str(tmp_path / 'nope'))
    assert tool_utils._load_session_key() is None


def test_load_session_key_decodes_hex_file(monkeypatch, tmp_path):
    from reverge_collector import tool_utils

    f = tmp_path / 'session'
    f.write_text('deadbeef' * 4)  # 32-byte hex
    monkeypatch.setattr(tool_utils, '_SESSION_FILE', str(f))
    out = tool_utils._load_session_key()
    assert out == bytes.fromhex('deadbeef' * 4)


def test_load_session_key_returns_none_on_invalid_hex(monkeypatch, tmp_path):
    from reverge_collector import tool_utils

    f = tmp_path / 'session'
    f.write_text('not hex at all')
    monkeypatch.setattr(tool_utils, '_SESSION_FILE', str(f))
    assert tool_utils._load_session_key() is None


def test_save_session_key_writes_hex_with_safe_perms(monkeypatch, tmp_path):
    import os as _os

    from reverge_collector import tool_utils

    f = tmp_path / 'session'
    monkeypatch.setattr(tool_utils, '_SESSION_FILE', str(f))
    tool_utils._save_session_key(b'\xde\xad\xbe\xef')

    assert f.exists()
    assert f.read_text() == 'deadbeef'
    # 0o600 perms
    mode = _os.stat(f).st_mode & 0o777
    assert mode == 0o600
