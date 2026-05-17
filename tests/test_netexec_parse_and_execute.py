"""Tests for netexec_scan.parse_netexec_output and execute_scan.

Walks the consolidation → record build pipeline without invoking the
netexec binary or touching the real ldap/smb services.
"""

from __future__ import annotations

import base64
import json
import os
import threading
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from reverge_collector import data_model
from reverge_collector.scan_utils import get_port_byte_array


def _scope(obj_list, port_list_str='445'):
    return {
        'b64_port_bitmap': base64.b64encode(get_port_byte_array(port_list_str)).decode(),
        'obj_list': obj_list,
    }


def make_scan(tmp_path, *, obj_list=None, args='', port_list_str='445'):
    if obj_list is None:
        obj_list = []
    scan_id = 'nxc-' + os.urandom(3).hex()
    scan_data = data_model.ScanData(_scope(obj_list, port_list_str))
    return SimpleNamespace(
        id=scan_id,
        scan_id=scan_id,
        target_id=1,
        scan_data=scan_data,
        current_tool=SimpleNamespace(id='tool-nxc', name='netexec', args=args),
        current_tool_instance_id='inst-' + os.urandom(3).hex(),
        collection_tool_map={},
        selected_interface=None,
        register_tool_executor=MagicMock(),
        tool_executor_map={},
        tool_executor_lock=threading.Lock(),
    )


# ===========================================================================
# parse_netexec_output
# ===========================================================================


def test_parse_returns_empty_when_meta_missing(tmp_path):
    from reverge_collector.netexec_scan import parse_netexec_output

    assert parse_netexec_output(str(tmp_path / 'nope'), 'ti', 'td') == []


def test_parse_returns_empty_when_meta_empty(tmp_path):
    from reverge_collector.netexec_scan import parse_netexec_output

    p = tmp_path / 'meta.json'
    p.write_text('')
    assert parse_netexec_output(str(p), 'ti', 'td') == []


def test_parse_skips_missing_or_empty_output_files(tmp_path):
    from reverge_collector.netexec_scan import parse_netexec_output

    meta = tmp_path / 'meta.json'
    meta.write_text(
        json.dumps(
            {
                'netexec_scan_list': [
                    # Output file doesn't exist
                    {'output_file': str(tmp_path / 'missing'), 'protocol': 'smb'},
                    # Output file is empty
                    {'output_file': str(tmp_path / 'empty'), 'protocol': 'smb'},
                ]
            }
        )
    )
    (tmp_path / 'empty').write_text('')
    assert parse_netexec_output(str(meta), 'ti', 'td') == []


def test_parse_skips_invalid_json_lines(tmp_path):
    from reverge_collector.netexec_scan import parse_netexec_output

    out = tmp_path / 'out.jsonl'
    out.write_text(
        '{not-json\n'
        + json.dumps({'host': '10.0.0.1', 'port': 445, 'hostname': 'srv1', 'message': 'ok'})
        + '\n'
    )
    meta = tmp_path / 'meta.json'
    meta.write_text(
        json.dumps(
            {
                'netexec_scan_list': [
                    {'output_file': str(out), 'protocol': 'smb'},
                ]
            }
        )
    )
    records = parse_netexec_output(str(meta), 'ti', 'td')
    # At least the valid line builds Host/Port/Module
    type_names = {type(r).__name__ for r in records}
    assert 'Host' in type_names
    assert 'Port' in type_names


def test_parse_skips_lines_missing_required_fields(tmp_path):
    from reverge_collector.netexec_scan import parse_netexec_output

    out = tmp_path / 'out.jsonl'
    out.write_text(
        json.dumps({'host': '10.0.0.1', 'port': 445})
        + '\n'  # missing hostname
        + json.dumps({'host': '10.0.0.2', 'port': 445, 'hostname': 'h2'})
        + '\n'
    )
    meta = tmp_path / 'meta.json'
    meta.write_text(
        json.dumps(
            {
                'netexec_scan_list': [
                    {'output_file': str(out), 'protocol': 'smb'},
                ]
            }
        )
    )
    records = parse_netexec_output(str(meta), 'ti', 'td')
    hosts = [r for r in records if type(r).__name__ == 'Host']
    assert len(hosts) == 1
    assert hosts[0].ipv4_addr == '10.0.0.2'


def test_parse_extracts_fqdn_from_info_message(tmp_path):
    """INFO-level message with (name:X) (domain:Y) → emits FQDN Domain."""
    from reverge_collector.netexec_scan import parse_netexec_output

    out = tmp_path / 'out.jsonl'
    out.write_text(
        json.dumps(
            {
                'host': '10.0.0.10',
                'port': 445,
                'hostname': 'srv',
                'message': '(name:WIN-FOO) (domain:CONTOSO)',
                'level': 'INFO',
                'type': '',
            }
        )
        + '\n'
    )
    meta = tmp_path / 'meta.json'
    meta.write_text(
        json.dumps({'netexec_scan_list': [{'output_file': str(out), 'protocol': 'smb'}]})
    )
    records = parse_netexec_output(str(meta), 'ti', 'td')
    domain_names = [r.name for r in records if type(r).__name__ == 'Domain']
    assert 'WIN-FOO.CONTOSO' in domain_names


def test_parse_extracts_credential_from_success_message(tmp_path):
    """success-type "DOMAIN\\user:pass" → Credential record."""
    from reverge_collector.netexec_scan import parse_netexec_output

    out = tmp_path / 'out.jsonl'
    out.write_text(
        json.dumps(
            {
                'host': '10.0.0.20',
                'port': 445,
                'hostname': 'srv',
                'message': 'CONTOSO\\admin:p@ss (Pwn3d!)',
                'level': 'SUCCESS',
                'type': 'success',
            }
        )
        + '\n'
    )
    meta = tmp_path / 'meta.json'
    meta.write_text(
        json.dumps({'netexec_scan_list': [{'output_file': str(out), 'protocol': 'smb'}]})
    )
    records = parse_netexec_output(str(meta), 'ti', 'td')
    creds = [r for r in records if type(r).__name__ == 'Credential']
    assert len(creds) == 1
    assert creds[0].username == 'admin'
    assert creds[0].password == 'p@ss'


def test_parse_handles_credential_parse_failure(tmp_path):
    """Malformed cred message doesn't crash the parse loop."""
    from reverge_collector.netexec_scan import parse_netexec_output

    out = tmp_path / 'out.jsonl'
    out.write_text(
        json.dumps(
            {
                'host': '10.0.0.30',
                'port': 445,
                'hostname': 'srv',
                'message': r'malformed\garbage no colon here',
                'level': 'SUCCESS',
                'type': 'success',
            }
        )
        + '\n'
    )
    meta = tmp_path / 'meta.json'
    meta.write_text(
        json.dumps({'netexec_scan_list': [{'output_file': str(out), 'protocol': 'smb'}]})
    )
    records = parse_netexec_output(str(meta), 'ti', 'td')
    # Parsed line still produces Host/Port/Module even though cred parse failed
    types = {type(r).__name__ for r in records}
    assert 'Host' in types


def test_parse_emits_operating_system_record(tmp_path):
    """server_os field → OperatingSystem record with version split."""
    from reverge_collector.netexec_scan import parse_netexec_output

    out = tmp_path / 'out.jsonl'
    out.write_text(
        json.dumps(
            {
                'host': '10.0.0.40',
                'port': 445,
                'hostname': 'srv',
                'message': 'banner',
                'server_os': 'Windows 10',
            }
        )
        + '\n'
    )
    meta = tmp_path / 'meta.json'
    meta.write_text(
        json.dumps({'netexec_scan_list': [{'output_file': str(out), 'protocol': 'smb'}]})
    )
    records = parse_netexec_output(str(meta), 'ti', 'td')
    os_recs = [r for r in records if type(r).__name__ == 'OperatingSystem']
    assert len(os_recs) == 1
    assert os_recs[0].name == 'Windows'
    assert os_recs[0].version == '10'


def test_parse_emits_module_when_module_name_present(tmp_path):
    """module_name in the line → CollectionModule named by module_name
    (lowercased)."""
    from reverge_collector.netexec_scan import parse_netexec_output

    out = tmp_path / 'out.jsonl'
    out.write_text(
        json.dumps(
            {
                'host': '10.0.0.50',
                'port': 445,
                'hostname': 'srv',
                'message': 'finding',
                'module_name': 'ENUM_AV',
            }
        )
        + '\n'
    )
    meta = tmp_path / 'meta.json'
    meta.write_text(
        json.dumps({'netexec_scan_list': [{'output_file': str(out), 'protocol': 'smb'}]})
    )
    records = parse_netexec_output(str(meta), 'ti', 'td')
    modules = [r for r in records if type(r).__name__ == 'CollectionModule']
    assert modules
    assert modules[0].name == 'enum_av'


# ===========================================================================
# execute_scan
# ===========================================================================


def test_execute_scan_skips_when_output_exists(tmp_path, monkeypatch):
    from reverge_collector.netexec_scan import execute_scan, get_output_path

    monkeypatch.chdir(tmp_path)
    scan = make_scan(tmp_path, obj_list=[])
    out = get_output_path(scan)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, 'w') as f:
        f.write('{}')
    with patch('reverge_collector.scan_utils.executor.submit') as m:
        execute_scan(scan)
        m.assert_not_called()


def test_execute_scan_no_valid_ports_writes_empty_list(tmp_path, monkeypatch):
    from reverge_collector.netexec_scan import execute_scan, get_output_path

    monkeypatch.chdir(tmp_path)
    # Use port not in netexec_protocol_map (e.g. 9999)
    scan = make_scan(tmp_path, obj_list=[], port_list_str='9999')
    execute_scan(scan)
    out = get_output_path(scan)
    assert os.path.exists(out)
    body = json.loads(open(out).read())
    assert body == {'netexec_scan_list': []}


def test_execute_scan_with_host_port_submits(tmp_path, monkeypatch):
    from reverge_collector.netexec_scan import execute_scan, get_output_path

    monkeypatch.chdir(tmp_path)
    obj_list = [
        {
            'type': 'host',
            'id': 'h1',
            'data': {'ipv4_addr': '10.0.0.5'},
            'tags': [data_model.RecordTag.SCOPE.value],
        },
        {
            'type': 'port',
            'id': 'p1',
            'parent': {'type': 'host', 'id': 'h1'},
            'data': {'port': '445', 'proto': 0, 'secure': False},
            'tags': [data_model.RecordTag.SCOPE.value],
        },
    ]
    scan = make_scan(tmp_path, obj_list=obj_list)
    fut = MagicMock()
    fut.result.return_value = {'exit_code': 0, 'stdout': '', 'stderr': ''}
    with patch('reverge_collector.scan_utils.executor.submit', return_value=fut) as sub:
        execute_scan(scan)
    assert sub.called
    out = get_output_path(scan)
    body = json.loads(open(out).read())
    assert len(body['netexec_scan_list']) == 1
    assert body['netexec_scan_list'][0]['protocol'] == 'smb'


def test_execute_scan_subnet_only_path(tmp_path, monkeypatch):
    from reverge_collector.netexec_scan import execute_scan, get_output_path

    monkeypatch.chdir(tmp_path)
    obj_list = [
        {
            'type': 'subnet',
            'id': 's1',
            'data': {'subnet': '10.0.0.0', 'mask': 30},
            'tags': [data_model.RecordTag.SCOPE.value],
        },
    ]
    scan = make_scan(tmp_path, obj_list=obj_list, port_list_str='445')
    fut = MagicMock()
    fut.result.return_value = {'exit_code': 0, 'stdout': '', 'stderr': ''}
    with patch('reverge_collector.scan_utils.executor.submit', return_value=fut) as sub:
        execute_scan(scan)
    assert sub.called


def test_execute_scan_failure_raises(tmp_path, monkeypatch):
    from reverge_collector.netexec_scan import execute_scan

    monkeypatch.chdir(tmp_path)
    obj_list = [
        {
            'type': 'host',
            'id': 'h1',
            'data': {'ipv4_addr': '10.0.0.5'},
            'tags': [data_model.RecordTag.SCOPE.value],
        },
        {
            'type': 'port',
            'id': 'p1',
            'parent': {'type': 'host', 'id': 'h1'},
            'data': {'port': '445', 'proto': 0, 'secure': False},
            'tags': [data_model.RecordTag.SCOPE.value],
        },
    ]
    scan = make_scan(tmp_path, obj_list=obj_list)
    bad = MagicMock()
    bad.result.return_value = {'exit_code': 2, 'stdout': '', 'stderr': 'bad creds'}
    with (
        patch('reverge_collector.scan_utils.executor.submit', return_value=bad),
        pytest.raises(RuntimeError, match='exited with code 2'),
    ):
        execute_scan(scan)
