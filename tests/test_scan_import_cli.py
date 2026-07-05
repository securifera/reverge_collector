"""Tests for reverge_collector.scan_import_cli.

The CLI turns a flat findings document into the ``{scan_id, tool_id, obj_list}``
envelope that the reverge server's ``import_scan_data`` tool consumes. It builds
records with the native ``data_model`` serializers, so a round-trip through
``data_model.Record.static_from_jsonsable`` proves the output is well-formed.
"""

from __future__ import annotations

import io
import json

import pytest
from reverge_collector import data_model
from reverge_collector.scan_import_cli import (
    build_envelope_from_argv,
    build_envelope_from_doc,
    main,
)


def _by_type(env):
    out = {}
    for rec in env['obj_list']:
        out.setdefault(rec['type'], []).append(rec)
    return out


def _doc():
    return {
        'scan_id': 'abc123',
        'records': [
            {'type': 'host', 'ref': 'h1', 'ipv4_addr': '10.0.0.1'},
            {'type': 'domain', 'parent': 'h1', 'name': 'api.example.com'},
            {
                'type': 'port',
                'ref': 'p1',
                'parent': 'h1',
                'port': 443,
                'proto': 'tcp',
                'secure': True,
            },
            {
                'type': 'cpe',
                'parent': 'p1',
                'product': 'tomcat',
                'vendor': 'apache',
                'version': '9.0',
            },
            {'type': 'vuln', 'parent': 'p1', 'name': 'CVE-2024-1234', 'vuln_details': 'RCE'},
        ],
    }


def test_envelope_shape_and_ref_linking():
    env = build_envelope_from_doc(_doc())
    assert env['scan_id'] == 'abc123'
    assert env['tool_id']

    by_type = {}
    for rec in env['obj_list']:
        by_type.setdefault(rec['type'], []).append(rec)

    host = by_type['host'][0]
    port = by_type['port'][0]
    assert port['parent'] == {'type': 'host', 'id': host['id']}
    assert by_type['domain'][0]['parent']['id'] == host['id']
    assert by_type['cpe'][0]['parent']['id'] == port['id']
    assert by_type['vuln'][0]['parent']['id'] == port['id']
    assert port['data']['proto'] == 0  # tcp -> 0


def test_proto_udp():
    env = build_envelope_from_doc(
        {
            'scan_id': 'x',
            'records': [
                {'type': 'host', 'ref': 'h', 'ipv4_addr': '10.0.0.2'},
                {'type': 'port', 'parent': 'h', 'port': 53, 'proto': 'udp'},
            ],
        }
    )
    port = next(r for r in env['obj_list'] if r['type'] == 'port')
    assert port['data']['proto'] == 1


def test_http_endpoint_web_path_autocreates_listitem():
    env = build_envelope_from_doc(
        {
            'scan_id': 'x',
            'records': [
                {'type': 'host', 'ref': 'h', 'ipv4_addr': '10.0.0.3'},
                {'type': 'port', 'ref': 'p', 'parent': 'h', 'port': 443, 'secure': True},
                {'type': 'httpendpoint', 'parent': 'p', 'web_path': '/admin'},
            ],
        }
    )
    listitem = next(r for r in env['obj_list'] if r['type'] == 'listitem')
    endpoint = next(r for r in env['obj_list'] if r['type'] == 'httpendpoint')
    assert listitem['data']['path'] == '/admin'
    assert endpoint['data']['web_path_id'] == listitem['id']


def test_unknown_type_and_parent_raise():
    with pytest.raises(Exception):
        build_envelope_from_doc({'scan_id': 'x', 'records': [{'type': 'wombat'}]})
    with pytest.raises(Exception):
        build_envelope_from_doc(
            {'scan_id': 'x', 'records': [{'type': 'port', 'parent': 'nope', 'port': 80}]}
        )


def test_output_roundtrips_through_data_model():
    env = build_envelope_from_doc(_doc())
    for rec in env['obj_list']:
        obj = data_model.Record.static_from_jsonsable(rec)
        assert obj is not None


def test_main_reads_stdin_writes_stdout(monkeypatch, capsys):
    monkeypatch.setattr('sys.stdin', io.StringIO(json.dumps(_doc())))
    rc = main([])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out['scan_id'] == 'abc123'
    assert any(r['type'] == 'vuln' for r in out['obj_list'])


# ---------------------------------------------------------------------------
# Flag-based (argv) mode
# ---------------------------------------------------------------------------


def test_argv_full_example_graph():
    """python scan_import_cli --host <ip> --port 80 --component Apache
    --version 1.0 --url https://www.example.com — the documented example."""
    env = build_envelope_from_argv(
        [
            '--scan-id',
            'abc123',
            '--host',
            '1.2.3.4',
            '--port',
            '80',
            '--component',
            'Apache',
            '--version',
            '1.0',
            '--url',
            'https://www.example.com',
        ]
    )
    by_type = _by_type(env)

    host = by_type['host'][0]
    assert host['data']['ipv4_addr'] == '1.2.3.4'
    assert host['parent'] is None

    port = by_type['port'][0]
    assert port['data']['port'] == '80'
    assert port['parent'] == {'type': 'host', 'id': host['id']}

    cpe = by_type['cpe'][0]
    assert cpe['data']['product'] == 'Apache'
    assert cpe['data']['version'] == '1.0'
    assert cpe['parent'] == {'type': 'port', 'id': port['id']}

    domain = by_type['domain'][0]
    assert domain['data']['name'] == 'www.example.com'
    assert domain['parent'] == {'type': 'host', 'id': host['id']}

    listitem = by_type['listitem'][0]
    assert listitem['data']['path'] == '/'
    endpoint = by_type['httpendpoint'][0]
    assert endpoint['parent'] == {'type': 'port', 'id': port['id']}
    assert endpoint['data']['web_path_id'] == listitem['id']


def test_argv_output_roundtrips():
    env = build_envelope_from_argv(
        ['--scan-id', 'x', '--host', '10.0.0.1', '--port', '443', '--secure', '--vuln', 'CVE-1']
    )
    for rec in env['obj_list']:
        assert data_model.Record.static_from_jsonsable(rec) is not None
    port = _by_type(env)['port'][0]
    assert port['data']['secure'] is True


def test_argv_url_without_port_derives_port_and_domain():
    env = build_envelope_from_argv(
        ['--scan-id', 'x', '--host', '10.0.0.1', '--url', 'https://api.example.com/admin']
    )
    by_type = _by_type(env)
    port = by_type['port'][0]
    assert port['data']['port'] == '443'
    assert port['data']['secure'] is True
    assert by_type['domain'][0]['data']['name'] == 'api.example.com'
    assert by_type['listitem'][0]['data']['path'] == '/admin'


def test_argv_proto_udp_and_os():
    env = build_envelope_from_argv(
        [
            '--scan-id',
            'x',
            '--host',
            '10.0.0.1',
            '--port',
            '53',
            '--proto',
            'udp',
            '--os',
            'Linux',
            '--os-version',
            '6.1',
        ]
    )
    by_type = _by_type(env)
    assert by_type['port'][0]['data']['proto'] == 1
    os_rec = by_type['operatingsystem'][0]
    assert os_rec['data'] == {'name': 'Linux', 'version': '6.1'}
    assert os_rec['parent']['id'] == by_type['host'][0]['id']


def test_argv_endpoint_data_fields():
    env = build_envelope_from_argv(
        [
            '--scan-id',
            'x',
            '--host',
            '10.0.0.1',
            '--port',
            '443',
            '--secure',
            '--path',
            '/login',
            '--title',
            'Login',
            '--status',
            '200',
        ]
    )
    by_type = _by_type(env)
    data = by_type['httpendpointdata'][0]
    assert data['data']['title'] == 'Login'
    assert data['data']['status'] == 200
    assert data['parent']['id'] == by_type['httpendpoint'][0]['id']


def test_argv_port_requires_host():
    with pytest.raises(SystemExit):
        build_envelope_from_argv(['--scan-id', 'x', '--port', '80'])


def test_argv_component_requires_port():
    with pytest.raises(SystemExit):
        build_envelope_from_argv(['--scan-id', 'x', '--host', '10.0.0.1', '--component', 'nginx'])


def test_argv_multiple_domains():
    env = build_envelope_from_argv(
        [
            '--scan-id',
            'x',
            '--host',
            '10.0.0.1',
            '--domain',
            'a.example.com',
            '--domain',
            'b.example.com',
        ]
    )
    names = {d['data']['name'] for d in _by_type(env)['domain']}
    assert names == {'a.example.com', 'b.example.com'}


def test_main_argv_writes_stdout(capsys):
    rc = main(['--scan-id', 'zz', '--host', '10.0.0.7', '--port', '22'])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out['scan_id'] == 'zz'
    assert any(r['type'] == 'port' for r in out['obj_list'])
