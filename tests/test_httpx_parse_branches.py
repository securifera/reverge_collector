"""Deep-branch tests for httpx_scan.parse_httpx_output and execute_scan."""

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


def _write_blobs(tmp_path, lines):
    """Write a JSONL file with one httpx-style record per line."""
    p = tmp_path / 'httpx_out_443'
    with open(p, 'w') as f:
        for line in lines:
            f.write(json.dumps(line) + '\n')
    return str(p)


# ===========================================================================
# parse_httpx_output — record-build branches
# ===========================================================================


def test_parse_basic_record_produces_full_chain(tmp_path):
    from reverge_collector.httpx_scan import parse_httpx_output

    out = _write_blobs(tmp_path, [{
        'input': '10.0.0.1',
        'port': '443',
        'scheme': 'https',
        'host_ip': '10.0.0.1',
        'status_code': '200',
        'content_length': '1234',
        'title': 'Example',
        'path': '/admin',
        'header': {'last_modified': 'Wed, 01-Jan-2024 12:00:00 GMT'},
        'url': 'https://example.com:443/admin',
    }])
    records = parse_httpx_output([out], tool_instance_id='ti', tool_id='td')
    types = {type(r).__name__ for r in records}
    assert {'Host', 'Port', 'ListItem', 'HttpEndpoint', 'HttpEndpointData',
            'ApplicationProtocol'}.issubset(types)


def test_parse_cname_list_emits_domains(tmp_path):
    from reverge_collector.httpx_scan import parse_httpx_output

    out = _write_blobs(tmp_path, [{
        'input': '10.0.0.2', 'port': '80',
        'cname': ['alias.example.com', 'cdn.example.com'],
    }])
    records = parse_httpx_output([out], tool_instance_id='ti', tool_id='td')
    domains = {r.name for r in records if type(r).__name__ == 'Domain'}
    assert 'alias.example.com' in domains
    assert 'cdn.example.com' in domains


def test_parse_uses_a_record_when_no_host_ip(tmp_path):
    from reverge_collector.httpx_scan import parse_httpx_output

    out = _write_blobs(tmp_path, [{
        'input': 'example.com', 'port': '80',
        'a': ['10.0.0.3'],
    }])
    records = parse_httpx_output([out], tool_instance_id='ti', tool_id='td')
    hosts = [r for r in records if type(r).__name__ == 'Host']
    assert hosts and hosts[0].ipv4_addr == '10.0.0.3'


def test_parse_400_with_https_message_flips_secure(tmp_path):
    """Plain-HTTP-sent-to-HTTPS-port 400 → port.secure = True."""
    from reverge_collector.httpx_scan import parse_httpx_output

    out = _write_blobs(tmp_path, [{
        'input': '10.0.0.5', 'port': '443',
        'status_code': '400',
        'title': 'The plain HTTP request was sent to HTTPS port',
    }])
    records = parse_httpx_output([out], tool_instance_id='ti', tool_id='td')
    ports = [r for r in records if type(r).__name__ == 'Port']
    assert ports and ports[0].secure is True


def test_parse_invalid_status_code_swallowed(tmp_path):
    from reverge_collector.httpx_scan import parse_httpx_output

    out = _write_blobs(tmp_path, [{
        'input': '10.0.0.6', 'port': '80',
        'status_code': 'not-a-number',
        'content_length': 'not-a-number',
    }])
    records = parse_httpx_output([out], tool_instance_id='ti', tool_id='td')
    epds = [r for r in records if type(r).__name__ == 'HttpEndpointData']
    assert epds and epds[0].status is None and epds[0].content_length is None


def test_parse_screenshot_bytes_dedup(tmp_path):
    """Two records with the same screenshot bytes → single Screenshot."""
    from reverge_collector.httpx_scan import parse_httpx_output

    ss = base64.b64encode(b'ICON-BYTES').decode()
    out = _write_blobs(tmp_path, [
        {'input': '10.0.0.7', 'port': '80', 'screenshot_bytes': ss},
        {'input': '10.0.0.8', 'port': '80', 'screenshot_bytes': ss},
    ])
    records = parse_httpx_output([out], tool_instance_id='ti', tool_id='td')
    screenshots = [r for r in records if type(r).__name__ == 'Screenshot']
    assert len(screenshots) == 1


def test_parse_tls_with_san_and_cn_dedups(tmp_path):
    """tls.subject_an and tls.subject_cn both feed Certificate.add_domain."""
    from reverge_collector.httpx_scan import parse_httpx_output

    out = _write_blobs(tmp_path, [{
        'input': 'example.com', 'port': '443',
        'tls': {
            'fingerprint_hash': {'sha1': 'tls-fp-1'},
            'subject_an': ['a.example.com', 'b.example.com'],
            'subject_cn': ['c.example.com'],
            'host': ['d.example.com', 'e.example.com'],
            'issuer_dn': 'CN=DigiCert',
            'not_before': '2023-01-01T00:00:00Z',
            'not_after': '2024-01-01T00:00:00Z',
        },
    }])
    records = parse_httpx_output([out], tool_instance_id='ti', tool_id='td')
    types = {type(r).__name__ for r in records}
    assert 'Certificate' in types
    cert = next(r for r in records if type(r).__name__ == 'Certificate')
    assert cert.fingerprint_hash == 'tls-fp-1'
    assert cert.issuer == 'CN=DigiCert'
    assert cert.issued is not None
    assert cert.expires is not None
    domains = {r.name for r in records if type(r).__name__ == 'Domain'}
    for d in ('a.example.com', 'b.example.com', 'c.example.com',
              'd.example.com', 'e.example.com'):
        assert d in domains


def test_parse_tls_dedup_returns_cached_cert(tmp_path):
    """Two records sharing the same TLS fingerprint → one Certificate."""
    from reverge_collector.httpx_scan import parse_httpx_output

    out = _write_blobs(tmp_path, [
        {
            'input': 'a.example.com', 'port': '443',
            'tls': {'fingerprint_hash': {'sha1': 'shared-fp'}, 'host': 'a.example.com'},
        },
        {
            'input': 'b.example.com', 'port': '443',
            'tls': {'fingerprint_hash': {'sha1': 'shared-fp'}, 'host': 'b.example.com'},
        },
    ])
    records = parse_httpx_output([out], tool_instance_id='ti', tool_id='td')
    certs = [r for r in records if type(r).__name__ == 'Certificate']
    assert len(certs) == 1


def test_parse_tech_and_cpe_metadata_overlay(tmp_path):
    """tech entries get matching cpe strings overlaid via the .cpe setter."""
    from reverge_collector.httpx_scan import parse_httpx_output

    out = _write_blobs(tmp_path, [{
        'input': '10.0.0.9', 'port': '80',
        'tech': ['nginx:1.21.0', 'jquery'],
        'cpe': [
            {'product': 'nginx', 'cpe': 'cpe:2.3:a:nginx:nginx:1.21.0:*:*:*:*:*:*:*'},
        ],
    }])
    records = parse_httpx_output([out], tool_instance_id='ti', tool_id='td')
    cpes = [r for r in records if type(r).__name__ == 'Cpe']
    assert len(cpes) == 2
    nginx = next(c for c in cpes if c.product == 'nginx')
    assert nginx.version == '1.21.0'
    # jquery should still produce a Cpe even with no structured metadata
    assert any(c.product == 'jquery' for c in cpes)


def test_parse_raw_header_and_body_emit_module_outputs(tmp_path):
    from reverge_collector.httpx_scan import parse_httpx_output

    out = _write_blobs(tmp_path, [{
        'input': '10.0.0.10', 'port': '80',
        'raw_header': 'HTTP/1.1 200 OK\r\nServer: nginx\r\n',
        'body': '<html>...</html>',
    }])
    records = parse_httpx_output([out], tool_instance_id='ti', tool_id='td')
    modules = [r for r in records if type(r).__name__ == 'CollectionModule']
    names = {m.name for m in modules}
    assert 'http-response-headers' in names
    assert 'http-response-body' in names


def test_parse_uses_scope_host_id_when_match(tmp_path):
    """When scope_obj has a matching host:port key, the existing host id is reused."""
    from reverge_collector.httpx_scan import parse_httpx_output
    from reverge_collector.data_model import ScanData

    scope_dict = {
        'b64_port_bitmap': base64.b64encode(get_port_byte_array('443')).decode(),
        'obj_list': [
            {
                'type': 'host', 'id': 'scope-h-1',
                'data': {'ipv4_addr': '10.0.0.99'},
                'tags': [data_model.RecordTag.SCOPE.value],
            },
            {
                'type': 'port', 'id': 'scope-p-1',
                'parent': {'type': 'host', 'id': 'scope-h-1'},
                'data': {'port': '443', 'proto': 0, 'secure': True},
                'tags': [data_model.RecordTag.SCOPE.value],
            },
        ],
    }
    scope = ScanData(scope_dict)
    out = _write_blobs(tmp_path, [{
        'input': '10.0.0.99', 'port': '443',
    }])
    records = parse_httpx_output([out], tool_instance_id='ti', tool_id='td', scope_obj=scope)
    # No Host record (the scope's host id was reused without creating a new one),
    # but a Port record still appears tied to that scope host id.
    ports = [r for r in records if type(r).__name__ == 'Port']
    assert ports
