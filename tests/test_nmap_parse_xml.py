"""Tests for nmap_scan.parse_nmap_xml using mocked NmapParser objects.

The XML parser itself is a third-party dep (python-libnmap). We mock its
output structure to walk each conditional in parse_nmap_xml without
needing a real nmap run or carefully-crafted XML on disk.
"""

from __future__ import annotations

import base64
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from reverge_collector import data_model
from reverge_collector.scan_utils import get_port_byte_array


def _fake_svc(name='http', product='', version='', scripts=None):
    """Build the libnmap-shaped service object the parser walks."""
    svc = SimpleNamespace()
    svc.service_dict = {'name': name, 'product': product, 'version': version}
    svc.scripts_results = scripts or []
    return svc


def _fake_host(ip='10.0.0.1', open_ports=None, hostnames=None, services=None):
    """A libnmap-shaped host object."""
    h = MagicMock()
    h.id = ip
    h.hostnames = hostnames or []
    h.get_open_ports.return_value = open_ports or []
    services_by_id = services or {}
    h.get_service_byid = lambda key: services_by_id.get(key)
    return h


def _fake_report(hosts):
    return SimpleNamespace(hosts=hosts)


def test_parse_returns_empty_when_no_hosts(tmp_path):
    from reverge_collector.nmap_scan import parse_nmap_xml

    with patch(
        'reverge_collector.nmap_scan.NmapParser.parse_fromfile',
        return_value=_fake_report([]),
    ):
        assert parse_nmap_xml('/x') == []


def test_parse_builds_host_port_records(tmp_path):
    from reverge_collector.nmap_scan import parse_nmap_xml

    host = _fake_host(
        ip='10.0.0.1',
        open_ports=[(80, 'tcp')],
        services={'tcp.80': _fake_svc(name='http')},
    )
    with patch(
        'reverge_collector.nmap_scan.NmapParser.parse_fromfile',
        return_value=_fake_report([host]),
    ):
        records = parse_nmap_xml('/x')
    types = [type(r).__name__ for r in records]
    assert 'Host' in types
    assert 'Port' in types
    assert 'ApplicationProtocol' in types


def test_parse_emits_domains_from_hostnames(tmp_path):
    from reverge_collector.nmap_scan import parse_nmap_xml

    host = _fake_host(
        ip='10.0.0.2',
        open_ports=[(80, 'tcp')],
        hostnames=['web.example.com', {'name': 'alias.example.com'}],
        services={'tcp.80': _fake_svc(name='http')},
    )
    with patch(
        'reverge_collector.nmap_scan.NmapParser.parse_fromfile',
        return_value=_fake_report([host]),
    ):
        records = parse_nmap_xml('/x')
    domain_names = {r.name for r in records if type(r).__name__ == 'Domain'}
    assert 'web.example.com' in domain_names
    assert 'alias.example.com' in domain_names


def test_parse_continues_when_service_missing(tmp_path):
    """get_service_byid returns None → no ApplicationProtocol but Host/Port
    still emitted."""
    from reverge_collector.nmap_scan import parse_nmap_xml

    host = _fake_host(
        ip='10.0.0.3',
        open_ports=[(22, 'tcp')],
        services={},  # no match
    )
    with patch(
        'reverge_collector.nmap_scan.NmapParser.parse_fromfile',
        return_value=_fake_report([host]),
    ):
        records = parse_nmap_xml('/x')
    types = {type(r).__name__ for r in records}
    assert {'Host', 'Port'}.issubset(types)
    assert 'ApplicationProtocol' not in types


def test_parse_skips_unknown_service_name(tmp_path):
    from reverge_collector.nmap_scan import parse_nmap_xml

    host = _fake_host(
        ip='10.0.0.4',
        open_ports=[(8080, 'tcp')],
        services={'tcp.8080': _fake_svc(name='unknown')},
    )
    with patch(
        'reverge_collector.nmap_scan.NmapParser.parse_fromfile',
        return_value=_fake_report([host]),
    ):
        records = parse_nmap_xml('/x')
    assert not any(type(r).__name__ == 'ApplicationProtocol' for r in records)


def test_parse_product_creates_cpe(tmp_path):
    from reverge_collector.nmap_scan import parse_nmap_xml

    host = _fake_host(
        ip='10.0.0.5',
        open_ports=[(80, 'tcp')],
        services={'tcp.80': _fake_svc(name='http', product='Apache httpd', version='2.4.52')},
    )
    with patch(
        'reverge_collector.nmap_scan.NmapParser.parse_fromfile',
        return_value=_fake_report([host]),
    ):
        records = parse_nmap_xml('/x')
    cpes = [r for r in records if type(r).__name__ == 'Cpe']
    assert cpes
    assert cpes[0].product == 'apache'
    assert cpes[0].version == '2.4.52'


def test_parse_ssl_cert_script_emits_certificate(tmp_path):
    from reverge_collector.nmap_scan import parse_nmap_xml

    ssl_script = {
        'id': 'ssl-cert',
        'output': 'cert info',
        'elements': {
            'sha1': 'aa11bb22',
            'validity': {
                'notBefore': '2023-01-01T00:00:00',
                'notAfter': '2024-01-01T00:00:00',
            },
            'subject': {'commonName': 'example.com'},
            'issuer': {'organizationName': 'DigiCert'},
            'extensions': {
                'null': [
                    {
                        'name': 'X509v3 Subject Alternative Name',
                        'value': 'DNS:alt.example.com',
                    }
                ]
            },
        },
    }
    host = _fake_host(
        ip='10.0.0.6',
        open_ports=[(443, 'tcp')],
        services={'tcp.443': _fake_svc(name='https', scripts=[ssl_script])},
    )
    with patch(
        'reverge_collector.nmap_scan.NmapParser.parse_fromfile',
        return_value=_fake_report([host]),
    ):
        records = parse_nmap_xml('/x')
    types = [type(r).__name__ for r in records]
    assert 'Certificate' in types
    cert = next(r for r in records if type(r).__name__ == 'Certificate')
    assert cert.fingerprint_hash == 'aa11bb22'
    assert cert.issued is not None
    assert cert.expires is not None
    # Port flipped to secure
    port = next(r for r in records if type(r).__name__ == 'Port')
    assert port.secure is True
    # Both CN and SAN domains emitted
    domain_names = {r.name for r in records if type(r).__name__ == 'Domain'}
    assert 'example.com' in domain_names
    assert 'alt.example.com' in domain_names


def test_parse_ssl_cert_with_invalid_dates_swallowed(tmp_path):
    from reverge_collector.nmap_scan import parse_nmap_xml

    ssl_script = {
        'id': 'ssl-cert',
        'output': 'x',
        'elements': {
            'validity': {
                'notBefore': 'not-a-date',
                'notAfter': 'not-a-date',
            },
        },
    }
    host = _fake_host(
        ip='10.0.0.7',
        open_ports=[(443, 'tcp')],
        services={'tcp.443': _fake_svc(name='https', scripts=[ssl_script])},
    )
    with patch(
        'reverge_collector.nmap_scan.NmapParser.parse_fromfile',
        return_value=_fake_report([host]),
    ):
        records = parse_nmap_xml('/x')
    # Certificate emitted but dates stay None
    cert = next(r for r in records if type(r).__name__ == 'Certificate')
    assert cert.issued is None
    assert cert.expires is None


def test_parse_http_script_emits_application_protocol(tmp_path):
    from reverge_collector.nmap_scan import parse_nmap_xml

    http_script = {'id': 'http-title', 'output': '<title>Welcome</title>'}
    host = _fake_host(
        ip='10.0.0.8',
        open_ports=[(80, 'tcp')],
        services={'tcp.80': _fake_svc(name='http', scripts=[http_script])},
    )
    with patch(
        'reverge_collector.nmap_scan.NmapParser.parse_fromfile',
        return_value=_fake_report([host]),
    ):
        records = parse_nmap_xml('/x')
    proto_names = [r.name for r in records if type(r).__name__ == 'ApplicationProtocol']
    # Both the service name + the http-script branch emit one each
    assert proto_names.count('http') >= 1
    # The http-title script also drives a CollectionModule + Output
    types = [type(r).__name__ for r in records]
    assert 'CollectionModule' in types
    assert 'CollectionModuleOutput' in types


def test_parse_script_without_id_or_output_skipped(tmp_path):
    from reverge_collector.nmap_scan import parse_nmap_xml

    script_no_id = {'output': 'x'}
    script_no_output = {'id': 'foo'}
    script_empty_output = {'id': 'bar', 'output': ''}
    host = _fake_host(
        ip='10.0.0.9',
        open_ports=[(80, 'tcp')],
        services={
            'tcp.80': _fake_svc(
                name='http',
                scripts=[script_no_id, script_no_output, script_empty_output],
            )
        },
    )
    with patch(
        'reverge_collector.nmap_scan.NmapParser.parse_fromfile',
        return_value=_fake_report([host]),
    ):
        records = parse_nmap_xml('/x')
    modules = [r for r in records if type(r).__name__ == 'CollectionModule']
    assert not modules


def test_parse_reuses_scope_host_id_when_match(tmp_path):
    """When the parsed IP:port is already in the scope, the existing host
    and port ids are reused."""
    from reverge_collector.data_model import ScanData
    from reverge_collector.nmap_scan import parse_nmap_xml

    scope_dict = {
        'b64_port_bitmap': base64.b64encode(get_port_byte_array('80')).decode(),
        'obj_list': [
            {
                'type': 'host',
                'id': 'scope-h',
                'data': {'ipv4_addr': '10.0.0.99'},
                'tags': [data_model.RecordTag.SCOPE.value],
            },
            {
                'type': 'port',
                'id': 'scope-p',
                'parent': {'type': 'host', 'id': 'scope-h'},
                'data': {'port': '80', 'proto': 0, 'secure': False},
                'tags': [data_model.RecordTag.SCOPE.value],
            },
        ],
    }
    scope = ScanData(scope_dict)
    host = _fake_host(
        ip='10.0.0.99',
        open_ports=[(80, 'tcp')],
        services={'tcp.80': _fake_svc(name='http')},
    )
    with patch(
        'reverge_collector.nmap_scan.NmapParser.parse_fromfile',
        return_value=_fake_report([host]),
    ):
        records = parse_nmap_xml('/x', scope_obj=scope)
    h = next(r for r in records if type(r).__name__ == 'Host')
    assert h.id == 'scope-h'
    p = next(r for r in records if type(r).__name__ == 'Port')
    assert p.id == 'scope-p'
