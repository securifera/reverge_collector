"""Parser tests for Shodan fields not previously surfaced.

Covers four enrichments added on top of the existing parser:
- Top-level ``cpe23`` array → ``Cpe`` records carrying vendor + version
- ``_shodan.module`` → ``ApplicationProtocol`` record per port
- ``http.waf`` → ``Cpe`` record for the detected WAF
- Top-level ``os`` → ``OperatingSystem`` record on the host
"""

from __future__ import annotations

import json


def _write_payload(tmp_path, services):
    p = tmp_path / 'shodan_out.json'
    p.write_text(json.dumps({'data': services}))
    return str(p)


def test_top_level_cpe23_creates_cpes_with_vendor(tmp_path):
    """``cpe23`` strings parse into Cpe records with vendor/product/version."""
    from reverge_collector.shodan_lookup import parse_shodan_output

    payload = [
        {
            'ip': 167772161,
            'port': 443,
            'cpe23': [
                'cpe:2.3:a:wordpress:wordpress:6.9.4',
                'cpe:2.3:a:apache:http_server',
            ],
            'http': {},
        }
    ]
    records = parse_shodan_output(_write_payload(tmp_path, payload), tool_instance_id='tid')

    cpes_by_product = {r.product: r for r in records if type(r).__name__ == 'Cpe'}
    assert 'wordpress' in cpes_by_product
    assert cpes_by_product['wordpress'].vendor == 'wordpress'
    assert cpes_by_product['wordpress'].version == '6.9.4'
    assert 'http_server' in cpes_by_product
    assert cpes_by_product['http_server'].vendor == 'apache'


def test_shodan_module_creates_application_protocol(tmp_path):
    """``_shodan.module`` becomes an ApplicationProtocol on the port."""
    from reverge_collector.shodan_lookup import parse_shodan_output

    payload = [
        {
            'ip': 167772161,
            'port': 22,
            '_shodan': {'module': 'ssh'},
        }
    ]
    records = parse_shodan_output(_write_payload(tmp_path, payload), tool_instance_id='tid')

    protos = [r for r in records if type(r).__name__ == 'ApplicationProtocol']
    assert len(protos) == 1
    assert protos[0].name == 'ssh'


def test_https_module_normalizes_to_http(tmp_path):
    """A Shodan 'https' module is the same http protocol on a secure port —
    record it as 'http' so it matches httpx's ApplicationProtocol naming."""
    from reverge_collector.shodan_lookup import parse_shodan_output

    payload = [
        {
            'ip': 167772161,
            'port': 443,
            '_shodan': {'module': 'https'},
            'http': {},
        }
    ]
    records = parse_shodan_output(_write_payload(tmp_path, payload), tool_instance_id='tid')

    protos = [r for r in records if type(r).__name__ == 'ApplicationProtocol']
    assert len(protos) == 1
    assert protos[0].name == 'http'


def test_http_waf_creates_cpe(tmp_path):
    """``http.waf`` (e.g. 'Cloudflare') becomes a Cpe on the port."""
    from reverge_collector.shodan_lookup import parse_shodan_output

    payload = [
        {
            'ip': 167772161,
            'port': 443,
            'http': {'waf': 'Cloudflare'},
        }
    ]
    records = parse_shodan_output(_write_payload(tmp_path, payload), tool_instance_id='tid')

    waf_cpes = [r for r in records if type(r).__name__ == 'Cpe' and r.product == 'cloudflare']
    assert len(waf_cpes) == 1


def test_top_level_os_creates_operating_system(tmp_path):
    """Non-null ``os`` field becomes an OperatingSystem record on the host."""
    from reverge_collector.shodan_lookup import parse_shodan_output

    payload = [
        {
            'ip': 167772161,
            'port': 80,
            'os': 'Linux 5.10',
        }
    ]
    records = parse_shodan_output(_write_payload(tmp_path, payload), tool_instance_id='tid')

    os_recs = [r for r in records if type(r).__name__ == 'OperatingSystem']
    assert len(os_recs) == 1
    assert os_recs[0].name == 'Linux 5.10'


def test_null_os_field_is_ignored(tmp_path):
    """``os: null`` (common in Shodan data) must not emit an empty OS record."""
    from reverge_collector.shodan_lookup import parse_shodan_output

    payload = [{'ip': 167772161, 'port': 80, 'os': None}]
    records = parse_shodan_output(_write_payload(tmp_path, payload), tool_instance_id='tid')

    assert not [r for r in records if type(r).__name__ == 'OperatingSystem']
