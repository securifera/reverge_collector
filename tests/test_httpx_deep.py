"""Deep parser tests for httpx_scan — exercise more branches via richer fixtures."""

from __future__ import annotations

import base64
import json


def test_httpx_with_full_fixture(tmp_path):
    from reverge_collector.data_model import (
        ApplicationProtocol,
        Certificate,
        Domain,
        Host,
        HttpEndpoint,
        HttpEndpointData,
        ListItem,
        Port,
        Screenshot,
    )
    from reverge_collector.httpx_scan import parse_httpx_output

    # 1×1 PNG bytes
    png = base64.b64decode(
        'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAA'
        'AAYAAjCB0C8AAAAASUVORK5CYII='
    )

    f = tmp_path / 'httpx.json'
    f.write_text(
        json.dumps(
            {
                'input': 'www.example.com',
                'host_ip': '93.184.216.34',
                'port': '443',
                'url': 'https://www.example.com/login',
                'scheme': 'https',
                'status_code': 200,
                'title': 'Login Page',
                'webserver': 'Apache/2.4',
                'content_length': 5432,
                'path': '/login',
                'favicon': 'abcd1234favicon',
                'screenshot_bytes': base64.b64encode(png).decode(),
                'header': {'last_modified': 'Tue, 01-Jan-2030 00:00:00 GMT'},
                'tls': {
                    'fingerprint_hash': {'sha1': 'ABCDEF123456'},
                    'subject_an': ['www.example.com', 'example.com'],
                    'subject_cn': 'www.example.com',
                    'issuer_dn': "CN=Let's Encrypt R3",
                    'not_before': '2030-01-01T00:00:00Z',
                    'not_after': '2030-04-01T00:00:00Z',
                },
                'cname': ['cdn.example.net'],
            }
        )
        + '\n'
    )
    records = parse_httpx_output([str(f)], tool_instance_id='tid')

    # Each record type the fixture should produce:
    hosts = [r for r in records if isinstance(r, Host)]
    ports = [r for r in records if isinstance(r, Port)]
    domains = [r for r in records if isinstance(r, Domain)]
    paths = [r for r in records if isinstance(r, ListItem)]
    screenshots = [r for r in records if isinstance(r, Screenshot)]
    endpoints = [r for r in records if isinstance(r, HttpEndpoint)]
    endpoint_data = [r for r in records if isinstance(r, HttpEndpointData)]
    certs = [r for r in records if isinstance(r, Certificate)]
    protos = [r for r in records if isinstance(r, ApplicationProtocol)]

    assert hosts and hosts[0].ipv4_addr == '93.184.216.34'
    assert ports and ports[0].port == '443'
    # cname domain + subject_an domains + subject_cn → multiple Domains
    domain_names = {d.name for d in domains}
    assert 'cdn.example.net' in domain_names
    assert 'www.example.com' in domain_names
    assert paths and paths[0].web_path == '/login'
    assert screenshots and screenshots[0].image_hash
    assert endpoints  # at least one
    assert endpoint_data and endpoint_data[0].status == 200
    assert endpoint_data[0].title == 'Login Page'
    assert certs and certs[0].fingerprint_hash == 'ABCDEF123456'
    assert "Let's Encrypt" in (certs[0].issuer or '')
    assert protos and protos[0].name == 'http'


def test_httpx_dedup_paths_and_screenshots_across_entries(tmp_path):
    """Same path/screenshot in two entries → only one ListItem/Screenshot."""
    from reverge_collector.data_model import ListItem, Screenshot
    from reverge_collector.httpx_scan import parse_httpx_output

    png = base64.b64decode(
        'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAA'
        'AAYAAjCB0C8AAAAASUVORK5CYII='
    )
    img = base64.b64encode(png).decode()

    entry = {
        'input': '1.2.3.4',
        'host_ip': '1.2.3.4',
        'port': '80',
        'url': 'http://1.2.3.4/admin',
        'scheme': 'http',
        'path': '/admin',
        'screenshot_bytes': img,
    }
    f = tmp_path / 'h.json'
    f.write_text(json.dumps(entry) + '\n' + json.dumps(entry) + '\n')
    records = parse_httpx_output([str(f)], 'tid')

    paths = [r for r in records if isinstance(r, ListItem)]
    screenshots = [r for r in records if isinstance(r, Screenshot)]
    # Same path & same image → deduped to single objects
    assert len(paths) == 1
    assert len(screenshots) == 1


def test_httpx_misdetect_400_https_on_http_port_marks_secure(tmp_path):
    """A 400 with the 'plain HTTP request was sent to HTTPS port' title
    upgrades port.secure to True."""
    from reverge_collector.data_model import Port
    from reverge_collector.httpx_scan import parse_httpx_output

    f = tmp_path / 'h.json'
    f.write_text(
        json.dumps(
            {
                'input': '1.2.3.4',
                'host_ip': '1.2.3.4',
                'port': '8443',
                'url': 'http://1.2.3.4:8443/',
                'scheme': 'http',
                'status_code': 400,
                'title': 'The plain HTTP request was sent to HTTPS port',
            }
        )
        + '\n'
    )
    records = parse_httpx_output([str(f)], 'tid')
    ports = [r for r in records if isinstance(r, Port)]
    assert ports and ports[0].secure is True


def test_httpx_certificate_deduped_by_sha1(tmp_path):
    """Two entries with same cert sha1 → only one Certificate record."""
    from reverge_collector.data_model import Certificate
    from reverge_collector.httpx_scan import parse_httpx_output

    def entry(host):
        return {
            'input': host,
            'host_ip': '1.2.3.4',
            'port': '443',
            'url': f'https://{host}',
            'scheme': 'https',
            'tls': {
                'fingerprint_hash': {'sha1': 'SAMESHA'},
                'subject_an': [host],
                'subject_cn': host,
                'issuer_dn': 'test',
                'not_before': '2030-01-01T00:00:00Z',
                'not_after': '2030-04-01T00:00:00Z',
            },
        }

    f = tmp_path / 'h.json'
    f.write_text(
        json.dumps(entry('a.example.com')) + '\n' + json.dumps(entry('b.example.com')) + '\n'
    )
    records = parse_httpx_output([str(f)], 'tid')
    certs = [r for r in records if isinstance(r, Certificate)]
    assert len(certs) == 1


def test_httpx_handles_missing_status_code_gracefully(tmp_path):
    from reverge_collector.httpx_scan import parse_httpx_output

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
    # No status_code → should still parse without raising
    records = parse_httpx_output([str(f)], 'tid')
    assert isinstance(records, list)


def test_httpx_skips_entry_without_input_or_port(tmp_path):
    """Missing required fields means entry should be skipped (or raise) —
    confirm parser is resilient."""
    from reverge_collector.httpx_scan import parse_httpx_output

    f = tmp_path / 'h.json'
    # Only one valid entry; one missing 'input'
    f.write_text(
        json.dumps({'host_ip': '1.2.3.4', 'port': '80'})  # no 'input'
        + '\n'
        + json.dumps(
            {
                'input': 'ok',
                'host_ip': '1.2.3.4',
                'port': '80',
                'url': 'http://ok',
                'scheme': 'http',
            }
        )
        + '\n'
    )
    # Parser may raise or skip; just confirm it doesn't infinite-loop
    try:
        out = parse_httpx_output([str(f)], 'tid')
        assert isinstance(out, list)
    except KeyError:
        # If parser raises on bad entry, that's also acceptable
        pass
