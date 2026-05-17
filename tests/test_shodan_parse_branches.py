"""Deep-branch tests for shodan_lookup.parse_shodan_output.

Targets the SSL cert + HTTP component + favicon + location branches that
the basic shodan tests don't reach (lines 567-669 in shodan_lookup.py).
"""

from __future__ import annotations

import json


def _write_payload(tmp_path, services):
    """Write a {'data': [...]} shodan output file and return its path."""
    p = tmp_path / 'shodan_out.json'
    p.write_text(json.dumps({'data': services}))
    return str(p)


def test_parse_ssl_cert_with_full_chain(tmp_path):
    """Cert with issued/expires/fingerprint/subject CN → Certificate +
    Domain records."""
    from reverge_collector.shodan_lookup import parse_shodan_output

    payload = [{
        'ip': 167772161,  # 10.0.0.1
        'port': 443,
        'ssl': {
            'cert': {
                'issued': '20230101000000Z',
                'expires': '20240101000000Z',
                'fingerprint': {'sha1': 'aa11bb22'},
                'subject': {'CN': 'example.com'},
            }
        },
        'http': {
            'status': 200,
            'title': 'Welcome',
        },
        'hostnames': ['example.com'],
    }]
    f = _write_payload(tmp_path, payload)
    records = parse_shodan_output(f, tool_instance_id='tid')

    type_names = [type(r).__name__ for r in records]
    assert 'Certificate' in type_names
    assert 'Domain' in type_names
    cert = next(r for r in records if type(r).__name__ == 'Certificate')
    assert cert.fingerprint_hash == 'aa11bb22'
    assert cert.issued is not None
    assert cert.expires is not None


def test_parse_http_components_with_versions(tmp_path):
    """http.components dict → one Cpe per component with version[0]."""
    from reverge_collector.shodan_lookup import parse_shodan_output

    payload = [{
        'ip': 167772162,
        'port': 80,
        'http': {
            'status': 200,
            'components': {
                'jQuery': {'versions': ['3.6.0', '3.5.0']},
                'Bootstrap': {'versions': ['5.0.0']},
                'NoVersion': {},
            },
        },
    }]
    records = parse_shodan_output(_write_payload(tmp_path, payload),
                                  tool_instance_id='tid')
    cpes = [r for r in records if type(r).__name__ == 'Cpe']
    names = {c.product: c.version for c in cpes}
    assert names.get('jquery') == '3.6.0'
    assert names.get('bootstrap') == '5.0.0'
    # Component without versions still emits a Cpe (no version set)
    assert 'noversion' in names


def test_parse_server_header_with_slash_split(tmp_path):
    """http.server "nginx/1.20.1 ..." → Cpe with product=nginx version=1.20.1."""
    from reverge_collector.shodan_lookup import parse_shodan_output

    payload = [{
        'ip': 167772163,
        'port': 80,
        'http': {'server': 'nginx/1.20.1 (Ubuntu)'},
    }]
    records = parse_shodan_output(_write_payload(tmp_path, payload),
                                  tool_instance_id='tid')
    cpes = [r for r in records if type(r).__name__ == 'Cpe']
    assert len(cpes) == 1
    assert cpes[0].product == 'nginx'
    assert cpes[0].version == '1.20.1'


def test_parse_server_header_with_no_slash_no_version(tmp_path):
    """A plain server string with no slash → no Cpe (parser only emits
    Cpe when slash present)."""
    from reverge_collector.shodan_lookup import parse_shodan_output

    payload = [{
        'ip': 167772164,
        'port': 80,
        'http': {'server': 'cloudflare'},
    }]
    records = parse_shodan_output(_write_payload(tmp_path, payload),
                                  tool_instance_id='tid')
    cpes = [r for r in records if type(r).__name__ == 'Cpe']
    assert len(cpes) == 0


def test_parse_favicon_and_location(tmp_path):
    """http.favicon.hash + http.location='/' → HttpEndpointData carries
    fav_icon_hash; non-/ location creates a ListItem."""
    from reverge_collector.shodan_lookup import parse_shodan_output

    payload = [{
        'ip': 167772165,
        'port': 80,
        'http': {
            'favicon': {'hash': 'fav123'},
            'location': '/admin',
        },
    }]
    records = parse_shodan_output(_write_payload(tmp_path, payload),
                                  tool_instance_id='tid')
    # ListItem created for /admin path
    list_items = [r for r in records if type(r).__name__ == 'ListItem']
    assert any('/admin' in (r.web_path or '') for r in list_items)
    # HttpEndpoint references that path
    endpoints = [r for r in records if type(r).__name__ == 'HttpEndpoint']
    assert endpoints
    assert endpoints[0].web_path_id == list_items[0].id


def test_parse_favicon_with_root_location_attaches_to_endpoint_data(tmp_path):
    """When location='/' the favicon hash is attached to the endpoint data."""
    from reverge_collector.shodan_lookup import parse_shodan_output

    payload = [{
        'ip': 167772166,
        'port': 80,
        'http': {
            'favicon': {'hash': 'fav-root'},
            'location': '/',
        },
    }]
    records = parse_shodan_output(_write_payload(tmp_path, payload),
                                  tool_instance_id='tid')
    epds = [r for r in records if type(r).__name__ == 'HttpEndpointData']
    assert epds and epds[0].fav_icon_hash == 'fav-root'


def test_parse_http_with_ssl_cert_cn_to_domain(tmp_path):
    """Inside the http branch, an SSL cert with CN becomes a Domain via
    cert_obj.add_domain (separate from the outer ssl-without-http path)."""
    from reverge_collector.shodan_lookup import parse_shodan_output

    payload = [{
        'ip': 167772167,
        'port': 443,
        'ssl': {
            'cert': {
                'subject': {'CN': 'inside-http.example.com'},
            }
        },
        'http': {'status': 200},
        # Don't put a wildcard or IP — those would be filtered by add_domain
    }]
    records = parse_shodan_output(_write_payload(tmp_path, payload),
                                  tool_instance_id='tid')
    domains = [r for r in records if type(r).__name__ == 'Domain']
    names = [d.name for d in domains]
    # Outer SSL branch emits one (top-level), inner http+ssl emits one via
    # cert.add_domain — Domain dedup via add_domain returns None on dup.
    assert 'inside-http.example.com' in names


def test_parse_path_dedup_same_location_only_one_listitem(tmp_path):
    """Two services pointing to the same location should share a single
    ListItem (path_hash_map dedup)."""
    from reverge_collector.shodan_lookup import parse_shodan_output

    payload = [
        {
            'ip': 167772168,
            'port': 80,
            'http': {'location': '/api/v1'},
        },
        {
            'ip': 167772169,
            'port': 80,
            'http': {'location': '/api/v1'},
        },
    ]
    records = parse_shodan_output(_write_payload(tmp_path, payload),
                                  tool_instance_id='tid')
    list_items = [r for r in records if type(r).__name__ == 'ListItem']
    # Only one ListItem because same path_hash
    assert len(list_items) == 1
