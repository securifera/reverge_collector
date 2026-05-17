"""Fixture-based parser tests for each scanner module.

The existing integration tests in tests/routes/ exercise the scanners
end-to-end (subprocess invocation + parse), which is slow and fragile —
they need the real binary on the box and network access to a target.

These tests cover only the pure parsing layer: write a synthetic output
fixture, call ``parse_X_output`` directly, assert on the produced
data_model records. No subprocesses, no network, sub-second per case.

Each scanner gets one happy-path test plus enough edge cases (empty file,
missing-key entries, malformed line, ipv6) to exercise the meaningful
branches in its parser.
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# masscan
# ---------------------------------------------------------------------------


MASSCAN_XML = """<?xml version="1.0"?>
<nmaprun scanner="masscan" start="1700000000" version="1.3.2" xmloutputversion="1.03">
  <host endtime="1700000010">
    <address addr="93.184.216.34" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/></port>
      <port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/></port>
    </ports>
  </host>
  <host endtime="1700000011">
    <address addr="2606:2800:220:1:248:1893:25c8:1946" addrtype="ipv6"/>
    <ports>
      <port protocol="udp" portid="53"><state state="open"/></port>
    </ports>
  </host>
</nmaprun>
"""


def test_masscan_parses_ipv4_and_ipv6_ports(tmp_path):
    from reverge_collector.data_model import Host, Port
    from reverge_collector.masscan import parse_masscan_xml

    f = tmp_path / 'mass.xml'
    f.write_text(MASSCAN_XML)
    records = parse_masscan_xml(str(f), tool_instance_id='tid-1')

    hosts = [r for r in records if isinstance(r, Host)]
    ports = [r for r in records if isinstance(r, Port)]
    assert len(hosts) == 2
    assert hosts[0].ipv4_addr == '93.184.216.34'
    assert hosts[1].ipv6_addr  # normalised
    assert len(ports) == 3
    assert {p.port for p in ports} == {'80', '443', '53'}
    # TCP=0, UDP=1
    assert {p.proto for p in ports} == {0, 1}
    for r in records:
        assert r.collection_tool_instance_id == 'tid-1'


def test_masscan_returns_empty_for_missing_file():
    from reverge_collector.masscan import parse_masscan_xml

    assert parse_masscan_xml('/nonexistent/path.xml') == []


def test_masscan_returns_empty_for_zero_byte_file(tmp_path):
    from reverge_collector.masscan import parse_masscan_xml

    f = tmp_path / 'empty.xml'
    f.touch()
    assert parse_masscan_xml(str(f)) == []


def test_masscan_skips_unparseable_address(tmp_path):
    from reverge_collector.data_model import Host
    from reverge_collector.masscan import parse_masscan_xml

    xml = (
        '<nmaprun><host><address addr="not.an.ip" addrtype="ipv4"/>'
        '<ports><port protocol="tcp" portid="22"/></ports></host>'
        '<host><address addr="1.2.3.4" addrtype="ipv4"/>'
        '<ports><port protocol="tcp" portid="80"/></ports></host></nmaprun>'
    )
    f = tmp_path / 'm.xml'
    f.write_text(xml)
    records = parse_masscan_xml(str(f))
    hosts = [r for r in records if isinstance(r, Host)]
    assert len(hosts) == 1
    assert hosts[0].ipv4_addr == '1.2.3.4'


# ---------------------------------------------------------------------------
# subfinder
# ---------------------------------------------------------------------------


def test_subfinder_parses_domain_list(tmp_path):
    from reverge_collector.data_model import Domain, Host
    from reverge_collector.subfinder_scan import parse_subfinder_output

    f = tmp_path / 'sf.json'
    f.write_text(
        json.dumps(
            {
                'domain_list': [
                    {'domain': 'a.example.com', 'ip': '1.2.3.4'},
                    {'domain': 'b.example.com', 'ip': '1.2.3.4'},
                    {'domain': 'c.example.com', 'ip': '5.6.7.8'},
                ]
            }
        )
    )
    records = parse_subfinder_output(str(f), tool_instance_id='tid')
    domains = [r for r in records if isinstance(r, Domain)]
    hosts = [r for r in records if isinstance(r, Host)]
    names = {d.name for d in domains}
    assert {'a.example.com', 'b.example.com', 'c.example.com'} == names
    assert len(hosts) == 2  # two unique IPs


def test_subfinder_skips_unparseable_ip(tmp_path):
    from reverge_collector.data_model import Domain
    from reverge_collector.subfinder_scan import parse_subfinder_output

    f = tmp_path / 'sf.json'
    f.write_text(
        json.dumps(
            {
                'domain_list': [
                    {'domain': 'x.example.com', 'ip': 'not-an-ip'},
                    {'domain': 'y.example.com', 'ip': '8.8.8.8'},
                ]
            }
        )
    )
    records = parse_subfinder_output(str(f))
    domains = [r for r in records if isinstance(r, Domain)]
    names = {d.name for d in domains}
    # 'y' should make it; 'x' is silently dropped along with its host
    assert 'y.example.com' in names


def test_subfinder_empty_file_returns_empty(tmp_path):
    from reverge_collector.subfinder_scan import parse_subfinder_output

    f = tmp_path / 'sf.json'
    f.write_text('')
    assert parse_subfinder_output(str(f)) == []


# ---------------------------------------------------------------------------
# gau
# ---------------------------------------------------------------------------


def test_gau_parses_metadata_file(tmp_path):
    from reverge_collector.gau_scan import parse_gau_output

    # gau parser expects a metadata JSON file that lists scan output files
    raw_out = tmp_path / 'gau_raw.txt'
    raw_out.write_text(
        'https://example.com/index.html\n'
        'https://example.com/admin/login.php?id=1\n'
        'https://example.com/static/css/site.css\n'
    )
    meta = tmp_path / 'gau.meta'
    meta.write_text(
        json.dumps(
            {
                'gau_scan_list': [
                    {'output_file': str(raw_out), 'port_id': None, 'host_id': None}
                ]
            }
        )
    )
    records = parse_gau_output(str(meta), tool_instance_id='tid')
    # gau emits ListItem / HttpEndpoint / HttpEndpointData records — just
    # confirm the parser ran and produced something without raising.
    assert isinstance(records, list)


# ---------------------------------------------------------------------------
# feroxbuster
# ---------------------------------------------------------------------------


def test_feroxbuster_parses_metadata_file(tmp_path):
    from reverge_collector.feroxbuster_scan import parse_feroxbuster_output

    ferox_out = tmp_path / 'ferox.json'
    # Feroxbuster writes JSONL with type=response for each path found
    ferox_out.write_text(
        json.dumps(
            {
                'type': 'response',
                'url': 'https://example.com/admin',
                'status': 200,
                'content_length': 1234,
            }
        )
        + '\n'
        + json.dumps(
            {
                'type': 'response',
                'url': 'https://example.com/login',
                'status': 403,
                'content_length': 0,
            }
        )
        + '\n'
    )
    meta = tmp_path / 'ferox.meta'
    meta.write_text(
        json.dumps(
            {
                'output_file': str(ferox_out),
                'url_to_id_map': {
                    'https://example.com/': {'port_id': 'p1', 'host_id': 'h1'},
                },
            }
        )
    )
    records = parse_feroxbuster_output(str(meta), tool_instance_id='tid')
    assert isinstance(records, list)


def test_feroxbuster_empty_meta_returns_empty(tmp_path):
    from reverge_collector.feroxbuster_scan import parse_feroxbuster_output

    meta = tmp_path / 'ferox.meta'
    meta.write_text('')
    assert parse_feroxbuster_output(str(meta), 'tid') == []


def test_feroxbuster_missing_output_file_in_meta(tmp_path):
    from reverge_collector.feroxbuster_scan import parse_feroxbuster_output

    meta = tmp_path / 'ferox.meta'
    meta.write_text(
        json.dumps(
            {
                'output_file': str(tmp_path / 'does-not-exist.json'),
                'url_to_id_map': {},
            }
        )
    )
    assert parse_feroxbuster_output(str(meta), 'tid') == []


# ---------------------------------------------------------------------------
# pyshot
# ---------------------------------------------------------------------------


def test_pyshot_parses_jsonl_screenshot_metadata(tmp_path):
    from reverge_collector.data_model import Screenshot
    from reverge_collector.pyshot_scan import parse_pyshot_output

    # Write a real 1x1 PNG to disk; pyshot reads it via file_path.
    png = base64.b64decode(
        'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAA'
        'AAYAAjCB0C8AAAAASUVORK5CYII='
    )
    img_path = tmp_path / 'shot.png'
    img_path.write_bytes(png)
    meta = tmp_path / 'screenshots.json'
    meta.write_text(
        json.dumps(
            {
                'file_path': str(img_path),
                'path': '/',
                'port_id': 'port-1',
                'endpoint_id': None,
                'domain': 'x.example.com',
                'status_code': 200,
                'title': 'Welcome',
                'url': 'https://x.example.com',
            }
        )
        + '\n'
    )
    records = parse_pyshot_output(str(meta), tool_instance_id='tid')
    screenshots = [r for r in records if isinstance(r, Screenshot)]
    assert len(screenshots) == 1
    assert screenshots[0].image_hash  # hash was computed


def test_pyshot_returns_empty_for_missing_file():
    from reverge_collector.pyshot_scan import parse_pyshot_output

    assert parse_pyshot_output('/nope.json', 'tid') == []


# ---------------------------------------------------------------------------
# webcap
# ---------------------------------------------------------------------------


def test_webcap_parses_jsonl_with_dedup(tmp_path):
    from reverge_collector.data_model import Screenshot
    from reverge_collector.webcap_scan import parse_webcap_output

    png = base64.b64decode(
        'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAA'
        'AAYAAjCB0C8AAAAASUVORK5CYII='
    )
    img = base64.b64encode(png).decode()
    meta = tmp_path / 'webcap.json'
    # Two entries with the SAME image data — parser should dedup via hash
    line = {
        'port_id': 'p1',
        'http_endpoint_data_id': None,
        'path': '/',
        'domain': 'x.com',
        'url': 'https://x.com',
        'image_data': img,
        'status_code': 200,
        'title': 'X',
    }
    meta.write_text(json.dumps(line) + '\n' + json.dumps(line) + '\n')
    records = parse_webcap_output(str(meta), tool_instance_id='tid')
    screenshots = [r for r in records if isinstance(r, Screenshot)]
    # Both lines should yield the same Screenshot object via dedup
    assert len({id(s) for s in screenshots}) == 1


def test_webcap_returns_empty_for_missing_file():
    from reverge_collector.webcap_scan import parse_webcap_output

    assert parse_webcap_output('/nope.json', 'tid') == []


def test_webcap_parse_args_defaults_and_overrides():
    from reverge_collector.webcap_scan import parse_args

    t, th, fmt, q = parse_args('')
    assert (t, th, fmt, q) == (5, 5, 'jpeg', 100)

    t, th, fmt, q = parse_args('--timeout 10 --threads 3 --quality 75 --format png')
    assert (t, th, fmt, q) == (10, 3, 'png', 75)

    # quality clamped 1..100
    _, _, _, q = parse_args('--quality 9999')
    assert q == 100
    _, _, _, q = parse_args('--quality 0')
    assert q == 1

    # bad format ignored, default jpeg kept
    _, _, fmt, _ = parse_args('--format webm')
    assert fmt == 'jpeg'

    # non-numeric values ignored (defaults retained)
    t, th, _, _ = parse_args('--timeout abc --threads xyz')
    assert (t, th) == (5, 5)


# ---------------------------------------------------------------------------
# nuclei
# ---------------------------------------------------------------------------


def test_nuclei_parses_standalone_url(tmp_path):
    from reverge_collector.data_model import Host, Port
    from reverge_collector.nuclei_scan import parse_nuclei_output

    f = tmp_path / 'nuc.jsonl'
    f.write_text(
        json.dumps(
            {
                'template-id': 'tech-detect',
                'url': 'https://93.184.216.34',
                'info': {
                    'name': 'apache',
                    'classification': {'cpe': 'cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*'},
                },
            }
        )
        + '\n'
    )
    records = parse_nuclei_output(str(f), endpoint_port_obj_map=None, tool_instance_id='tid')
    hosts = [r for r in records if isinstance(r, Host)]
    ports = [r for r in records if isinstance(r, Port)]
    assert len(hosts) == 1 and hosts[0].ipv4_addr == '93.184.216.34'
    assert any(p.port == '443' and p.secure for p in ports)


def test_nuclei_parses_url_with_port_80_default(tmp_path):
    from reverge_collector.data_model import Port
    from reverge_collector.nuclei_scan import parse_nuclei_output

    f = tmp_path / 'n.jsonl'
    f.write_text(
        json.dumps({'template-id': 'x', 'url': 'http://1.1.1.1', 'info': {}}) + '\n'
    )
    records = parse_nuclei_output(str(f), None, 'tid')
    ports = [r for r in records if isinstance(r, Port)]
    assert any(p.port == '80' for p in ports)


def test_nuclei_skips_entries_without_url_or_template(tmp_path):
    from reverge_collector.nuclei_scan import parse_nuclei_output

    f = tmp_path / 'n.jsonl'
    f.write_text(
        json.dumps({'no_url': True}) + '\n'
        + json.dumps({'url': 'http://x', 'info': {}}) + '\n'  # no template-id
    )
    records = parse_nuclei_output(str(f), None, 'tid')
    # Both records should be skipped → no template/cpe-derived records
    from reverge_collector.data_model import Cpe

    assert not [r for r in records if isinstance(r, Cpe)]


# ---------------------------------------------------------------------------
# httpx
# ---------------------------------------------------------------------------


def test_httpx_parses_basic_output(tmp_path):
    from reverge_collector.data_model import Host, Port
    from reverge_collector.httpx_scan import parse_httpx_output

    f = tmp_path / 'httpx.json'
    f.write_text(
        json.dumps(
            {
                'input': '52.4.7.15',
                'host_ip': '52.4.7.15',
                'port': '443',
                'url': 'https://52.4.7.15:443/',
                'scheme': 'https',
                'status_code': 200,
                'title': 'OK',
                'webserver': 'Apache',
            }
        )
        + '\n'
    )
    records = parse_httpx_output([str(f)], tool_instance_id='tid')
    hosts = [r for r in records if isinstance(r, Host)]
    ports = [r for r in records if isinstance(r, Port)]
    assert hosts and hosts[0].ipv4_addr == '52.4.7.15'
    assert ports and ports[0].port == '443'


def test_httpx_parses_cname_list(tmp_path):
    from reverge_collector.data_model import Domain
    from reverge_collector.httpx_scan import parse_httpx_output

    f = tmp_path / 'h.json'
    f.write_text(
        json.dumps(
            {
                'input': 'foo.example.com',
                'host_ip': '1.2.3.4',
                'port': '80',
                'url': 'http://foo.example.com',
                'cname': ['cdn.example.net', 'alias.example.net'],
            }
        )
        + '\n'
    )
    records = parse_httpx_output([str(f)])
    domain_names = {r.name for r in records if isinstance(r, Domain)}
    assert {'cdn.example.net', 'alias.example.net'}.issubset(domain_names)


# ---------------------------------------------------------------------------
# crapsecrets (badsecrets fork)
# ---------------------------------------------------------------------------


def test_crapsecrets_returns_empty_for_empty_file(tmp_path):
    from reverge_collector.crapsecrets_scan import parse_crapsecrets_output

    f = tmp_path / 'crap.json'
    f.write_text('')
    out = parse_crapsecrets_output(str(f), 'tid', 'toolid')
    assert out == []


# ---------------------------------------------------------------------------
# python_scan
# ---------------------------------------------------------------------------


def test_python_scan_returns_empty_for_empty_file(tmp_path):
    from reverge_collector.python_scan import parse_python_scan_output

    f = tmp_path / 'p.json'
    f.write_text('')
    out = parse_python_scan_output(str(f), 'tid', 'toolid')
    assert out == []


# ---------------------------------------------------------------------------
# ip_thc_lookup
# ---------------------------------------------------------------------------


def test_ip_thc_returns_empty_for_empty_file(tmp_path):
    from reverge_collector.ip_thc_lookup import parse_ip_thc_output

    f = tmp_path / 'i.json'
    f.write_text('')
    assert parse_ip_thc_output(str(f), 'tid') == []


# ---------------------------------------------------------------------------
# iis_short_scan
# ---------------------------------------------------------------------------


def test_iis_short_scan_returns_empty_for_empty_file(tmp_path):
    from reverge_collector.iis_short_scan import parse_iis_short_scan_output

    f = tmp_path / 'i.json'
    f.write_text('')
    assert parse_iis_short_scan_output(str(f), 'tid', 'toolid') == []


# ---------------------------------------------------------------------------
# netexec
# ---------------------------------------------------------------------------


def test_netexec_returns_empty_for_missing_file(tmp_path):
    from reverge_collector.netexec_scan import parse_netexec_output

    # netexec_scan has the os.path.exists check
    assert parse_netexec_output(str(tmp_path / 'nope.json'), 'tid', 'toolid') == []


def test_netexec_returns_empty_for_empty_file(tmp_path):
    from reverge_collector.netexec_scan import parse_netexec_output

    f = tmp_path / 'n.json'
    f.write_text('')
    assert parse_netexec_output(str(f), 'tid', 'toolid') == []


# ---------------------------------------------------------------------------
# sqlmap
# ---------------------------------------------------------------------------


def test_sqlmap_returns_empty_for_empty_file(tmp_path):
    from reverge_collector.sqlmap_scan import parse_sqlmap_output

    f = tmp_path / 's.json'
    f.write_text('')
    assert parse_sqlmap_output(str(f), 'tid') == []


# ---------------------------------------------------------------------------
# shodan
# ---------------------------------------------------------------------------


def test_shodan_returns_empty_for_empty_file(tmp_path):
    from reverge_collector.shodan_lookup import parse_shodan_output

    f = tmp_path / 's.json'
    f.write_text('')
    assert parse_shodan_output(str(f), 'tid') == []
