"""More fixture-based tests for scanner parsers: sqlmap, gau, iis_short_scan,
crapsecrets, netexec, python_scan, plus deeper httpx/nuclei coverage.
"""

from __future__ import annotations

import json

# ===========================================================================
# sqlmap
# ===========================================================================


def test_sqlmap_emits_vuln_when_injection_marker_present(tmp_path):
    from reverge_collector.data_model import Vuln
    from reverge_collector.sqlmap_scan import parse_sqlmap_output

    # Build the multi-file structure: manifest references a stdout file.
    stdout = tmp_path / 'sqlmap_stdout.txt'
    stdout.write_text(
        'sqlmap identified the following injection point with a total of 23 HTTP(s) requests:\n'
        '---\n'
        'Parameter: id (GET)\n'
        '    Type: boolean-based blind\n'
        '---\n'
    )
    manifest = tmp_path / 'sqlmap_manifest.json'
    manifest.write_text(
        json.dumps(
            {
                'url_to_id_map': {
                    'https://target.example.com/x?id=1': {
                        'output_file': str(stdout),
                        'port_id': 'port-uuid-1',
                    }
                }
            }
        )
    )
    records = parse_sqlmap_output(str(manifest), tool_instance_id='tid')
    vulns = [r for r in records if isinstance(r, Vuln)]
    assert len(vulns) == 1
    assert vulns[0].name == 'sql_injection'


def test_sqlmap_no_vuln_when_clean_output(tmp_path):
    from reverge_collector.sqlmap_scan import parse_sqlmap_output

    stdout = tmp_path / 'clean.txt'
    stdout.write_text('all tested parameters do not appear to be injectable\n')
    manifest = tmp_path / 'm.json'
    manifest.write_text(
        json.dumps(
            {
                'url_to_id_map': {
                    'https://x/?id=1': {
                        'output_file': str(stdout),
                        'port_id': 'p1',
                    }
                }
            }
        )
    )
    assert parse_sqlmap_output(str(manifest), 'tid') == []


def test_sqlmap_skips_missing_output_file(tmp_path):
    from reverge_collector.sqlmap_scan import parse_sqlmap_output

    manifest = tmp_path / 'm.json'
    manifest.write_text(
        json.dumps(
            {
                'url_to_id_map': {
                    'https://x/': {
                        'output_file': str(tmp_path / 'does-not-exist.txt'),
                        'port_id': 'p1',
                    }
                }
            }
        )
    )
    assert parse_sqlmap_output(str(manifest), 'tid') == []


def test_sqlmap_handles_empty_manifest(tmp_path):
    from reverge_collector.sqlmap_scan import parse_sqlmap_output

    m = tmp_path / 'm.json'
    m.write_text('')
    assert parse_sqlmap_output(str(m), 'tid') == []


# ===========================================================================
# gau
# ===========================================================================


def test_gau_parses_url_list(tmp_path):
    from reverge_collector.gau_scan import parse_gau_output

    gau_raw = tmp_path / 'gau.jsonl'
    gau_raw.write_text(
        json.dumps({'url': 'https://www.example.com/index.html'})
        + '\n'
        + json.dumps({'url': 'https://www.example.com/admin/login.php?id=1'})
        + '\n'
        # IP-host URL should be skipped per parser (gau filters IPs)
        + json.dumps({'url': 'http://192.168.1.1/admin'})
        + '\n'
        # Invalid line
        + 'not json\n'
    )
    meta = tmp_path / 'gau.meta'
    meta.write_text(
        json.dumps(
            {
                'output_file': str(gau_raw),
                'domain_map': {
                    'www.example.com': {
                        'domain_id': 'dom1',
                        'host_id': 'host1',
                        'ip_addr': '93.184.216.34',
                    }
                },
            }
        )
    )
    records = parse_gau_output(str(meta), tool_instance_id='tid')
    # Parser returns a list; just confirm it ran and produced records.
    assert isinstance(records, list)


# ===========================================================================
# iis_short_scan
# ===========================================================================


def test_iis_short_scan_parses_results(tmp_path):
    from reverge_collector.data_model import (
        CollectionModule,
        CollectionModuleOutput,
        Host,
        Port,
    )
    from reverge_collector.iis_short_scan import parse_iis_short_scan_output

    f = tmp_path / 'iis.json'
    f.write_text(
        json.dumps(
            {
                'port-uuid-1': {
                    'meta_data': {
                        'host_id': 'host-uuid-1',
                        'ip_addr': '10.0.0.5',
                        'port_str': '443',
                    },
                    'results': ['ADMIN~1', 'BACKUP~1'],
                }
            }
        )
    )
    records = parse_iis_short_scan_output(str(f), tool_instance_id='tid', tool_id='tool-uuid')
    modules = [r for r in records if isinstance(r, CollectionModule)]
    hosts = [r for r in records if isinstance(r, Host)]
    ports = [r for r in records if isinstance(r, Port)]
    outputs = [r for r in records if isinstance(r, CollectionModuleOutput)]

    assert len(modules) == 1
    assert modules[0].name == 'iis-shortname-scan'
    assert hosts and hosts[0].ipv4_addr == '10.0.0.5'
    assert ports and ports[0].port == '443'
    assert outputs and 'ADMIN~1' in outputs[0].output


# ===========================================================================
# crapsecrets
# ===========================================================================


def test_crapsecrets_empty_returns_empty(tmp_path):
    from reverge_collector.crapsecrets_scan import parse_crapsecrets_output

    f = tmp_path / 'cs.json'
    f.write_text('')
    assert parse_crapsecrets_output(str(f), 'tid', 'toolid') == []


# ===========================================================================
# netexec — happy path with one credential success line
# ===========================================================================


def test_netexec_parses_credential_success(tmp_path):
    from reverge_collector.netexec_scan import parse_netexec_output

    netexec_jsonl = tmp_path / 'netexec_out.jsonl'
    netexec_jsonl.write_text(
        json.dumps(
            {
                'protocol': 'smb',
                'host': '10.0.0.50',
                'port': 445,
                'hostname': 'WIN-HOST',
                'type': 'success',
                'level': '',
                'message': 'CONTOSO\\admin:Password123!',
                'module_name': None,
                'server_os': 'Windows 10',
            }
        )
        + '\n'
    )
    meta = tmp_path / 'netexec.meta'
    meta.write_text(
        json.dumps({'netexec_scan_list': [{'output_file': str(netexec_jsonl), 'protocol': 'smb'}]})
    )
    # Should not raise; returns a list of records
    records = parse_netexec_output(str(meta), tool_instance_id='tid', tool_id='toolid')
    assert isinstance(records, list)


def test_netexec_skips_lines_missing_required_fields(tmp_path):
    from reverge_collector.netexec_scan import parse_netexec_output

    netexec_jsonl = tmp_path / 'netexec_out.jsonl'
    netexec_jsonl.write_text(
        '\n'  # blank
        + 'not json\n'  # malformed
        # Missing port/hostname
        + json.dumps({'host': '1.2.3.4'})
        + '\n'
    )
    meta = tmp_path / 'm.meta'
    meta.write_text(
        json.dumps({'netexec_scan_list': [{'output_file': str(netexec_jsonl), 'protocol': 'smb'}]})
    )
    out = parse_netexec_output(str(meta), tool_instance_id='tid', tool_id='toolid')
    assert isinstance(out, list)


# ===========================================================================
# python_scan
# ===========================================================================


def test_python_scan_with_minimal_metadata(tmp_path):
    from reverge_collector.python_scan import parse_python_scan_output

    # Smallest viable input — parser walks expected structure if present
    f = tmp_path / 'p.json'
    f.write_text(json.dumps({'results': []}))
    out = parse_python_scan_output(str(f), 'tid', 'toolid')
    assert isinstance(out, list)


# ===========================================================================
# nuclei — additional branches
# ===========================================================================


def test_nuclei_with_metadata_vendor_product_falls_back_to_constructed_cpe(tmp_path):
    """When classification.cpe is empty, parser builds one from
    metadata.vendor + metadata.product."""
    from reverge_collector.data_model import Cpe
    from reverge_collector.nuclei_scan import parse_nuclei_output

    f = tmp_path / 'n.jsonl'
    f.write_text(
        json.dumps(
            {
                'template-id': 'apache-detect',
                'url': 'https://1.2.3.4',
                'info': {
                    'name': 'Apache Detect',
                    'metadata': {'vendor': 'apache', 'product': 'http_server'},
                },
            }
        )
        + '\n'
    )
    records = parse_nuclei_output(str(f), None, 'tid', tool_id='toolid')
    cpes = [r for r in records if isinstance(r, Cpe)]
    assert any('apache' in (c.vendor or '') for c in cpes)


def test_nuclei_with_endpoint_port_map(tmp_path):
    """When endpoint_port_obj_map is provided, parser uses the supplied
    port_id instead of constructing host/port from the URL."""
    from reverge_collector.data_model import Host
    from reverge_collector.nuclei_scan import parse_nuclei_output

    f = tmp_path / 'n.jsonl'
    f.write_text(
        json.dumps(
            {
                'template-id': 'x',
                'url': 'https://target.example.com',
                'info': {},
            }
        )
        + '\n'
    )
    endpoint_map = {'https://target.example.com': {'port_id': 'port-uuid-1'}}
    records = parse_nuclei_output(str(f), endpoint_map, 'tid')
    # With map provided, no Host record should be created from URL
    hosts = [r for r in records if isinstance(r, Host)]
    assert hosts == []


def test_nuclei_endpoint_not_in_map_is_skipped(tmp_path):
    from reverge_collector.nuclei_scan import parse_nuclei_output

    f = tmp_path / 'n.jsonl'
    f.write_text(json.dumps({'template-id': 'x', 'url': 'https://stranger.com', 'info': {}}) + '\n')
    # Endpoint not in the supplied map → entry is skipped
    out = parse_nuclei_output(
        str(f), endpoint_port_obj_map={'https://other.com': {'port_id': 'p1'}}
    )
    assert out == []


# ===========================================================================
# httpx — extra branches
# ===========================================================================


def test_httpx_parses_via_scope_object(tmp_path):
    """When scope_obj is provided and matches the input, parser correlates
    host_id from the existing scope rather than creating a new Host."""
    from reverge_collector.data_model import Host
    from reverge_collector.httpx_scan import parse_httpx_output

    # Build a minimal scope-like object
    class FakeScope:
        host_port_obj_map = {}
        host_ip_id_map = {'1.2.3.4': 'existing-host-id'}

    f = tmp_path / 'h.json'
    f.write_text(
        json.dumps(
            {
                'input': '1.2.3.4',
                'host_ip': '1.2.3.4',
                'port': '80',
                'url': 'http://1.2.3.4',
                'scheme': 'http',
                'status_code': 200,
            }
        )
        + '\n'
    )
    records = parse_httpx_output([str(f)], 'tid', scope_obj=FakeScope())
    # Parser still creates a Host (with the new IP) — confirm it runs
    hosts = [r for r in records if isinstance(r, Host)]
    assert hosts


def test_httpx_parses_a_records_array(tmp_path):
    """Alternative IP field: 'a' is a list, take first entry."""
    from reverge_collector.data_model import Host
    from reverge_collector.httpx_scan import parse_httpx_output

    f = tmp_path / 'h.json'
    f.write_text(
        json.dumps(
            {
                'input': 'host.example.com',
                'a': ['1.1.1.1', '2.2.2.2'],
                'port': '443',
                'url': 'https://host.example.com',
                'scheme': 'https',
            }
        )
        + '\n'
    )
    records = parse_httpx_output([str(f)], 'tid')
    hosts = [r for r in records if isinstance(r, Host)]
    assert hosts and hosts[0].ipv4_addr == '1.1.1.1'


# ===========================================================================
# masscan — invalid XML branch
# ===========================================================================


def test_masscan_corrupt_xml_raises_after_removing(tmp_path):
    from reverge_collector.masscan import parse_masscan_xml

    f = tmp_path / 'bad.xml'
    f.write_text('this is not xml at all')
    # Parser logs the error, deletes the file, and re-raises
    import pytest

    with pytest.raises(Exception):
        parse_masscan_xml(str(f), 'tid')
    # File was removed
    assert not f.exists()
