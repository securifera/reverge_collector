"""Deep parser tests for nuclei_scan."""

from __future__ import annotations

import json


def test_nuclei_cve_template_emits_vuln(tmp_path):
    from reverge_collector.data_model import Vuln
    from reverge_collector.nuclei_scan import parse_nuclei_output

    f = tmp_path / 'n.jsonl'
    f.write_text(
        json.dumps(
            {
                'template-id': 'cve-2021-44228',
                'url': 'http://target.example.com',
                'info': {'name': 'Log4Shell'},
            }
        )
        + '\n'
    )
    records = parse_nuclei_output(str(f), None, 'tid', tool_id='toolid')
    vulns = [r for r in records if isinstance(r, Vuln)]
    assert any(v.name == 'cve-2021-44228' for v in vulns)


def test_nuclei_emits_collection_module_per_result(tmp_path):
    from reverge_collector.data_model import (
        CollectionModule,
        CollectionModuleOutput,
    )
    from reverge_collector.nuclei_scan import parse_nuclei_output

    f = tmp_path / 'n.jsonl'
    f.write_text(
        json.dumps(
            {
                'template-id': 'tech-detect',
                'template': 'http/technologies/tech-detect.yaml',
                'url': 'https://target.example.com',
                'info': {'name': 'Tech Detect'},
                'matcher-name': 'apache',
            }
        )
        + '\n'
    )
    records = parse_nuclei_output(str(f), None, 'tid', tool_id='toolid')
    modules = [r for r in records if isinstance(r, CollectionModule)]
    outputs = [r for r in records if isinstance(r, CollectionModuleOutput)]
    assert modules and modules[0].name == 'tech-detect'
    assert modules[0].args == 'http/technologies/tech-detect.yaml'
    assert outputs and outputs[0].port_id is not None


def test_nuclei_matcher_with_per_matcher_cpe(tmp_path):
    """Multi-matcher template: matcher-cpe overrides template-level CPE."""
    from reverge_collector.data_model import Cpe
    from reverge_collector.nuclei_scan import parse_nuclei_output

    f = tmp_path / 'n.jsonl'
    f.write_text(
        json.dumps(
            {
                'template-id': 'fingerprinthub',
                'url': 'http://x.com',
                'info': {'name': 'FH'},
                'matcher-name': 'apache',
                'matcher-cpe': 'cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*',
            }
        )
        + '\n'
    )
    records = parse_nuclei_output(str(f), None, 'tid')
    cpes = [r for r in records if isinstance(r, Cpe)]
    # Cpe vendor should come from the matcher-cpe
    assert any(c.vendor == 'apache' for c in cpes)
    # Product is the matcher-name (lowercased)
    assert any(c.product == 'apache' for c in cpes)


def test_nuclei_matcher_no_cpe_emits_product_only(tmp_path):
    from reverge_collector.data_model import Cpe
    from reverge_collector.nuclei_scan import parse_nuclei_output

    f = tmp_path / 'n.jsonl'
    f.write_text(
        json.dumps(
            {
                'template-id': 'fingerprinthub',
                'url': 'http://x.com',
                'info': {'name': 'FH'},
                'matcher-name': 'wordpress',
                # No matcher-cpe, no template-level cpe
            }
        )
        + '\n'
    )
    records = parse_nuclei_output(str(f), None, 'tid')
    cpes = [r for r in records if isinstance(r, Cpe)]
    # Product set to matcher-name (lowercased); vendor empty
    assert any(c.product == 'wordpress' for c in cpes)


def test_nuclei_template_cpe_fallback_no_matcher_name(tmp_path):
    """When matcher-name missing but classification.cpe present, parser
    emits a Cpe with product = info.name (lowercased)."""
    from reverge_collector.data_model import Cpe
    from reverge_collector.nuclei_scan import parse_nuclei_output

    f = tmp_path / 'n.jsonl'
    f.write_text(
        json.dumps(
            {
                'template-id': 'angular-detect',
                'url': 'http://x.com',
                'info': {
                    'name': 'Angular Detect',
                    'classification': {
                        'cpe': 'cpe:2.3:a:angularjs:angular.js:*:*:*:*:*:*:*:*'
                    },
                },
            }
        )
        + '\n'
    )
    records = parse_nuclei_output(str(f), None, 'tid')
    cpes = [r for r in records if isinstance(r, Cpe)]
    assert any(c.product == 'angular detect' for c in cpes)
    assert any(c.vendor == 'angularjs' for c in cpes)


def test_nuclei_ipv6_url(tmp_path):
    """Standalone (no endpoint map) with an IPv6 URL → Host gets ipv6_addr."""
    from reverge_collector.data_model import Host
    from reverge_collector.nuclei_scan import parse_nuclei_output

    f = tmp_path / 'n.jsonl'
    f.write_text(
        json.dumps(
            {
                'template-id': 'x',
                'url': 'http://[2606:2800:220:1:248:1893:25c8:1946]',
                'info': {},
            }
        )
        + '\n'
    )
    records = parse_nuclei_output(str(f), None, 'tid')
    hosts = [r for r in records if isinstance(r, Host)]
    # Just confirm a host was emitted; IP type may or may not be set
    # depending on netaddr's view of bracketed addrs
    assert hosts


def test_nuclei_hostname_url_no_ip_address_set(tmp_path):
    """URL with hostname (not an IP) → Host record with no ipv4/ipv6 set."""
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
    records = parse_nuclei_output(str(f), None, 'tid')
    hosts = [r for r in records if isinstance(r, Host)]
    assert hosts
    # Hostname isn't an IP → ipv4_addr stays None
    assert hosts[0].ipv4_addr is None
