"""Tests for the API/lookup modules: shodan_lookup, ip_thc_lookup.

These modules wrap external APIs (Shodan, IP THC). The unit tests here:
  - Cover the pure-logic helpers directly (reduce_subnets, process_response,
    parse_X_output, etc.)
  - Mock the external API client for the wrappers (shodan_dns_query,
    shodan_host_query) so we exercise the rate-limit/retry/error branches
    without hitting the network.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import netaddr
import pytest


# ===========================================================================
# shodan_lookup
# ===========================================================================


class TestReduceSubnets:
    def test_filters_out_private_ranges(self):
        from reverge_collector.shodan_lookup import reduce_subnets

        out = reduce_subnets(['10.0.0.1/32', '192.168.1.0/24', '172.16.0.0/12'])
        # All three are private → nothing left
        assert out == []

    def test_keeps_specific_subnets_as_is(self):
        from reverge_collector.shodan_lookup import reduce_subnets

        # Anything /24 or more specific (prefixlen >= 24) is kept verbatim.
        out = reduce_subnets(['8.8.8.8/32'])
        assert len(out) == 1
        assert out[0].prefixlen == 32

    def test_merges_adjacent_class_c_networks(self):
        from reverge_collector.shodan_lookup import reduce_subnets

        # Two /24s in same /23 should merge.
        out = reduce_subnets(['8.8.8.0/24', '8.8.9.0/24'])
        assert len(out) == 1
        assert out[0].prefixlen == 23

    def test_expands_broader_subnets_to_24(self):
        from reverge_collector.shodan_lookup import reduce_subnets

        # /16 is broader than /24 → expanded down to a /24 (first one).
        out = reduce_subnets(['8.8.0.0/16'])
        assert len(out) == 1
        # The function uses the network address of the IPNetwork — for /16
        # input '8.8.0.0/16' the network base is 8.8.0.0, then /24 → 8.8.0.0/24
        assert out[0].prefixlen == 24
        assert str(out[0].network) == '8.8.0.0'


class TestParseShodanOutput:
    def test_empty_file_returns_empty(self, tmp_path):
        from reverge_collector.shodan_lookup import parse_shodan_output

        f = tmp_path / 's.json'
        f.write_text('')
        assert parse_shodan_output(str(f), 'tid') == []

    def test_parses_host_and_port_records(self, tmp_path):
        from reverge_collector.data_model import Host, Port
        from reverge_collector.shodan_lookup import parse_shodan_output

        # Shodan service data uses int IPs (legacy) and integer port keys
        ip_int = int(netaddr.IPAddress('1.2.3.4'))
        f = tmp_path / 's.json'
        f.write_text(
            json.dumps(
                {
                    'data': [
                        {'ip': ip_int, 'port': 80},
                        {'ip': ip_int, 'port': 443},
                    ]
                }
            )
        )
        records = parse_shodan_output(str(f), tool_instance_id='tid')
        hosts = [r for r in records if isinstance(r, Host)]
        ports = [r for r in records if isinstance(r, Port)]
        # One host per service entry (parser doesn't dedup); 2 ports
        assert len(hosts) == 2
        assert len(ports) == 2
        assert {p.port for p in ports} == {80, 443}

    def test_parses_ssl_marks_port_secure_and_emits_domain(self, tmp_path):
        from reverge_collector.data_model import Domain, Port
        from reverge_collector.shodan_lookup import parse_shodan_output

        ip_int = int(netaddr.IPAddress('1.2.3.4'))
        f = tmp_path / 's.json'
        f.write_text(
            json.dumps(
                {
                    'data': [
                        {
                            'ip': ip_int,
                            'port': 443,
                            'ssl': {
                                'cert': {'subject': {'CN': 'WWW.EXAMPLE.COM'}}
                            },
                        }
                    ]
                }
            )
        )
        records = parse_shodan_output(str(f), tool_instance_id='tid')
        ports = [r for r in records if isinstance(r, Port)]
        domains = [r for r in records if isinstance(r, Domain)]
        assert ports and ports[0].secure is True
        assert domains and domains[0].name == 'www.example.com'  # lowercased


class TestShodanDnsQuery:
    def test_returns_unique_ips_from_a_records(self):
        from reverge_collector.shodan_lookup import shodan_dns_query

        api = MagicMock()
        api.dns.domain_info.return_value = {
            'data': [
                {'type': 'A', 'value': '1.1.1.1'},
                {'type': 'A', 'value': '1.1.1.1'},  # duplicate
                {'type': 'A', 'value': '2.2.2.2'},
                {'type': 'TXT', 'value': 'v=spf1'},  # filtered out
            ]
        }
        out = shodan_dns_query(api, 'example.com')
        assert set(out) == {'1.1.1.1', '2.2.2.2'}

    def test_returns_empty_on_no_information(self):
        import shodan as shodan_pkg

        from reverge_collector.shodan_lookup import shodan_dns_query

        api = MagicMock()
        api.dns.domain_info.side_effect = shodan_pkg.exception.APIError(
            'No information available'
        )
        assert shodan_dns_query(api, 'nope.example.com') == []

    def test_invalid_key_propagates(self):
        import shodan as shodan_pkg

        from reverge_collector.shodan_lookup import shodan_dns_query

        api = MagicMock()
        api.dns.domain_info.side_effect = shodan_pkg.exception.APIError(
            'Invalid API key'
        )
        with pytest.raises(shodan_pkg.exception.APIError):
            shodan_dns_query(api, 'x.com')

    def test_rate_limit_retries_then_succeeds(self):
        import shodan as shodan_pkg

        from reverge_collector.shodan_lookup import shodan_dns_query

        api = MagicMock()
        # First call: rate-limit; second: success
        api.dns.domain_info.side_effect = [
            shodan_pkg.exception.APIError('Request rate limit reached'),
            {'data': [{'type': 'A', 'value': '9.9.9.9'}]},
        ]
        # Patch sleep to avoid real delay
        with patch('reverge_collector.shodan_lookup.time.sleep'):
            out = shodan_dns_query(api, 'x.com')
        assert out == ['9.9.9.9']
        assert api.dns.domain_info.call_count == 2


class TestShodanHostQuery:
    def test_returns_service_list_from_host_response(self):
        from reverge_collector.shodan_lookup import shodan_host_query

        api = MagicMock()
        api.host.return_value = {
            'data': [
                {'port': 80, 'transport': 'tcp'},
                {'port': 22, 'transport': 'tcp'},
            ]
        }
        out = shodan_host_query(api, '1.2.3.4')
        assert len(out) == 2
        assert {s['port'] for s in out} == {80, 22}

    def test_returns_empty_on_no_information(self):
        import shodan as shodan_pkg

        from reverge_collector.shodan_lookup import shodan_host_query

        api = MagicMock()
        api.host.side_effect = shodan_pkg.exception.APIError(
            'No information available for that IP'
        )
        assert shodan_host_query(api, '8.8.8.8') == []

    def test_invalid_key_propagates(self):
        import shodan as shodan_pkg

        from reverge_collector.shodan_lookup import shodan_host_query

        api = MagicMock()
        api.host.side_effect = shodan_pkg.exception.APIError('Access denied')
        with pytest.raises(shodan_pkg.exception.APIError):
            shodan_host_query(api, '8.8.8.8')

    def test_rate_limit_retries_then_succeeds(self):
        import shodan as shodan_pkg

        from reverge_collector.shodan_lookup import shodan_host_query

        api = MagicMock()
        api.host.side_effect = [
            shodan_pkg.exception.APIError('limit reached'),
            {'data': [{'port': 443}]},
        ]
        with patch('reverge_collector.shodan_lookup.time.sleep'):
            out = shodan_host_query(api, '1.2.3.4')
        assert out == [{'port': 443}]
        assert api.host.call_count == 2


# ===========================================================================
# ip_thc_lookup
# ===========================================================================


class TestIpThcProcessResponse:
    def test_extracts_domain_names_from_response(self):
        from reverge_collector.ip_thc_lookup import process_response

        body = json.dumps(
            {
                'domains': [
                    {'domain': 'a.example.com'},
                    {'domain': 'b.example.com'},
                    {'domain': '  c.example.com  '},  # whitespace stripped
                ]
            }
        ).encode('utf-8')
        out = process_response(body)
        assert out == {'a.example.com', 'b.example.com', 'c.example.com'}

    def test_handles_missing_domains_key(self):
        from reverge_collector.ip_thc_lookup import process_response

        body = json.dumps({'meta': 'no domains here'}).encode('utf-8')
        assert process_response(body) == set()

    def test_handles_non_dict_top_level(self):
        from reverge_collector.ip_thc_lookup import process_response

        body = json.dumps(['just', 'an', 'array']).encode('utf-8')
        assert process_response(body) == set()

    def test_filters_blank_domain_entries(self):
        from reverge_collector.ip_thc_lookup import process_response

        body = json.dumps(
            {
                'domains': [
                    {'domain': ''},
                    {'no_domain_key': True},
                    {'domain': 'good.example.com'},
                ]
            }
        ).encode('utf-8')
        assert process_response(body) == {'good.example.com'}


class TestParseIpThcOutput:
    def test_empty_file_returns_empty_list(self, tmp_path):
        from reverge_collector.ip_thc_lookup import parse_ip_thc_output

        f = tmp_path / 'i.json'
        f.write_text('')
        assert parse_ip_thc_output(str(f), 'tid') == []

    def test_emits_host_and_domain_records(self, tmp_path):
        from reverge_collector.data_model import Domain, Host
        from reverge_collector.ip_thc_lookup import parse_ip_thc_output

        f = tmp_path / 'i.json'
        f.write_text(
            json.dumps(
                {
                    'ip_to_host_dict_map': {
                        '1.2.3.4': {
                            'host_id': None,  # parser creates a new Host
                            'domains': ['one.example.com', 'two.example.com'],
                        },
                        '5.6.7.8': {
                            'host_id': 'existing-id',  # parser skips host creation
                            'domains': ['three.example.com'],
                        },
                    }
                }
            )
        )
        records = parse_ip_thc_output(str(f), tool_instance_id='tid')
        hosts = [r for r in records if isinstance(r, Host)]
        domains = [r for r in records if isinstance(r, Domain)]
        # One host created (the other reuses 'existing-id')
        assert len(hosts) == 1
        assert hosts[0].ipv4_addr == '1.2.3.4'
        # All three domains emitted
        assert {d.name for d in domains} == {
            'one.example.com',
            'two.example.com',
            'three.example.com',
        }

    def test_skips_invalid_ip_addresses(self, tmp_path):
        from reverge_collector.data_model import Host
        from reverge_collector.ip_thc_lookup import parse_ip_thc_output

        f = tmp_path / 'i.json'
        f.write_text(
            json.dumps(
                {
                    'ip_to_host_dict_map': {
                        'not.an.ip': {'host_id': None, 'domains': ['x.com']},
                        '8.8.8.8': {'host_id': None, 'domains': ['y.com']},
                    }
                }
            )
        )
        records = parse_ip_thc_output(str(f), 'tid')
        hosts = [r for r in records if isinstance(r, Host)]
        # Only the valid IP becomes a host
        assert len(hosts) == 1
        assert hosts[0].ipv4_addr == '8.8.8.8'

    def test_handles_ipv6_address(self, tmp_path):
        from reverge_collector.data_model import Host
        from reverge_collector.ip_thc_lookup import parse_ip_thc_output

        f = tmp_path / 'i.json'
        f.write_text(
            json.dumps(
                {
                    'ip_to_host_dict_map': {
                        '2606:2800:220:1:248:1893:25c8:1946': {
                            'host_id': None,
                            'domains': ['v6.example.com'],
                        }
                    }
                }
            )
        )
        records = parse_ip_thc_output(str(f), 'tid')
        hosts = [r for r in records if isinstance(r, Host)]
        assert hosts and hosts[0].ipv6_addr
