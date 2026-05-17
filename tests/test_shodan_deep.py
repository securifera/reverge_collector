"""Deep tests for shodan_lookup: _prepare_shodan_scope, execute_scan,
shodan_subnet_query, shodan_wrapper, and full-fixture parse_shodan_output.
"""

from __future__ import annotations

import base64
import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import netaddr
import pytest
from reverge_collector import data_model
from reverge_collector.scan_utils import get_port_byte_array


def _scope(obj_list, port_list_str='443'):
    return {
        'b64_port_bitmap': base64.b64encode(get_port_byte_array(port_list_str)).decode(),
        'obj_list': obj_list,
    }


def make_scan(tmp_path, *, obj_list=None, api_key='test-key'):
    """Build a minimal scheduled scan object with proper scan_data."""
    if obj_list is None:
        obj_list = []
    return SimpleNamespace(
        id='scan-shodan-' + str(id(obj_list)),
        scan_id='scan-shodan',
        target_id=1,
        scan_data=data_model.ScanData(_scope(obj_list)),
        current_tool=SimpleNamespace(name='shodan', id='shodan-tool', args=''),
        current_tool_instance_id='ct-1',
        current_tool_api_key=api_key,
        collection_tool_map={},
        selected_interface=None,
        register_tool_executor=MagicMock(),
    )


# ===========================================================================
# _prepare_shodan_scope
# ===========================================================================


class TestPrepareShodanScope:
    def test_writes_input_file_for_subnet(self, tmp_path, monkeypatch):
        from reverge_collector.shodan_lookup import _prepare_shodan_scope

        monkeypatch.chdir(tmp_path)
        scan = make_scan(
            tmp_path,
            obj_list=[
                {
                    'type': 'subnet',
                    'id': 's1',
                    'data': {'subnet': '8.8.8.0', 'mask': 24},
                    'tags': [data_model.RecordTag.SCOPE.value],
                },
            ],
        )
        path = _prepare_shodan_scope(scan)
        assert path.endswith('shodan_ips_' + scan.id)
        with open(path) as f:
            data = json.loads(f.read())
        assert '8.8.8.0/24' in data['host_list']

    def test_writes_input_file_for_host(self, tmp_path, monkeypatch):
        from reverge_collector.shodan_lookup import _prepare_shodan_scope

        monkeypatch.chdir(tmp_path)
        scan = make_scan(
            tmp_path,
            obj_list=[
                {
                    'type': 'host',
                    'id': 'h1',
                    'data': {'ipv4_addr': '8.8.8.8'},
                    'tags': [data_model.RecordTag.SCOPE.value],
                },
            ],
        )
        path = _prepare_shodan_scope(scan)
        with open(path) as f:
            data = json.loads(f.read())
        assert '8.8.8.8/32' in data['host_list']

    def test_returns_cached_file_when_exists(self, tmp_path, monkeypatch):
        from reverge_collector.shodan_lookup import _prepare_shodan_scope

        monkeypatch.chdir(tmp_path)
        scan = make_scan(tmp_path)
        # First call writes the file
        path1 = _prepare_shodan_scope(scan)
        # Write a sentinel marker
        with open(path1, 'w') as f:
            f.write('SENTINEL')
        # Second call should return the cached file (not overwrite it)
        path2 = _prepare_shodan_scope(scan)
        assert path1 == path2
        with open(path2) as f:
            assert f.read() == 'SENTINEL'


# ===========================================================================
# shodan_subnet_query
# ===========================================================================


class TestShodanSubnetQuery:
    def test_returns_search_results(self):
        from reverge_collector.shodan_lookup import shodan_subnet_query

        api = MagicMock()
        api.search_cursor.return_value = iter([{'ip': 1, 'port': 80}, {'ip': 2, 'port': 443}])
        out = shodan_subnet_query(api, '8.8.8.0', 24)
        assert len(out) == 2

    def test_rate_limit_retries_then_succeeds(self):
        import shodan as shodan_pkg
        from reverge_collector.shodan_lookup import shodan_subnet_query

        api = MagicMock()
        api.search_cursor.side_effect = [
            shodan_pkg.exception.APIError('rate limit reached'),
            iter([{'ip': 1, 'port': 80}]),
        ]
        with patch('reverge_collector.shodan_lookup.time.sleep'):
            out = shodan_subnet_query(api, '8.8.8.0', 24)
        assert out == [{'ip': 1, 'port': 80}]

    def test_invalid_key_propagates(self):
        import shodan as shodan_pkg
        from reverge_collector.shodan_lookup import shodan_subnet_query

        api = MagicMock()
        api.search_cursor.side_effect = shodan_pkg.exception.APIError('invalid api key')
        with pytest.raises(shodan_pkg.exception.APIError):
            shodan_subnet_query(api, '8.8.8.0', 24)

    def test_no_information_returns_empty(self):
        import shodan as shodan_pkg
        from reverge_collector.shodan_lookup import shodan_subnet_query

        api = MagicMock()
        api.search_cursor.side_effect = shodan_pkg.exception.APIError('no information available')
        assert shodan_subnet_query(api, '8.8.8.0', 24) == []


# ===========================================================================
# shodan_wrapper — dispatch logic
# ===========================================================================


class TestShodanWrapper:
    def test_dns_lookup_dispatches_to_dns_query(self):
        from reverge_collector import shodan_lookup
        from reverge_collector.shodan_lookup import shodan_wrapper

        with (
            patch.object(
                shodan_lookup,
                'shodan_dns_query',
                return_value=['1.2.3.4'],
            ),
            patch('reverge_collector.shodan_lookup.shodan.Shodan'),
        ):
            out = shodan_wrapper('key', domain='example.com')
        assert out == ['1.2.3.4']

    def test_host_query_dispatches_for_small_subnet(self):
        from reverge_collector import shodan_lookup
        from reverge_collector.shodan_lookup import shodan_wrapper

        # /32 is small enough to iterate hosts individually
        with (
            patch.object(
                shodan_lookup,
                'shodan_host_query',
                return_value=[{'port': 80}],
            ) as host_q,
            patch('reverge_collector.shodan_lookup.shodan.Shodan'),
        ):
            out = shodan_wrapper('key', ip='8.8.8.8', cidr=32)
        # /32 has 1 host → 1 call
        assert host_q.call_count == 1

    def test_subnet_query_dispatches_for_large_subnet(self):
        from reverge_collector import shodan_lookup
        from reverge_collector.shodan_lookup import shodan_wrapper

        # /24 is too big for host-by-host; uses subnet query
        with (
            patch.object(
                shodan_lookup,
                'shodan_subnet_query',
                return_value=[{'ip': 1, 'port': 80}],
            ) as subnet_q,
            patch('reverge_collector.shodan_lookup.shodan.Shodan'),
        ):
            out = shodan_wrapper('key', ip='8.8.8.0', cidr=24)
        subnet_q.assert_called_once()


# ===========================================================================
# execute_scan
# ===========================================================================


class TestShodanExecuteScan:
    def test_skips_when_output_already_exists(self, tmp_path, monkeypatch):
        from reverge_collector.shodan_lookup import execute_scan, get_output_path

        monkeypatch.chdir(tmp_path)
        scan = make_scan(tmp_path)
        # Pre-create the output file
        out_path = get_output_path(scan)
        import os

        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, 'w') as f:
            f.write('existing-output')
        # Should bail out without doing anything
        execute_scan(scan)
        with open(out_path) as f:
            assert f.read() == 'existing-output'

    def test_raises_when_no_api_key(self, tmp_path, monkeypatch):
        from reverge_collector.shodan_lookup import execute_scan

        monkeypatch.chdir(tmp_path)
        scan = make_scan(tmp_path, api_key=None)
        # No api key → wrapper call still happens, but loop raises
        with pytest.raises(Exception, match='shodan API key'):
            execute_scan(scan)

    def test_processes_subnets_and_writes_output(self, tmp_path, monkeypatch):
        from reverge_collector import shodan_lookup
        from reverge_collector.shodan_lookup import execute_scan, get_output_path

        monkeypatch.chdir(tmp_path)
        scan = make_scan(
            tmp_path,
            obj_list=[
                {
                    'type': 'subnet',
                    'id': 's1',
                    'data': {'subnet': '8.8.8.0', 'mask': 24},
                    'tags': [data_model.RecordTag.SCOPE.value],
                },
            ],
        )

        # Make wrapper return immediately with empty results
        def fake_wrapper(*args, **kwargs):
            return []

        with patch.object(shodan_lookup, 'shodan_wrapper', side_effect=fake_wrapper):
            execute_scan(scan)

        # Output written
        out_path = get_output_path(scan)
        with open(out_path) as f:
            data = json.loads(f.read())
        assert data == {'data': []}

    def test_skips_private_ip_subnets(self, tmp_path, monkeypatch):
        from reverge_collector import shodan_lookup
        from reverge_collector.shodan_lookup import execute_scan

        monkeypatch.chdir(tmp_path)
        scan = make_scan(
            tmp_path,
            obj_list=[
                {
                    'type': 'subnet',
                    'id': 'private',
                    'data': {'subnet': '10.0.0.0', 'mask': 8},
                    'tags': [data_model.RecordTag.SCOPE.value],
                },
                {
                    'type': 'subnet',
                    'id': 'public',
                    'data': {'subnet': '8.8.8.0', 'mask': 24},
                    'tags': [data_model.RecordTag.SCOPE.value],
                },
            ],
        )
        wrapper_calls = []

        def fake_wrapper(*args, **kwargs):
            wrapper_calls.append(kwargs)
            return []

        with patch.object(shodan_lookup, 'shodan_wrapper', side_effect=fake_wrapper):
            execute_scan(scan)

        # First call is the initial /32 probe (8.8.8.8). After that, only the
        # public subnet should be probed; the 10.0.0.0/8 should be skipped.
        # Count calls with non-private IPs
        public_ips = [c for c in wrapper_calls if c.get('ip', '').startswith('8.')]
        private_ips = [c for c in wrapper_calls if c.get('ip', '').startswith('10.')]
        assert len(private_ips) == 0
        assert len(public_ips) >= 1


# ===========================================================================
# parse_shodan_output — more http/ssl/title/server branches
# ===========================================================================


class TestParseShodanOutputDeep:
    def test_parses_http_status_title_server(self, tmp_path):
        from reverge_collector.data_model import Cpe, Port
        from reverge_collector.shodan_lookup import parse_shodan_output

        ip_int = int(netaddr.IPAddress('1.2.3.4'))
        f = tmp_path / 's.json'
        f.write_text(
            json.dumps(
                {
                    'data': [
                        {
                            'ip': ip_int,
                            'port': 80,
                            'http': {
                                'status': 200,
                                'title': 'Example',
                                'server': 'Apache/2.4.41',
                            },
                        }
                    ]
                }
            )
        )
        records = parse_shodan_output(str(f), tool_instance_id='tid')
        ports = [r for r in records if isinstance(r, Port)]
        cpes = [r for r in records if isinstance(r, Cpe)]
        assert ports
        # Apache server header should produce a Cpe
        apache = [c for c in cpes if 'apache' in (c.product or '')]
        assert apache  # at least one apache-related Cpe

    def test_parses_ssl_subject_alt_name_as_domains(self, tmp_path):
        """The parser may emit domain records for SAN entries when SSL data is present."""
        from reverge_collector.data_model import Domain
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
                                'cert': {
                                    'subject': {'CN': 'www.example.com'},
                                },
                            },
                        }
                    ]
                }
            )
        )
        records = parse_shodan_output(str(f), 'tid')
        domains = [r for r in records if isinstance(r, Domain)]
        assert any(d.name == 'www.example.com' for d in domains)

    def test_empty_data_array_returns_empty(self, tmp_path):
        from reverge_collector.shodan_lookup import parse_shodan_output

        f = tmp_path / 's.json'
        f.write_text(json.dumps({'data': []}))
        # When data is empty, parser still iterates but produces no records
        assert parse_shodan_output(str(f), 'tid') == []

    def test_handles_ipv6_address_field(self, tmp_path):
        from reverge_collector.data_model import Host
        from reverge_collector.shodan_lookup import parse_shodan_output

        ipv6 = netaddr.IPAddress('2606:2800:220:1:248:1893:25c8:1946')
        f = tmp_path / 's.json'
        f.write_text(json.dumps({'data': [{'ip': int(ipv6), 'port': 443}]}))
        records = parse_shodan_output(str(f), 'tid')
        hosts = [r for r in records if isinstance(r, Host)]
        assert hosts and hosts[0].ipv6_addr
