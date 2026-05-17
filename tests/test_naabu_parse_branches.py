"""Branch-coverage tests for naabu_scan.parse_naabu_output and _cpe22_to_cpe23."""

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


def _write_jsonl(tmp_path, entries):
    p = tmp_path / 'naabu.jsonl'
    with open(p, 'w') as fh:
        for e in entries:
            if isinstance(e, str):
                fh.write(e + '\n')
            else:
                fh.write(json.dumps(e) + '\n')
    return str(p)


# ===========================================================================
# _cpe22_to_cpe23
# ===========================================================================


class TestCpe22To23:
    def test_passthrough_when_not_cpe22(self):
        from reverge_collector.naabu_scan import _cpe22_to_cpe23

        assert _cpe22_to_cpe23('not-a-cpe') == 'not-a-cpe'

    def test_basic_three_part_with_version(self):
        from reverge_collector.naabu_scan import _cpe22_to_cpe23

        out = _cpe22_to_cpe23('cpe:/a:openbsd:openssh:9.6p1/')
        assert out == 'cpe:2.3:a:openbsd:openssh:9.6p1:*:*:*:*:*:*:*'

    def test_two_part_without_version(self):
        from reverge_collector.naabu_scan import _cpe22_to_cpe23

        out = _cpe22_to_cpe23('cpe:/a:apache:http_server/')
        assert out == 'cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*'


# ===========================================================================
# parse_naabu_output
# ===========================================================================


class TestParseNaabuOutput:
    def test_skips_blank_and_invalid_json_lines(self, tmp_path):
        from reverge_collector.naabu_scan import parse_naabu_output

        f = _write_jsonl(tmp_path, [
            '',
            'not-json {',
            {'ip': '10.0.0.1', 'port': 22, 'host': '10.0.0.1'},
        ])
        records = parse_naabu_output(f, tool_instance_id='ti')
        hosts = [r for r in records if type(r).__name__ == 'Host']
        assert len(hosts) == 1

    def test_skips_entry_missing_ip_or_port(self, tmp_path):
        from reverge_collector.naabu_scan import parse_naabu_output

        f = _write_jsonl(tmp_path, [
            {'port': 22},  # missing ip
            {'ip': '10.0.0.2'},  # missing port
            {'ip': '10.0.0.3', 'port': 22},  # valid
        ])
        records = parse_naabu_output(f, tool_instance_id='ti')
        ips = [r.ipv4_addr for r in records if type(r).__name__ == 'Host']
        assert ips == ['10.0.0.3']

    def test_invalid_ip_address_is_skipped(self, tmp_path):
        from reverge_collector.naabu_scan import parse_naabu_output

        f = _write_jsonl(tmp_path, [
            {'ip': 'not-an-ip', 'port': 22},
            {'ip': '10.0.0.1', 'port': 22},
        ])
        records = parse_naabu_output(f, tool_instance_id='ti')
        ips = [r.ipv4_addr for r in records if type(r).__name__ == 'Host']
        assert ips == ['10.0.0.1']

    def test_emits_domain_when_host_differs_from_ip(self, tmp_path):
        from reverge_collector.naabu_scan import parse_naabu_output

        f = _write_jsonl(tmp_path, [
            {'ip': '10.0.0.5', 'port': 80, 'host': 'web.example.com'},
        ])
        records = parse_naabu_output(f, tool_instance_id='ti')
        domains = [r for r in records if type(r).__name__ == 'Domain']
        assert domains and domains[0].name == 'web.example.com'

    def test_tls_true_marks_port_secure(self, tmp_path):
        from reverge_collector.naabu_scan import parse_naabu_output

        f = _write_jsonl(tmp_path, [
            {'ip': '10.0.0.1', 'port': 443, 'tls': True},
        ])
        records = parse_naabu_output(f, tool_instance_id='ti')
        ports = [r for r in records if type(r).__name__ == 'Port']
        assert ports and ports[0].secure is True

    def test_service_name_emits_application_protocol(self, tmp_path):
        from reverge_collector.naabu_scan import parse_naabu_output

        f = _write_jsonl(tmp_path, [
            {'ip': '10.0.0.1', 'port': 22, 'name': 'ssh'},
        ])
        records = parse_naabu_output(f, tool_instance_id='ti')
        protos = [r for r in records if type(r).__name__ == 'ApplicationProtocol']
        assert protos and protos[0].name == 'ssh'

    def test_unknown_service_name_skips_application_protocol(self, tmp_path):
        from reverge_collector.naabu_scan import parse_naabu_output

        f = _write_jsonl(tmp_path, [
            {'ip': '10.0.0.1', 'port': 9999, 'name': 'unknown'},
        ])
        records = parse_naabu_output(f, tool_instance_id='ti')
        protos = [r for r in records if type(r).__name__ == 'ApplicationProtocol']
        assert not protos

    def test_product_emits_cpe_with_version_when_no_cpes(self, tmp_path):
        from reverge_collector.naabu_scan import parse_naabu_output

        f = _write_jsonl(tmp_path, [
            {'ip': '10.0.0.1', 'port': 80,
             'name': 'http', 'product': 'apache httpd', 'version': '2.4.52'},
        ])
        records = parse_naabu_output(f, tool_instance_id='ti')
        cpes = [r for r in records if type(r).__name__ == 'Cpe']
        assert cpes
        assert cpes[0].product == 'apache httpd'
        assert cpes[0].version == '2.4.52'

    def test_cpe22_input_is_converted_and_overlays_product(self, tmp_path):
        from reverge_collector.naabu_scan import parse_naabu_output

        f = _write_jsonl(tmp_path, [
            {'ip': '10.0.0.1', 'port': 22,
             'name': 'ssh', 'product': 'openssh server', 'version': '9.6p1',
             'cpes': ['cpe:/a:openbsd:openssh:9.6p1/']},
        ])
        records = parse_naabu_output(f, tool_instance_id='ti')
        cpe = next(r for r in records if type(r).__name__ == 'Cpe')
        # Product overlay from naabu's human-readable name
        assert cpe.product == 'openssh server'

    def test_product_matching_service_name_is_skipped(self, tmp_path):
        from reverge_collector.naabu_scan import parse_naabu_output

        f = _write_jsonl(tmp_path, [
            {'ip': '10.0.0.1', 'port': 80, 'name': 'http', 'product': 'http'},
        ])
        records = parse_naabu_output(f, tool_instance_id='ti')
        cpes = [r for r in records if type(r).__name__ == 'Cpe']
        assert not cpes

    def test_uses_scope_host_id_when_match(self, tmp_path):
        """Existing scope host:port → reuse the scope's host/port ids."""
        from reverge_collector.naabu_scan import parse_naabu_output
        from reverge_collector.data_model import ScanData

        scope_dict = {
            'b64_port_bitmap': base64.b64encode(get_port_byte_array('22')).decode(),
            'obj_list': [
                {
                    'type': 'host', 'id': 'sc-h',
                    'data': {'ipv4_addr': '10.0.0.99'},
                    'tags': [data_model.RecordTag.SCOPE.value],
                },
                {
                    'type': 'port', 'id': 'sc-p',
                    'parent': {'type': 'host', 'id': 'sc-h'},
                    'data': {'port': '22', 'proto': 0, 'secure': False},
                    'tags': [data_model.RecordTag.SCOPE.value],
                },
            ],
        }
        scope = ScanData(scope_dict)
        f = _write_jsonl(tmp_path, [
            {'ip': '10.0.0.99', 'port': 22},
        ])
        records = parse_naabu_output(f, scope_obj=scope, tool_instance_id='ti')
        host = next(r for r in records if type(r).__name__ == 'Host')
        assert host.id == 'sc-h'
