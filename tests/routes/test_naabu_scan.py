import json
import os
import shutil
import uuid
from types import SimpleNamespace
from unittest.mock import patch

from reverge_collector.data_model import ScanData, ScheduledScan
from reverge_collector.naabu_scan import Naabu, _cpe22_to_cpe23, parse_naabu_output
from reverge_collector.recon_manager import ReconManager, ScheduledScanThread
from reverge_collector.scan_utils import get_port_byte_array

from tests.conftest import get_tool_id


class TestNaabuScan:
    TOOL_NAME = 'naabu'
    TEST_SCAN_ID = format(uuid.uuid4().int, 'x')
    TEST_SCHEDULED_SCAN_ID = format(uuid.uuid4().int, 'x')

    def _make_scheduled_scan(self, recon_manager, target_ip, port_list, args='-sD -sV'):
        tool_id_instance = get_tool_id(recon_manager, self.TOOL_NAME)
        tool_inst = {
            'id': 'b1234abcde5678901234567890abcdef',
            'collection_tool': {
                'wordlists': [],
                'name': self.TOOL_NAME,
                'args': args,
                'tool_type': 2,
                'scan_order': 4,
                'api_key': None,
                'id': tool_id_instance,
            },
            'args_override': None,
            'enabled': 1,
            'status': 0,
            'status_message': None,
            'collection_tool_id': tool_id_instance,
            'scheduled_scan_id': self.TEST_SCHEDULED_SCAN_ID,
            'owner_id': '94cb514e85da4abea6ee227730328619',
        }
        scheduler_inst_object = {
            'id': self.TEST_SCHEDULED_SCAN_ID,
            'scan_id': self.TEST_SCAN_ID,
            'target_id': 1234,
            'collection_tools': [tool_inst],
        }
        data = json.dumps(scheduler_inst_object)
        sched_scan_arr = json.loads(data, object_hook=lambda d: SimpleNamespace(**d))

        port_bytes = get_port_byte_array(port_list)
        import base64

        b64_ports = base64.b64encode(port_bytes).decode()
        scope = {
            'b64_port_bitmap': b64_ports,
            'obj_list': [
                {
                    'type': 'subnet',
                    'id': 'f57d93bcbe924127b24add0f5af04a63',
                    'data': {'subnet': target_ip, 'mask': 32},
                    'tags': [3],
                }
            ],
        }
        scan_data = {
            'scan_id': self.TEST_SCAN_ID,
            'scope': scope,
        }
        return sched_scan_arr, scan_data

    # ------------------------------------------------------------------
    # Scan execution test
    # ------------------------------------------------------------------

    def test_naabu_scan_success(self, recon_manager):
        target_ip = 'www.securifera.com'
        port_list = '443'

        sched_scan_arr, scan_data = self._make_scheduled_scan(recon_manager, target_ip, port_list)

        scan_thread = ScheduledScanThread(recon_manager, None)
        with patch.object(ReconManager, 'get_scheduled_scan', return_value=scan_data):
            scheduled_scan_obj = ScheduledScan(scan_thread, sched_scan_arr)
            first_key = next(iter(scheduled_scan_obj.collection_tool_map))
            first_tool = scheduled_scan_obj.collection_tool_map[first_key]
            scheduled_scan_obj.current_tool = first_tool.collection_tool
            if first_tool.args_override:
                scheduled_scan_obj.current_tool.args = first_tool.args_override

            result = recon_manager.scan_func(scheduled_scan_obj)
            assert result is True

            output_dir = '/tmp/%s' % self.TEST_SCHEDULED_SCAN_ID
            assert os.path.exists(output_dir)

            input_conf = '%s/%s-outputs/naabu_in_0' % (output_dir, self.TOOL_NAME)
            assert os.path.exists(input_conf)

            with open(input_conf) as f:
                assert target_ip in f.read()

            output_file = '%s/%s-outputs/naabu_out_0' % (output_dir, self.TOOL_NAME)
            assert os.path.exists(output_file)

    # ------------------------------------------------------------------
    # Import / parse test
    # ------------------------------------------------------------------

    def test_naabu_import_success(self, recon_manager):
        target_ip = 'www.securifera.com'
        port_list = '443'

        sched_scan_arr, scan_data = self._make_scheduled_scan(recon_manager, target_ip, port_list)

        output_dir = '/tmp/%s' % self.TEST_SCHEDULED_SCAN_ID
        try:
            scan_thread = ScheduledScanThread(recon_manager, None)
            with patch.object(ReconManager, 'get_scheduled_scan', return_value=scan_data):
                scheduled_scan_obj = ScheduledScan(scan_thread, sched_scan_arr)
                first_key = next(iter(scheduled_scan_obj.collection_tool_map))
                first_tool = scheduled_scan_obj.collection_tool_map[first_key]
                scheduled_scan_obj.current_tool = first_tool.collection_tool
                if first_tool.args_override:
                    scheduled_scan_obj.current_tool.args = first_tool.args_override

                with patch.object(ReconManager, 'import_data', return_value={}):
                    result = recon_manager.import_func(scheduled_scan_obj)
                    assert result is True

                    output_json = '%s/%s-outputs/tool_import_json' % (output_dir, self.TOOL_NAME)
                    assert os.path.exists(output_json)

                    import_arr = []
                    with open(output_json) as import_fd:
                        for line in import_fd:
                            line = line.strip()
                            if line:
                                import_arr.extend(json.loads(line))

                    if import_arr:
                        scan_data_obj = {'obj_list': import_arr}
                        scan_data_parsed = ScanData(scan_data_obj)

                        port_map = scan_data_parsed.port_host_map
                        assert len(port_map) > 0
                        assert '443' in port_map

                        host_id_set = port_map['443']
                        assert len(host_id_set) > 0
                        host_id = next(iter(host_id_set))
                        host_obj = scan_data_parsed.host_map[host_id]
                        assert host_obj.ipv4_addr == '52.4.7.15'

                        port_obj_list = scan_data_parsed.host_id_port_map[host_id]
                        assert len(port_obj_list) > 0
                        port_obj = port_obj_list[0]
                        assert port_obj.port == '443'
                        assert port_obj.secure is True

        finally:
            if os.path.exists(output_dir):
                shutil.rmtree(output_dir)


# ------------------------------------------------------------------
# Unit tests for parse_naabu_output
# ------------------------------------------------------------------


class TestParseNaabuOutput:
    def _write_jsonl(self, tmp_path, lines):
        path = os.path.join(tmp_path, 'naabu_out.jsonl')
        with open(path, 'w') as f:
            for entry in lines:
                f.write(json.dumps(entry) + '\n')
        return path

    def test_basic_http_entry(self, tmp_path):
        entry = {
            'host': 'www.example.com',
            'ip': '93.184.216.34',
            'port': 80,
            'protocol': 'tcp',
            'tls': False,
            'name': 'http',
            'product': 'Apache httpd',
            'cpes': ['cpe:/a:apache:http_server/'],
        }
        path = self._write_jsonl(str(tmp_path), [entry])
        records = parse_naabu_output(path)

        from reverge_collector.data_model import ApplicationProtocol, Cpe, Domain, Host, Port

        host_records = [r for r in records if isinstance(r, Host)]
        port_records = [r for r in records if isinstance(r, Port)]
        cpe_records = [r for r in records if isinstance(r, Cpe)]
        proto_records = [r for r in records if isinstance(r, ApplicationProtocol)]
        domain_records = [r for r in records if isinstance(r, Domain)]

        assert len(host_records) == 1
        assert host_records[0].ipv4_addr == '93.184.216.34'

        assert len(port_records) == 1
        assert port_records[0].port == '80'
        assert port_records[0].secure is False

        assert len(domain_records) == 1
        assert domain_records[0].name == 'www.example.com'

        # service name now emitted as ApplicationProtocol
        proto = next((p for p in proto_records if p.name == 'http'), None)
        assert proto is not None

        # product-level component carries vendor/product extracted from the CPE
        prod = next((c for c in cpe_records if c.product == 'apache httpd'), None)
        assert prod is not None
        assert prod.vendor == 'apache'

    def test_tls_port_marked_secure(self, tmp_path):
        entry = {
            'host': 'www.example.com',
            'ip': '93.184.216.34',
            'port': 443,
            'protocol': 'tcp',
            'tls': True,
            'name': 'https',
            'product': 'nginx',
            'cpes': [],
        }
        path = self._write_jsonl(str(tmp_path), [entry])
        records = parse_naabu_output(path)

        from reverge_collector.data_model import Port

        port_records = [r for r in records if isinstance(r, Port)]
        assert port_records[0].secure is True

        # service name == 'https' → ApplicationProtocol; product 'nginx' → Cpe
        from reverge_collector.data_model import ApplicationProtocol, Cpe

        cpe_records = [r for r in records if isinstance(r, Cpe)]
        proto_records = [r for r in records if isinstance(r, ApplicationProtocol)]
        assert any(p.name == 'https' for p in proto_records)
        assert any(c.product == 'nginx' for c in cpe_records)

    def test_version_populated(self, tmp_path):
        entry = {
            'host': 'example.com',
            'ip': '1.2.3.4',
            'port': 22,
            'protocol': 'tcp',
            'tls': False,
            'name': 'ssh',
            'product': 'OpenSSH',
            'version': '9.6p1 Ubuntu 3ubuntu13.16',
            'cpes': ['cpe:/a:openbsd:openssh:9.6p1/'],
        }
        path = self._write_jsonl(str(tmp_path), [entry])
        records = parse_naabu_output(path)

        from reverge_collector.data_model import ApplicationProtocol, Cpe

        cpe_records = [r for r in records if isinstance(r, Cpe)]
        proto_records = [r for r in records if isinstance(r, ApplicationProtocol)]
        # service 'ssh' → ApplicationProtocol; product 'openssh' → Cpe
        prod = next((c for c in cpe_records if c.product == 'openssh'), None)
        assert prod is not None
        # The naabu-provided CPE 2.2 string is parsed into vendor/product/version
        assert prod.vendor == 'openbsd'
        assert prod.version == '9.6p1'
        svc = next((p for p in proto_records if p.name == 'ssh'), None)
        assert svc is not None

    def test_no_cpes_uses_generic(self, tmp_path):
        entry = {
            'host': 'example.com',
            'ip': '1.2.3.4',
            'port': 8080,
            'protocol': 'tcp',
            'tls': False,
            'name': 'http-proxy',
            'product': '',
            'cpes': [],
        }
        path = self._write_jsonl(str(tmp_path), [entry])
        records = parse_naabu_output(path)

        from reverge_collector.data_model import ApplicationProtocol, Cpe

        cpe_records = [r for r in records if isinstance(r, Cpe)]
        proto_records = [r for r in records if isinstance(r, ApplicationProtocol)]
        # product is empty so only the service-name protocol is emitted
        assert len(cpe_records) == 0
        assert len(proto_records) == 1
        assert proto_records[0].name == 'http-proxy'

    def test_skips_invalid_json_lines(self, tmp_path):
        path = os.path.join(str(tmp_path), 'naabu_out.jsonl')
        with open(path, 'w') as f:
            f.write('not json\n')
            f.write(
                json.dumps(
                    {
                        'host': 'x.com',
                        'ip': '5.5.5.5',
                        'port': 80,
                        'protocol': 'tcp',
                        'tls': False,
                        'name': 'http',
                        'product': 'nginx',
                        'cpes': [],
                    }
                )
                + '\n'
            )
        records = parse_naabu_output(path)
        assert len(records) > 0  # valid line should still be parsed

    def test_multiple_entries(self, tmp_path):
        entries = [
            {
                'host': 'h.com',
                'ip': '10.0.0.1',
                'port': 80,
                'protocol': 'tcp',
                'tls': False,
                'name': 'http',
                'product': 'Apache httpd',
                'cpes': ['cpe:/a:apache:http_server/'],
            },
            {
                'host': 'h.com',
                'ip': '10.0.0.1',
                'port': 443,
                'protocol': 'tcp',
                'tls': True,
                'name': 'https',
                'product': 'nginx',
                'cpes': [],
            },
        ]
        path = self._write_jsonl(str(tmp_path), entries)
        records = parse_naabu_output(path)

        from reverge_collector.data_model import Port

        port_records = [r for r in records if isinstance(r, Port)]
        ports = {p.port for p in port_records}
        assert '80' in ports
        assert '443' in ports


# ------------------------------------------------------------------
# Unit tests for _cpe22_to_cpe23
# ------------------------------------------------------------------


class TestCpe22ToCpe23:
    def test_apache(self):
        result = _cpe22_to_cpe23('cpe:/a:apache:http_server/')
        assert result == 'cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*'

    def test_openssh_with_version(self):
        result = _cpe22_to_cpe23('cpe:/a:openbsd:openssh:9.6p1/')
        assert result == 'cpe:2.3:a:openbsd:openssh:9.6p1:*:*:*:*:*:*:*'

    def test_os_type(self):
        result = _cpe22_to_cpe23('cpe:/o:canonical:ubuntu_linux/')
        assert result == 'cpe:2.3:o:canonical:ubuntu_linux:*:*:*:*:*:*:*:*'

    def test_passthrough_non_cpe22(self):
        cpe23 = 'cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*'
        assert _cpe22_to_cpe23(cpe23) == cpe23
