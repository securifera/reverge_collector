import base64
import os
import shutil
import uuid
import json
from waluigi.recon_manager import ReconManager, ScheduledScanThread
from waluigi.data_model import ScheduledScan, ScanData
from types import SimpleNamespace
from unittest.mock import patch
from waluigi.scan_utils import get_port_byte_array
from tests.conftest import get_tool_id


class TestNmapScan:

    TOOL_NAME = 'nmap'
    TEST_SCAN_ID = format(uuid.uuid4().int, 'x')
    TEST_SCHEDULED_SCAN_ID = format(uuid.uuid4().int, 'x')

    def test_nmap_scan_success(self, recon_manager):

        tool_id_instance = get_tool_id(recon_manager, self.TOOL_NAME)
        scan_id = self.TEST_SCAN_ID
        scheduled_scan_id = self.TEST_SCHEDULED_SCAN_ID

        tool_inst = {'id': 'a9866b94f7104754bd161c1ab7cbf0cd', 'collection_tool': {'wordlists': [], 'name': self.TOOL_NAME, 'args':
                                                                                   '-sV --script +ssl-cert --script-args ssl=True', 'tool_type': 2, 'scan_order': 2, 'api_key': None, 'id': tool_id_instance}, 'args_override': None,
                     'enabled': 1, 'status': 0, 'status_message': None, 'collection_tool_id': tool_id_instance,
                     'scheduled_scan_id': scheduled_scan_id, 'owner_id': '94cb514e85da4abea6ee227730328619'}

        scheduler_inst_object = {
            "id": scheduled_scan_id,
            "scan_id": scan_id,
            "target_id": 1234,
            'collection_tools': [tool_inst], }

        data = json.dumps(scheduler_inst_object)
        sched_scan_arr = json.loads(
            data, object_hook=lambda d: SimpleNamespace(**d))

        port_list = "443"
        target_ip = 'www.securifera.com'
        port_bytes = get_port_byte_array(port_list)
        b64_ports = base64.b64encode(port_bytes).decode()
        scope = {'b64_port_bitmap': b64_ports,
                 'obj_list': [{'type': 'subnet', 'id': 'f57d93bcbe924127b24add0f5af04a62',
                              'data': {'subnet': target_ip, 'mask': 32}, 'tags': [3]}]}
        scan_data = {
            'scan_id': scan_id,
            'scope': scope,
        }

        scan_thread = ScheduledScanThread(recon_manager, None)
        with patch.object(ReconManager, 'get_scheduled_scan', return_value=scan_data):

            scheduled_scan_obj = ScheduledScan(scan_thread, sched_scan_arr)

            first_key = next(iter(scheduled_scan_obj.collection_tool_map))
            first_tool = scheduled_scan_obj.collection_tool_map[first_key]

            # Set the current tool
            scheduled_scan_obj.current_tool = first_tool.collection_tool
            if first_tool.args_override:
                scheduled_scan_obj.current_tool.args = first_tool.args_override

            result = recon_manager.scan_func(scheduled_scan_obj)
            assert result == True
            output_dir = "/tmp/%s" % scheduled_scan_id
            assert os.path.exists(output_dir) == True
            input_conf = "%s/%s-outputs/%s_in_0" % (
                output_dir, self.TOOL_NAME, self.TOOL_NAME)
            assert os.path.exists(input_conf) == True
            output_file = "%s/%s-outputs/%s_out_0" % (
                output_dir, self.TOOL_NAME, self.TOOL_NAME)
            assert os.path.exists(output_file) == True

            with open(input_conf, 'r') as f:
                file_contents = f.read()
                assert target_ip in file_contents

            with open(output_file, 'r') as f:
                file_contents = f.read()
                assert target_ip in file_contents

    def test_nmap_import_success(self, recon_manager):

        tool_id_instance = get_tool_id(recon_manager, self.TOOL_NAME)
        scan_id = self.TEST_SCAN_ID
        scheduled_scan_id = self.TEST_SCHEDULED_SCAN_ID

        tool_inst = {'id': 'a9866b94f7104754bd161c1ab7cbf0cd', 'collection_tool': {'wordlists': [], 'name': self.TOOL_NAME, 'args':
                                                                                   '-sV --script +ssl-cert --script-args ssl=True', 'tool_type': 2, 'scan_order': 2, 'api_key': None, 'id': tool_id_instance}, 'args_override': None,
                     'enabled': 1, 'status': 0, 'status_message': None, 'collection_tool_id': tool_id_instance,
                     'scheduled_scan_id': scheduled_scan_id, 'owner_id': '94cb514e85da4abea6ee227730328619'}

        scheduler_inst_object = {
            "id": scheduled_scan_id,
            "scan_id": scan_id,
            "target_id": 1234,
            'collection_tools': [tool_inst], }

        data = json.dumps(scheduler_inst_object)
        sched_scan_arr = json.loads(
            data, object_hook=lambda d: SimpleNamespace(**d))

        port_list = "443"
        target_ip = 'www.securifera.com'
        port_bytes = get_port_byte_array(port_list)
        b64_ports = base64.b64encode(port_bytes).decode()
        scope = {'b64_port_bitmap': b64_ports,
                 'obj_list': [{'type': 'subnet', 'id': 'f57d93bcbe924127b24add0f5af04a62',
                              'data': {'subnet': target_ip, 'mask': 32}, 'tags': [3]}]}
        scan_data = {
            'scan_id': scan_id,
            'scope': scope,
        }

        output_dir = "/tmp/%s" % scheduled_scan_id
        try:
            scan_thread = ScheduledScanThread(recon_manager, None)
            with patch.object(ReconManager, 'get_scheduled_scan', return_value=scan_data):

                scheduled_scan_obj = ScheduledScan(scan_thread, sched_scan_arr)
                first_key = next(iter(scheduled_scan_obj.collection_tool_map))
                first_tool = scheduled_scan_obj.collection_tool_map[first_key]

                # Set the current tool
                scheduled_scan_obj.current_tool = first_tool.collection_tool
                if first_tool.args_override:
                    scheduled_scan_obj.current_tool.args = first_tool.args_override

                with patch.object(ReconManager, 'import_data', return_value={}):
                    result = recon_manager.import_func(scheduled_scan_obj)
                    assert result == True
                    output_json = "%s/%s-outputs/tool_import_json" % (
                        output_dir, self.TOOL_NAME)
                    assert os.path.exists(output_json) == True

                    import_arr = []
                    with open(output_json, 'r') as import_fd:
                        for line in import_fd:
                            line = line.strip()
                            if not line:
                                continue
                            import_arr.extend(json.loads(line))

                    if import_arr:
                        # Create a ScanData object to hold the scan data
                        scan_data_obj = {'obj_list': import_arr}
                        scan_data = ScanData(scan_data_obj)

                        # Get host port map
                        port_map = scan_data.port_host_map
                        assert len(port_map) > 0
                        assert '443' in port_map

                        host_id_list = port_map['443']
                        assert len(host_id_list) > 0
                        host_id = list(host_id_list)[0]
                        assert len(scan_data.host_map) > 0
                        assert host_id in scan_data.host_map

                        host_obj = scan_data.host_map[host_id]
                        host_id = host_obj.id

                        assert host_id in scan_data.host_id_port_map
                        port_obj_list = scan_data.host_id_port_map[host_id]

                        assert len(port_obj_list) > 0
                        port_obj = port_obj_list[0]

                        assert port_obj.port == '443'
                        assert port_obj.secure == True

                        assert host_obj.ipv4_addr == '52.4.7.15'

                        assert host_id == port_obj.parent.id

                        # Get domain map
                        domain_map = scan_data.domain_map
                        first_domain = next(iter(domain_map.values()))
                        assert first_domain.name == target_ip

                        # Verify certificate
                        cert_map = scan_data.certificate_port_id_map
                        assert port_obj.id in cert_map

                        # Verify collection modules
                        assert len(scan_data.module_name_id_map) > 0
                        assert 'http-server-header' in scan_data.module_name_id_map
                        collection_module_obj_list = scan_data.module_name_id_map['http-server-header']
                        assert len(collection_module_obj_list) > 0

                        collection_module_obj_id = collection_module_obj_list[0].id
                        assert len(scan_data.module_output_module_id_map) > 0
                        assert collection_module_obj_id in scan_data.module_output_module_id_map
                        collection_module_output_obj_list = scan_data.module_output_module_id_map[
                            collection_module_obj_id]
                        assert len(collection_module_output_obj_list) > 0
                        collection_module_output_obj = collection_module_output_obj_list[0]
                        assert collection_module_output_obj.output == 'Apache'

        finally:
            # Cleanup
            if os.path.exists(output_dir):
                shutil.rmtree(output_dir)
            pass
