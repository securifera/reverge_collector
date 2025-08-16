import base64
import os
import shutil
from waluigi.recon_manager import ReconManager, ScheduledScanThread
from waluigi.data_model import ScheduledScan, ScanData
from types import SimpleNamespace
from unittest.mock import patch
from waluigi.scan_utils import get_port_byte_array
import json
import uuid
from tests.conftest import get_tool_id


class TestGauScan:

    TOOL_NAME = 'gau'
    TEST_SCAN_ID = format(uuid.uuid4().int, 'x')
    TEST_SCHEDULED_SCAN_ID = format(uuid.uuid4().int, 'x')

    def test_gau_scan_success(self, recon_manager):

        tool_id_instance = get_tool_id(recon_manager, self.TOOL_NAME)

        scan_id = self.TEST_SCAN_ID
        scheduled_scan_id = self.TEST_SCHEDULED_SCAN_ID
        tool_inst = {'id': 'a9866b94f7104754bd161c1ab7cbf0cd', 'collection_tool': {'wordlists': [], 'name': self.TOOL_NAME, 'args':
                                                                                   '', 'tool_type': 2, 'scan_order': 2, 'api_key': None, 'id': tool_id_instance}, 'args_override': None,
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

        port_list = "80"
        target_domain = 'securifera.com'
        port_bytes = get_port_byte_array(port_list)
        b64_ports = base64.b64encode(port_bytes).decode()
        scope = {'b64_port_bitmap': b64_ports,
                 'obj_list': [{'type': 'domain', 'id': 'fadf99076dcf42e6a21549d074560b42', 'data': {'name': target_domain}, 'tags': [3]}]}

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

            tool_name = scheduled_scan_obj.current_tool.name
            result = recon_manager.scan_func(scheduled_scan_obj)
            assert result == True
            output_dir = f"/tmp/{scheduled_scan_id}"
            assert os.path.exists(output_dir) == True
            # Check if output file exists
            output_file = f"{output_dir}/{tool_name}-outputs/{tool_name}_outputs_{scheduled_scan_id}.json"
            assert os.path.exists(output_file) == True

            # Check if target_ip is in the file contents of target_conf
            with open(output_file, 'r') as f:
                file_contents = f.read()
                assert 'securifera.com' in file_contents

    def test_gau_import_success(self, recon_manager):

        tool_id_instance = get_tool_id(recon_manager, self.TOOL_NAME)

        scan_id = self.TEST_SCAN_ID
        scheduled_scan_id = self.TEST_SCHEDULED_SCAN_ID
        tool_inst = {'id': 'a9866b94f7104754bd161c1ab7cbf0cd', 'collection_tool': {'wordlists': [], 'name': self.TOOL_NAME, 'args':
                                                                                   '', 'tool_type': 2, 'scan_order': 2, 'api_key': None, 'id': tool_id_instance}, 'args_override': None,
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

        port_list = "80"
        target_domain = 'securifera.com'
        port_bytes = get_port_byte_array(port_list)
        b64_ports = base64.b64encode(port_bytes).decode()
        scope = {'b64_port_bitmap': b64_ports,
                 'obj_list': [{'type': 'domain', 'id': 'fadf99076dcf42e6a21549d074560b42', 'data': {'name': target_domain}, 'tags': [3]}]}

        scan_data = {
            'scan_id': scan_id,
            'scope': scope,
        }

        output_dir = f"/tmp/{scheduled_scan_id}"
        try:
            scan_thread = ScheduledScanThread(recon_manager, None)
            with patch.object(ReconManager, 'get_scheduled_scan', return_value=scan_data):

                scheduled_scan_obj = ScheduledScan(scan_thread, sched_scan_arr)
                first_key = next(iter(scheduled_scan_obj.collection_tool_map))
                first_tool = scheduled_scan_obj.collection_tool_map[first_key]

                # Set the current tool
                scheduled_scan_obj.current_tool = first_tool.collection_tool
                tool_name = scheduled_scan_obj.current_tool.name
                if first_tool.args_override:
                    scheduled_scan_obj.current_tool.args = first_tool.args_override

                with patch.object(ReconManager, 'import_data', return_value={}):
                    result = recon_manager.import_func(scheduled_scan_obj)
                    assert result == True
                    output_json = f"{output_dir}/{tool_name}-outputs/tool_import_json"
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

                        # Get host map
                        host_map = scan_data.host_map
                        assert len(host_map) > 0
                        host_ips = [
                            host.ipv4_addr for host in host_map.values()]
                        assert '52.4.7.15' in host_ips

                        # Get domain map
                        domain_map = scan_data.domain_map
                        domain_list = [
                            domain.name for domain in domain_map.values()]
                        assert target_domain in domain_list

        finally:
            # Cleanup
            if os.path.exists(output_dir):
                shutil.rmtree(output_dir)
            pass
