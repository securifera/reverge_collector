import base64
import logging
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


class TestIISShortScan:

    TOOL_NAME = 'iis_short_scan'
    TEST_SCAN_ID = format(uuid.uuid4().int, 'x')
    TEST_SCHEDULED_SCAN_ID = format(uuid.uuid4().int, 'x')

    def test_iis_short_scan_success(self, recon_manager):

        tool_id_instance = get_tool_id(recon_manager, self.TOOL_NAME)

        scan_id = self.TEST_SCAN_ID
        scheduled_scan_id = self.TEST_SCHEDULED_SCAN_ID
        tool_inst = {'id': 'a9866b94f7104754bd161c1ab7cbf0cd', 'collection_tool': {'wordlists': [], 'name': self.TOOL_NAME, 'args':
                                                                                   'print("Testing")', 'tool_type': 2, 'scan_order': 10, 'api_key': None, 'id': tool_id_instance}, 'args_override': None,
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

        port_list = '443'
        target_domain = 'www.securifera.com'
        target_ip = '52.4.7.15'
        port_bytes = get_port_byte_array(port_list)
        b64_ports = base64.b64encode(port_bytes).decode()
        scope = {'b64_port_bitmap': b64_ports,
                 'obj_list': [{'type': 'port', 'id': 'c14918af17294944bf8db41f0ec1dc63', 'parent': {'type': 'host', 'id': 'eb45abca98834ad4a525dac9a6879141'}, 'data': {'port': 443, 'proto': 0, 'secure': 1}, 'tags': [3]}, {'type': 'domain', 'id': 'aa6775050f374f6f8b05fc2a94c5c629', 'parent': {'type': 'host', 'id': 'eb45abca98834ad4a525dac9a6879141'}, 'data': {'name': target_domain}, 'tags': [3]}, {'type': 'host', 'id': 'eb45abca98834ad4a525dac9a6879141', 'data': {'ipv4_addr': target_ip}, 'tags': [3]}]}
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
            output_file = f"{output_dir}/{tool_name}-outputs/{tool_name}_outputs_{scheduled_scan_id}"
            assert os.path.exists(output_file) == True

            # Check if target_ip is in the file contents of target_conf
            with open(output_file, 'r') as f:
                file_contents = f.read()
                result_map = json.loads(file_contents)

                assert isinstance(result_map, dict) and len(result_map) > 0
                port_entry_list = next(iter(result_map.values()))

                logging.getLogger(__name__).warning(
                    f"Result map: {port_entry_list}")

                assert port_entry_list[0]['target'] == "https://www.securifera.com" or port_entry_list[0]['target'] == "https://52.4.7.15"
                assert port_entry_list[0]['vulnerable'] == False

    def test_iis_short_scan_import_success(self, recon_manager):

        tool_id_instance = get_tool_id(recon_manager, self.TOOL_NAME)

        scan_id = self.TEST_SCAN_ID
        scheduled_scan_id = self.TEST_SCHEDULED_SCAN_ID
        tool_inst = {'id': 'a9866b94f7104754bd161c1ab7cbf0cd', 'collection_tool': {'wordlists': [], 'name': self.TOOL_NAME, 'args':
                                                                                   'print("Testing")', 'tool_type': 2, 'scan_order': 2, 'api_key': None, 'id': tool_id_instance}, 'args_override': None,
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

        port_list = '443'
        target_domain = 'www.securifera.com'
        target_ip = '52.4.7.15'
        port_bytes = get_port_byte_array(port_list)
        b64_ports = base64.b64encode(port_bytes).decode()
        scope = {'b64_port_bitmap': b64_ports,
                 'obj_list': [{'type': 'port', 'id': 'c14918af17294944bf8db41f0ec1dc63', 'parent': {'type': 'host', 'id': 'eb45abca98834ad4a525dac9a6879141'}, 'data': {'port': 443, 'proto': 0, 'secure': 1}, 'tags': [3]}, {'type': 'domain', 'id': 'aa6775050f374f6f8b05fc2a94c5c629', 'parent': {'type': 'host', 'id': 'eb45abca98834ad4a525dac9a6879141'}, 'data': {'name': target_domain}, 'tags': [3]}, {'type': 'host', 'id': 'eb45abca98834ad4a525dac9a6879141', 'data': {'ipv4_addr': target_ip}, 'tags': [3]}]}
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
                        collection_module_map = scan_data.collection_module_map
                        assert len(collection_module_map) > 0
                        module_names = [
                            module.name for module in collection_module_map.values()]
                        assert 'iis-shortname-scan' in module_names

                        # Get domain map
                        collection_module_output_map = scan_data.collection_module_output_map
                        output_list = [
                            module_output.output for module_output in collection_module_output_map.values()]
                        assert 'https://www.securifera.com' in str(output_list)

        finally:
            # Cleanup
            if os.path.exists(output_dir):
                shutil.rmtree(output_dir)
            pass
