import base64
import logging
import os
import shutil
import json
import uuid
from waluigi.recon_manager import ReconManager, ScheduledScanThread
from waluigi.data_model import ScheduledScan, ScanData
from types import SimpleNamespace
from unittest.mock import patch
from waluigi.scan_utils import get_port_byte_array
from tests.conftest import get_tool_id


class TestFeroxbusterScan:

    TOOL_NAME = 'feroxbuster'
    TEST_SCAN_ID = format(uuid.uuid4().int, 'x')
    TEST_SCHEDULED_SCAN_ID = format(uuid.uuid4().int, 'x')

    def test_feroxbuster_scan_success(self, recon_manager):

        tool_id_instance = get_tool_id(recon_manager, self.TOOL_NAME)

        scan_id = self.TEST_SCAN_ID
        scheduled_scan_id = self.TEST_SCHEDULED_SCAN_ID
        wordlist_inst = {'id': 'a9866b94f7104754bd161c1ab7cbf0cd',
                         'hash': 'c9c8c6152751b78c6bfa078a5a33a29edae2e7bdf4cd71dfeb8631c0229e2b23'}
        tool_inst = {'id': 'a9866b94f7104754bd161c1ab7cbf0cd', 'collection_tool': {'wordlists': [wordlist_inst], 'name': self.TOOL_NAME, 'args':
                                                                                   '--rate-limit 50 -s 200 -n', 'tool_type': 2, 'scan_order': 2, 'api_key': None, 'id': tool_id_instance}, 'args_override': None,
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

        wordlist_data = {'hash': 'c9c8c6152751b78c6bfa078a5a33a29edae2e7bdf4cd71dfeb8631c0229e2b23', 'words': [
            '/', '/__includes'], }
        scan_thread = ScheduledScanThread(recon_manager, None)
        with patch.object(ReconManager, 'get_scheduled_scan', return_value=scan_data):
            with patch.object(ReconManager, 'get_wordlist', return_value=wordlist_data):

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

                target_output = "%s/%s-outputs/ferox_outputs_%s" % (
                    output_dir, self.TOOL_NAME, scheduled_scan_id)
                assert os.path.exists(target_output) == True

                # Check if target_ip is in the file contents of target_conf
                with open(target_output, 'r') as f:
                    file_contents = f.read()
                    assert len(file_contents) > 0
                    scan_data_dict = json.loads(file_contents)

                    # Get data and map
                    url_to_id_map = scan_data_dict['url_to_id_map']
                    for url_str in url_to_id_map:

                        obj_data = url_to_id_map[url_str]
                        output_file = obj_data['output_file']
                        assert os.path.exists(output_file) == True
                        with open(output_file, 'r') as f:
                            file_contents = f.read()
                            assert len(file_contents) > 0

    def test_feroxbuster_import_success(self, recon_manager):

        tool_id_instance = get_tool_id(recon_manager, self.TOOL_NAME)

        scan_id = self.TEST_SCAN_ID
        scheduled_scan_id = self.TEST_SCHEDULED_SCAN_ID
        wordlist_inst = {'id': 'a9866b94f7104754bd161c1ab7cbf0cd',
                         'hash': 'c9c8c6152751b78c6bfa078a5a33a29edae2e7bdf4cd71dfeb8631c0229e2b23'}
        tool_inst = {'id': 'a9866b94f7104754bd161c1ab7cbf0cd', 'collection_tool': {'wordlists': [wordlist_inst], 'name': self.TOOL_NAME, 'args':
                                                                                   '--rate-limit 50 -s 200 -n', 'tool_type': 2, 'scan_order': 2, 'api_key': None, 'id': tool_id_instance}, 'args_override': None,
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

        wordlist_data = {'hash': 'c9c8c6152751b78c6bfa078a5a33a29edae2e7bdf4cd71dfeb8631c0229e2b23', 'words': [
            '/', '/__includes'], }
        output_dir = "/tmp/%s" % scheduled_scan_id
        try:
            scan_thread = ScheduledScanThread(recon_manager, None)
            with patch.object(ReconManager, 'get_scheduled_scan', return_value=scan_data):
                with patch.object(ReconManager, 'get_wordlist', return_value=wordlist_data):

                    scheduled_scan_obj = ScheduledScan(
                        scan_thread, sched_scan_arr)
                    first_key = next(
                        iter(scheduled_scan_obj.collection_tool_map))
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

                            http_endpoint_map = scan_data.http_endpoint_map
                            assert len(http_endpoint_map) > 0

                            # Get http endpoint data map
                            http_endpoint_data_map = scan_data.http_endpoint_data_map
                            for http_endpoint_data_inst in http_endpoint_data_map.values():
                                if http_endpoint_data_inst.domain_id:
                                    assert http_endpoint_data_inst.parent.id in http_endpoint_map

                            path_map = scan_data.path_map
                            path_list = [
                                path_obj.web_path for path_obj in path_map.values()]
                            assert "/" in path_list

        finally:
            # Cleanup
            if os.path.exists(output_dir):
                shutil.rmtree(output_dir)
            pass
