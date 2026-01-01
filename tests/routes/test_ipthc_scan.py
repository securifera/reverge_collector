import base64
import logging
import os
import shutil
import json
import uuid

from waluigi.recon_manager import ReconManager, ScheduledScanThread
from types import SimpleNamespace
from unittest.mock import patch
from waluigi.scan_utils import get_port_byte_array
from waluigi.data_model import ScanData, ScheduledScan, ImportToolXOutput
from tests.conftest import get_tool_id


class TestIpthcScan:

    TOOL_NAME = 'ipthc'
    TEST_SCAN_ID = format(uuid.uuid4().int, 'x')
    TEST_SCHEDULED_SCAN_ID = format(uuid.uuid4().int, 'x')

    def test_ipthc_ip_scan_success(self, recon_manager):

        tool_id_instance = get_tool_id(recon_manager, self.TOOL_NAME)
        scan_id = self.TEST_SCAN_ID
        scheduled_scan_id = self.TEST_SCHEDULED_SCAN_ID
        tool_inst = {'id': 'a9866b94f7104754bd161c1ab7cbf0cd', 'api_key': 'test', 'collection_tool': {'wordlists': [], 'name': self.TOOL_NAME, 'args':
                                                                                                      '', 'tool_type': 1, 'scan_order': 1,
                                                                                                      'id': tool_id_instance}, 'args_override': None,
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
            with patch.object(ImportToolXOutput, 'import_results', return_value=None):

                result = recon_manager.import_func(scheduled_scan_obj)
                assert result == True
                output_dir = "/tmp/%s" % scheduled_scan_id
                assert os.path.exists(output_dir) == True

                output_file = "%s/%s-outputs/ip-thc-ip-lookup-outputs-%s" % (
                    output_dir, self.TOOL_NAME, scheduled_scan_id)
                assert os.path.exists(output_file) == True

                # Check if target_ip is in the file contents of target_conf
                with open(output_file, 'r') as f:
                    file_contents = f.read()
                    # logging.getLogger(__name__).warning(
                    #    f"Result map: {file_contents}")
                    json_obj = json.loads(file_contents)
                    assert 'ip_to_host_dict_map' in json_obj
                    ip_map = json_obj['ip_to_host_dict_map']
                    assert target_ip in ip_map
                    ip_obj = ip_map[target_ip]
                    assert 'domains' in ip_obj and target_domain in ip_obj['domains']

    def test_ipthc_import_ip_success(self, recon_manager):

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
                        logging.getLogger(__name__).warning(
                            f"Result map: {import_arr}")
                        scan_data = ScanData(scan_data_obj)

                        # Get domain map
                        domain_map = scan_data.domain_map
                        domain_list = [
                            domain.name for domain in domain_map.values()]
                        assert target_domain in domain_list

        finally:
            # Cleanup
            if os.path.exists(output_dir):
                shutil.rmtree(output_dir)

    def test_ipthc_subnet_scan_success(self, recon_manager):

        tool_id_instance = get_tool_id(recon_manager, self.TOOL_NAME)
        scan_id = self.TEST_SCAN_ID
        scheduled_scan_id = self.TEST_SCHEDULED_SCAN_ID
        tool_inst = {'id': 'a9866b94f7104754bd161c1ab7cbf0cd', 'api_key': 'test', 'collection_tool': {'wordlists': [], 'name': self.TOOL_NAME, 'args':
                                                                                                      '', 'tool_type': 1, 'scan_order': 1,
                                                                                                      'id': tool_id_instance}, 'args_override': None,
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
                 'obj_list': [{'type': 'subnet', 'id': 'f57d93bcbe924127b24add0f5af04a62',
                              'data': {'subnet': target_ip, 'mask': 24}, 'tags': [3]}]}
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
            with patch.object(ImportToolXOutput, 'import_results', return_value=None):

                result = recon_manager.import_func(scheduled_scan_obj)
                assert result == True
                output_dir = "/tmp/%s" % scheduled_scan_id
                assert os.path.exists(output_dir) == True

                output_file = "%s/%s-outputs/ip-thc-ip-lookup-outputs-%s" % (
                    output_dir, self.TOOL_NAME, scheduled_scan_id)
                assert os.path.exists(output_file) == True

                # Check if target_ip is in the file contents of target_conf
                with open(output_file, 'r') as f:
                    file_contents = f.read()
                    logging.getLogger(__name__).warning(
                        f"Result map: {file_contents}")
                    json_obj = json.loads(file_contents)
                    assert 'ip_to_host_dict_map' in json_obj
                    ip_map = json_obj['ip_to_host_dict_map']
                    assert target_ip in ip_map
                    ip_obj = ip_map[target_ip]
                    assert 'domains' in ip_obj and target_domain in ip_obj['domains']

    def test_ipthc_subnet_import_success(self, recon_manager):

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
                        # logging.getLogger(__name__).warning(
                        #    f"Result map: {import_arr}")
                        scan_data = ScanData(scan_data_obj)
                        # Get host map
                        host_map = scan_data.host_map
                        assert len(host_map) > 0
                        host_ips = [
                            host.ipv4_addr for host in host_map.values()]
                        assert target_ip in host_ips

                        # Get domain map
                        domain_map = scan_data.domain_map
                        domain_list = [
                            domain.name for domain in domain_map.values()]
                        assert target_domain in domain_list
        finally:
            # Cleanup
            if os.path.exists(output_dir):
                shutil.rmtree(output_dir)

    def test_ipthc_domain_scan_success(self, recon_manager):

        tool_id_instance = get_tool_id(recon_manager, self.TOOL_NAME)
        scan_id = self.TEST_SCAN_ID
        scheduled_scan_id = self.TEST_SCHEDULED_SCAN_ID
        tool_inst = {'id': 'a9866b94f7104754bd161c1ab7cbf0cd', 'api_key': 'test', 'collection_tool': {'wordlists': [], 'name': self.TOOL_NAME, 'args':
                                                                                                      '', 'tool_type': 1, 'scan_order': 1,
                                                                                                      'id': tool_id_instance}, 'args_override': None,
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
        target_domain = 'securifera.com'
        target_ip = '52.4.7.15'
        port_bytes = get_port_byte_array(port_list)
        b64_ports = base64.b64encode(port_bytes).decode()
        scope = {'b64_port_bitmap': b64_ports,
                 'obj_list': [{'type': 'domain', 'id': 'aa6775050f374f6f8b05fc2a94c5c629', 'parent': {'type': 'host', 'id': None}, 'data': {'name': target_domain}, 'tags': [3]}]}
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
            with patch.object(ImportToolXOutput, 'import_results', return_value=None):

                result = recon_manager.import_func(scheduled_scan_obj)
                assert result == True
                output_dir = "/tmp/%s" % scheduled_scan_id
                assert os.path.exists(output_dir) == True

                output_file = "%s/%s-outputs/ip-thc-ip-lookup-outputs-%s" % (
                    output_dir, self.TOOL_NAME, scheduled_scan_id)
                assert os.path.exists(output_file) == True

                # Check if target_ip is in the file contents of target_conf
                with open(output_file, 'r') as f:
                    file_contents = f.read()
                    # logging.getLogger(__name__).warning(
                    #    f"Result map: {file_contents}")
                    json_obj = json.loads(file_contents)
                    assert 'ip_to_host_dict_map' in json_obj
                    ip_map = json_obj['ip_to_host_dict_map']
                    assert target_ip in ip_map
                    ip_obj = ip_map[target_ip]
                    assert 'domains' in ip_obj and target_domain in ip_obj['domains']

    def test_ipthc_import_domain_success(self, recon_manager):

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

        port_list = '443'
        target_domain = 'www.securifera.com'
        target_ip = '52.4.7.15'
        port_bytes = get_port_byte_array(port_list)
        b64_ports = base64.b64encode(port_bytes).decode()
        scope = {'b64_port_bitmap': b64_ports,
                 'obj_list': [{'type': 'domain', 'id': 'aa6775050f374f6f8b05fc2a94c5c629', 'parent': {'type': 'host', 'id': None}, 'data': {'name': target_domain}, 'tags': [3]}]}
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
                        # logging.getLogger(__name__).warning(
                        #    f"Result map: {import_arr}")
                        scan_data = ScanData(scan_data_obj)
                        host_map = scan_data.host_map
                        assert len(host_map) > 0
                        host_ips = [
                            host.ipv4_addr for host in host_map.values()]
                        assert target_ip in host_ips

                        # Get domain map
                        domain_map = scan_data.domain_map
                        domain_list = [
                            domain.name for domain in domain_map.values()]
                        assert target_domain in domain_list

        finally:
            # Cleanup
            if os.path.exists(output_dir):
                shutil.rmtree(output_dir)
