import base64
import os
import shutil
import json
import uuid
import logging
import time

from waluigi.recon_manager import ReconManager, ScheduledScanThread
from types import SimpleNamespace
from unittest.mock import patch
from waluigi.scan_utils import get_port_byte_array
from waluigi.data_model import ScanData, ScheduledScan
from tests.conftest import get_tool_id


class TestCrapsecretsScan:

    TOOL_NAME = 'crapsecrets'
    TEST_SCAN_ID = format(uuid.uuid4().int, 'x')
    TEST_SCHEDULED_SCAN_ID = format(uuid.uuid4().int, 'x')

    def test_crapsecrets_scan_base(self, recon_manager):


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

        port_list = '80'
        target_domain = 'update.microsoft.com'
        target_ip = '132.196.74.18'
        port_bytes = get_port_byte_array(port_list)
        b64_ports = base64.b64encode(port_bytes).decode()
        scope = {'b64_port_bitmap': b64_ports,
                 'obj_list': [{'type': 'port', 'id': 'c14918af17294944bf8db41f0ec1dc63', 'parent': {'type': 'host', 'id': 'eb45abca98834ad4a525dac9a6879141'}, 'data': {'port': 80, 'proto': 0, 'secure': 0}, 'tags': [3]}, {'type': 'domain', 'id': 'aa6775050f374f6f8b05fc2a94c5c629', 'parent': {'type': 'host', 'id': 'eb45abca98834ad4a525dac9a6879141'}, 'data': {'name': target_domain}, 'tags': [3]}, {'type': 'host', 'id': 'eb45abca98834ad4a525dac9a6879141', 'data': {'ipv4_addr': target_ip}, 'tags': [3]}]}
          
        scan_data = {
            'scan_id': scan_id,
            'scope': scope,
        }

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

                output_dir = "/tmp/%s" % scheduled_scan_id

                result = recon_manager.scan_func(scheduled_scan_obj)
                assert result == True
                assert os.path.exists(output_dir) == True
                
                output_file = "%s/%s-outputs/%s_outputs_%s.json" % (
                    output_dir, self.TOOL_NAME, self.TOOL_NAME, scheduled_scan_id)
                assert os.path.exists(output_file) == True

                with open(output_file, 'r') as f:
                    output_data = json.load(f)
                
                assert len(output_data['output_list']) > 0

        finally:
            # Cleanup
            if os.path.exists(output_dir):
                shutil.rmtree(output_dir)
            
    def test_crapsecrets_scan_success(self, recon_manager):

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

        port_list = '80'
        target_domain = 'update.microsoft.com'
        target_ip = '132.196.74.18'
        port_bytes = get_port_byte_array(port_list)
        b64_ports = base64.b64encode(port_bytes).decode()
        scope = {'b64_port_bitmap': b64_ports,
                 'obj_list': [{'type': 'port', 'id': 'c14918af17294944bf8db41f0ec1dc63', 'parent': {'type': 'host', 'id': 'eb45abca98834ad4a525dac9a6879141'}, 'data': {'port': 80, 'proto': 0, 'secure': 0}, 'tags': [3]}, {'type': 'domain', 'id': 'aa6775050f374f6f8b05fc2a94c5c629', 'parent': {'type': 'host', 'id': 'eb45abca98834ad4a525dac9a6879141'}, 'data': {'name': target_domain}, 'tags': [3]}, {'type': 'host', 'id': 'eb45abca98834ad4a525dac9a6879141', 'data': {'ipv4_addr': target_ip}, 'tags': [3]}]}
          
        scan_data = {
            'scan_id': scan_id,
            'scope': scope,
        }

        crap_secrets_response = {"port_id": "c14918af17294944bf8db41f0ec1dc63", "http_endpoint_id": None, "url": "http://192.168.110.131/", "custom_args": None, "output": {"target": "http://192.168.110.131/", "results": [{"detecting_module": "ASPNET_Viewstate", "product_type": "ASP.NET Viewstate", "product": "Viewstate: /wEPDwULLTEwNDcyMDA1MTQPZBYCAgMPZBYCZg8VATtSZWdpc3RyeUtleTogNC42LjIgLS0tIEVudmlyb25tZW50LlZlcnNpb246IDQuMC4zMDMxOS40MjAwMGRkjez32gk9qLoRFKNaUp+OdqsYYW4= Generator: CA0B0334", "secret_type": "ASP.NET MachineKey", "location": "body - URL: http://192.168.110.131/", "type": "SecretFound", "secret": "ValidationKey: [3DA7A917DF10B92A642434F1532E639C8EB81E8667289F2068A18B24DD8269AE7759FE23B3158EAC6955308D42B5B74CBD49CEDB3F3929D6C769DC4081CC1986] ValidationAlgo: [SHA1]", "severity": "CRITICAL", "details": "Mode: DotNetMode.DOTNET40_LEGACY\nURL: [http://192.168.110.131/]"}, {"detecting_module": "ASPNET_Resource", "product_type": "ASP.NET Resource", "product": "Resources: OMvcSUjTz2zWsB/tBOZcJg+Gghhv1MSHOS9t5HZMimKN/jdZT/tveHqCP6Ukevgccg7Inx6RdN7Alk0mhpIIiT/D/8c9gthPjS28OXcb5HB1blt5wdO4/QYf/U5o+iHGjwztTg==", "secret_type": "ASP.NET MachineKey", "location": "body - URL: http://192.168.110.131/", "type": "SecretFound", "secret": "ValidationKey: [3DA7A917DF10B92A642434F1532E639C8EB81E8667289F2068A18B24DD8269AE7759FE23B3158EAC6955308D42B5B74CBD49CEDB3F3929D6C769DC4081CC1986] ValidationAlgo: [SHA1 or 3DES or AES] EncryptionKey: [D0CC8D9BC98B9C36023B0DD7271FC8405E32007986A3D69C2CE716EED106BFA6] EncryptionAlgo: [AES]", "severity": "HIGH", "details": "Mode: DotNetMode.DOTNET40_LEGACY\nURL: [http://192.168.110.131/]"}]}}

        scan_thread = ScheduledScanThread(recon_manager, None)
        with patch.object(ReconManager, 'get_scheduled_scan', return_value=scan_data):

            with patch('waluigi.crapsecrets_scan.request_wrapper', return_value=crap_secrets_response):

                scheduled_scan_obj = ScheduledScan(scan_thread, sched_scan_arr)

                first_key = next(iter(scheduled_scan_obj.collection_tool_map))
                first_tool = scheduled_scan_obj.collection_tool_map[first_key]

                # Set the current tool
                scheduled_scan_obj.current_tool = first_tool.collection_tool
                if first_tool.args_override:
                    scheduled_scan_obj.current_tool.args = first_tool.args_override

                output_dir = "/tmp/%s" % scheduled_scan_id

                result = recon_manager.scan_func(scheduled_scan_obj)
                assert result == True
                assert os.path.exists(output_dir) == True
                
                output_file = "%s/%s-outputs/%s_outputs_%s.json" % (
                    output_dir, self.TOOL_NAME, self.TOOL_NAME, scheduled_scan_id)
                assert os.path.exists(output_file) == True

                with open(output_file, 'r') as f:
                    output_data = json.load(f)
                
                assert len(output_data['output_list']) > 0
            

    def test_crapsecrets_import_success(self, recon_manager):

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
                        scan_data = ScanData(scan_data_obj)

                        vulnerability_map = scan_data.vulnerability_map
                        assert len(vulnerability_map) > 0



        finally:
            # Cleanup
            if os.path.exists(output_dir):
                shutil.rmtree(output_dir)
