import base64
import os
import shutil
from waluigi.recon_manager import ReconManager, ScheduledScanThread
from waluigi.data_model import ScheduledScan, ScanData
from types import SimpleNamespace
from unittest.mock import patch
from waluigi.scan_utils import get_port_byte_array
import json


def test_pyshot_scan_success(recon_manager):

    scan_id = 'f35c684c61da412c8aaf7d386540f666'
    scheduled_scan_id = 'f35c684c61da412c8aaf7d386540f663'
    tool_inst = {'id': 'a9866b94f7104754bd161c1ab7cbf0cd', 'collection_tool': {'wordlists': [], 'name': 'pyshot', 'args':
                                                                               '', 'tool_type': 2, 'scan_order': 2, 'api_key': None, 'id': 'f35c684c61da412c8aaf7d386540f666'}, 'args_override': None,
                 'enabled': 1, 'status': 0, 'status_message': None, 'collection_tool_id': 'f35c684c61da412c8aaf7d386540f666',
                 'scheduled_scan_id': 'f00e34cffce546edb2701096fc66da65', 'owner_id': '94cb514e85da4abea6ee227730328619'}

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

        result = recon_manager.scan_func(scheduled_scan_obj)
        assert result == True
        output_dir = "/tmp/%s" % scheduled_scan_id
        assert os.path.exists(output_dir) == True
        input_conf = "%s/pyshot-outputs/screenshots.meta" % (output_dir)
        assert os.path.exists(input_conf) == True

        with open(input_conf, 'r') as f:
            file_contents = f.read()
            assert target_ip in file_contents

        with open(input_conf, 'r') as f:
            file_contents = f.read()
            assert target_domain in file_contents


def test_pyshot_import_success(recon_manager):

    scan_id = 'f35c684c61da412c8aaf7d386540f666'
    scheduled_scan_id = 'f35c684c61da412c8aaf7d386540f663'
    tool_inst = {'id': 'a9866b94f7104754bd161c1ab7cbf0cd', 'collection_tool': {'wordlists': [], 'name': 'pyshot', 'args':
                                                                               '', 'tool_type': 2, 'scan_order': 2, 'api_key': None, 'id': 'f35c684c61da412c8aaf7d386540f666'}, 'args_override': None,
                 'enabled': 1, 'status': 0, 'status_message': None, 'collection_tool_id': 'f35c684c61da412c8aaf7d386540f666',
                 'scheduled_scan_id': 'f00e34cffce546edb2701096fc66da65', 'owner_id': '94cb514e85da4abea6ee227730328619'}

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
                output_json = "%s/pyshot-outputs/tool_import_json" % (
                    output_dir)
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

                    # Get domain map
                    domain_map = scan_data.domain_map
                    first_domain = next(iter(domain_map.values()))
                    assert first_domain.name == target_domain

                    # Get screenshot map
                    screenshot_map = scan_data.screenshot_map
                    for screenshot_inst in screenshot_map.values():
                        assert screenshot_inst.screenshot is not None
                        assert len(screenshot_inst.screenshot) > 0
                        assert screenshot_inst.image_hash is not None

                    http_endpoint_map = scan_data.http_endpoint_map
                    assert len(http_endpoint_map) > 0

                    # Get http endpoint data map
                    http_endpoint_data_map = scan_data.http_endpoint_data_map
                    for http_endpoint_data_inst in http_endpoint_data_map.values():
                        if http_endpoint_data_inst.domain_id:
                            assert http_endpoint_data_inst.parent.id in http_endpoint_map
                            assert http_endpoint_data_inst.domain_id in domain_map
                            assert http_endpoint_data_inst.screenshot_id in screenshot_map

                    path_map = scan_data.path_map
                    first_path = next(iter(path_map.values()))
                    assert first_path.web_path == "/"

    finally:
        # Cleanup
        if os.path.exists(output_dir):
            shutil.rmtree(output_dir)
