import base64
import os
import shutil
from waluigi.recon_manager import ReconManager, ScheduledScanThread
from waluigi.data_model import ScheduledScan
from types import SimpleNamespace
from unittest.mock import patch
from waluigi.scan_utils import get_port_byte_array
import json


def test_httpx_success(recon_manager):

    scan_id = 'f35c684c61da412c8aaf7d386540f663'
    schedule_scan_id = 'f35c684c61da412c8aaf7d386540f664'
    tool_inst = {'id': 'a9866b94f7104754bd161c1ab7cbf0cd', 'collection_tool': {'wordlists': [], 'name': 'httpx', 'args':
                                                                               '', 'tool_type': 2, 'scan_order': 2, 'api_key': None, 'id': 'f35c684c61da412c8aaf7d386540f663'}, 'args_override': None,
                 'enabled': 1, 'status': 0, 'status_message': None, 'collection_tool_id': 'f35c684c61da412c8aaf7d386540f663',
                 'scheduled_scan_id': 'f00e34cffce546edb2701096fc66da65', 'owner_id': '94cb514e85da4abea6ee227730328619'}

    scheduler_inst_object = {
        "id": schedule_scan_id,
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

        result = recon_manager.scan_func(scheduled_scan_obj)
        assert result == True
        output_dir = "/tmp/%s" % schedule_scan_id
        assert os.path.exists(output_dir) == True
        input_conf = "%s/httpx-outputs/httpx_in_%s" % (output_dir, port_list)
        assert os.path.exists(input_conf) == True
        target_output = "%s/httpx-outputs/httpx_outputs_%s" % (
            output_dir, schedule_scan_id)
        assert os.path.exists(target_output) == True
        output_file = "%s/httpx-outputs/httpx_out_%s" % (output_dir, port_list)
        assert os.path.exists(output_file) == True

        with open(input_conf, 'r') as f:
            file_contents = f.read()
            assert target_domain in file_contents

        # Check if target_ip is in the file contents of target_conf
        with open(output_file, 'r') as f:
            file_contents = f.read()
            assert '52.4.7.15' in file_contents

        # Cleanup
        shutil.rmtree(output_dir)
