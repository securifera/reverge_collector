import base64
import logging
import os
import shutil
import time
import uuid
import json
from waluigi.metasploit_scan import Metasploit
from waluigi.recon_manager import ReconManager, ScheduledScanThread
from waluigi.data_model import ScheduledScan, ScanData
from types import SimpleNamespace
from unittest.mock import patch
from waluigi.scan_utils import get_port_byte_array
from tests.conftest import get_tool_id

TARGET_IP = '192.168.110.131'

# Simulated JSON RPC module.results response for auxiliary/scanner/smb/smb_ms17_010
# and auxiliary/scanner/dcerpc/endpoint_mapper.  The message text is parsed by
# ImportMetasploitOutput using the [prefix] IP:PORT - Message pattern.


def _make_mock_rpc_response(ip: str, port: str) -> dict:
    return {
        "jsonrpc": "2.0",
        "result": {
            "status": "completed",
            "result": {
                "message": (
                    f"[*] {ip}:{port} - Scanned 1 of 1 hosts\n"
                    f"[*] {ip}:{port} - Host is running Windows Server 2016 14393\n"
                    f"[+] {ip}:{port} - Host is likely VULNERABLE to MS17-010!\n"
                )
            }
        }
    }


def _mock_execute_msfrpc_commands(ip_list, module_path, output_file, **kwargs):
    """Patch for execute_msfrpc_commands — writes a mock JSON RPC result file."""
    # Derive port from module path (e.g. smb_ms17_010 → 445, endpoint_mapper → 135)
    port_map = {
        'auxiliary/scanner/smb/smb_ms17_010': '445',
        'auxiliary/scanner/dcerpc/endpoint_mapper': '135',
        'auxiliary/scanner/ftp/ftp_version': '21',
        'auxiliary/scanner/ssh/ssh_version': '22',
        'auxiliary/scanner/nfs/nfsmount': '111',
        'auxiliary/scanner/ldap/ldap_search': '389',
        'auxiliary/scanner/mysql/mysql_version': '3306',
        'auxiliary/scanner/rdp/rdp_scanner': '3389',
        'auxiliary/scanner/vnc/vnc_none_auth': '5900',
        'auxiliary/scanner/winrm/winrm_enum_users': '5985',
    }
    port = port_map.get(module_path, '445')
    # Strip CIDR notation if the IP was passed as a subnet string (e.g. "1.2.3.4/32")
    raw_ip = ip_list[0] if ip_list else TARGET_IP
    ip = raw_ip.split('/')[0]
    response = _make_mock_rpc_response(ip, port)
    with open(output_file, 'w') as f:
        json.dump(response, f)
    return response


class TestMetasploitScan:

    TOOL_NAME = 'metasploit'
    TEST_SCAN_ID = format(uuid.uuid4().int, 'x')
    TEST_SCHEDULED_SCAN_ID = format(uuid.uuid4().int, 'x')

    def _make_scan_objects(self, recon_manager, port_list="135, 445", args=""):
        tool_id_instance = get_tool_id(recon_manager, self.TOOL_NAME)
        scan_id = self.TEST_SCAN_ID
        scheduled_scan_id = self.TEST_SCHEDULED_SCAN_ID

        tool_inst = {
            'id': 'a9866b94f7104754bd161c1ab7cbf0cd',
            'collection_tool': {
                'wordlists': [], 'name': self.TOOL_NAME, 'args': args,
                'tool_type': 2, 'scan_order': 2, 'api_key': None,
                'id': tool_id_instance,
            },
            'args_override': None,
            'enabled': 1, 'status': 0, 'status_message': None,
            'collection_tool_id': tool_id_instance,
            'scheduled_scan_id': scheduled_scan_id,
            'owner_id': '94cb514e85da4abea6ee227730328619',
        }
        scheduler_inst_object = {
            "id": scheduled_scan_id,
            "scan_id": scan_id,
            "target_id": 1234,
            'collection_tools': [tool_inst],
        }
        sched_scan_arr = json.loads(
            json.dumps(scheduler_inst_object),
            object_hook=lambda d: SimpleNamespace(**d))

        port_bytes = get_port_byte_array(port_list)
        b64_ports = base64.b64encode(port_bytes).decode()
        scope = {
            'b64_port_bitmap': b64_ports,
            'obj_list': [{
                'type': 'subnet',
                'id': 'f57d93bcbe924127b24add0f5af04a62',
                'data': {'subnet': TARGET_IP, 'mask': 32},
                'tags': [3],
            }],
        }
        scan_data = {'scan_id': scan_id, 'scope': scope}
        return sched_scan_arr, scan_data

    def test_metasploit_scan_success(self, recon_manager):
        sched_scan_arr, scan_data = self._make_scan_objects(recon_manager)
        scheduled_scan_id = self.TEST_SCHEDULED_SCAN_ID

        scan_thread = ScheduledScanThread(recon_manager, None)
        with patch.object(ReconManager, 'get_scheduled_scan', return_value=scan_data), \
            patch('waluigi.metasploit_scan.execute_msfrpc_commands',
                  side_effect=_mock_execute_msfrpc_commands):

            scheduled_scan_obj = ScheduledScan(scan_thread, sched_scan_arr)
            first_key = next(iter(scheduled_scan_obj.collection_tool_map))
            first_tool = scheduled_scan_obj.collection_tool_map[first_key]
            scheduled_scan_obj.current_tool = first_tool.collection_tool
            if first_tool.args_override:
                scheduled_scan_obj.current_tool.args = first_tool.args_override

            result = recon_manager.scan_func(scheduled_scan_obj)

            assert result == True
            output_dir = "/tmp/%s" % scheduled_scan_id
            assert os.path.exists(output_dir) == True

            # Verify input (IP list) and output files were created for at least one module
            input_conf = "%s/%s-outputs/%s_in_0" % (
                output_dir, self.TOOL_NAME, self.TOOL_NAME)
            assert os.path.exists(input_conf) == True
            output_file = "%s/%s-outputs/%s_out_0" % (
                output_dir, self.TOOL_NAME, self.TOOL_NAME)
            assert os.path.exists(output_file) == True

            with open(input_conf, 'r') as f:
                # Input file contains the subnet (may include CIDR notation)
                assert '192.168.110.131' in f.read()

            with open(output_file, 'r') as f:
                assert TARGET_IP in f.read()

    def test_metasploit_import_success(self, recon_manager):
        sched_scan_arr, scan_data = self._make_scan_objects(recon_manager)
        scheduled_scan_id = self.TEST_SCHEDULED_SCAN_ID
        output_dir = "/tmp/%s" % scheduled_scan_id

        try:
            scan_thread = ScheduledScanThread(recon_manager, None)
            with patch.object(ReconManager, 'get_scheduled_scan', return_value=scan_data), \
                    patch('waluigi.metasploit_scan.execute_msfrpc_commands',
                          side_effect=_mock_execute_msfrpc_commands), \
                    patch.object(ReconManager, 'import_data', return_value={}):

                scheduled_scan_obj = ScheduledScan(scan_thread, sched_scan_arr)
                first_key = next(iter(scheduled_scan_obj.collection_tool_map))
                first_tool = scheduled_scan_obj.collection_tool_map[first_key]
                scheduled_scan_obj.current_tool = first_tool.collection_tool
                if first_tool.args_override:
                    scheduled_scan_obj.current_tool.args = first_tool.args_override

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

                assert len(import_arr) > 0, "Import produced no data objects"

                scan_data_obj = {'obj_list': import_arr}
                imported = ScanData(scan_data_obj)

                port_map = imported.port_host_map
                assert len(port_map) > 0
                assert '445' in port_map

                host_id_list = port_map['445']
                assert len(host_id_list) > 0
                host_id = list(host_id_list)[0]
                assert host_id in imported.host_map

                host_obj = imported.host_map[host_id]
                assert host_obj.ipv4_addr == TARGET_IP

                assert host_id in imported.host_id_port_map
                port_obj_list = imported.host_id_port_map[host_id]
                assert len(port_obj_list) > 0

                port_obj = next(p for p in port_obj_list if p.port == '445')
                assert port_obj.port == '445'
                assert port_obj.parent.id == host_id

        finally:
            if os.path.exists(output_dir):
                shutil.rmtree(output_dir)

    def test_get_modules_success(self, recon_manager):
        """metasploit_modules() returns a list (may be empty — no live server needed)."""
        modules = Metasploit.metasploit_modules()
        assert isinstance(modules, list)
