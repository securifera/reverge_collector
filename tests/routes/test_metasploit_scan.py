import base64
import logging
import os
import shutil
import time
import uuid
import json
from reverge_collector.metasploit_scan import Metasploit
from reverge_collector.recon_manager import ReconManager, ScheduledScanThread
from reverge_collector.data_model import ScheduledScan, ScanData
from types import SimpleNamespace
from unittest.mock import patch, MagicMock
from reverge_collector.scan_utils import get_port_byte_array
from tests.conftest import get_tool_id

# ---------------------------------------------------------------------------
# Realistic module.search RPC responses used by description-parsing tests
# ---------------------------------------------------------------------------

# module.search responses — these return only names/fullnames, no description
MSF_SEARCH_AUXILIARY_RESPONSE = {
    "jsonrpc": "2.0", "id": "test-id-1",
    "result": [
        {"fullname": "auxiliary/scanner/smb/smb_ms17_010",
            "name": "smb_ms17_010", "type": "auxiliary", "rank": 300},
        {"fullname": "auxiliary/scanner/ssh/ssh_version",
            "name": "ssh_version", "type": "auxiliary", "rank": 300},
    ],
}
MSF_SEARCH_EXPLOIT_RESPONSE = {
    "jsonrpc": "2.0", "id": "test-id-2",
    "result": [
        {"fullname": "exploit/windows/smb/ms17_010_eternalblue",
            "name": "ms17_010_eternalblue", "type": "exploit", "rank": 700},
    ],
}

# module.info responses — these DO include the description
# Shared options blocks used across info fixture entries.
# RHOSTS/RPORT are present but should be excluded from module.args.
_OPT_RHOSTS = {"type": "rhosts", "required": True,
               "advanced": False, "desc": "Target host(s)"}
_OPT_RPORT_445 = {"type": "port", "required": True,
                  "advanced": False, "desc": "SMB port", "default": 445}
_OPT_RPORT_22 = {"type": "port", "required": True,
                 "advanced": False, "desc": "SSH port", "default": 22}
# A required non-auto option with no default — should appear in module.args
_OPT_DOMAIN = {"type": "string", "required": True,
               "advanced": False, "desc": "Target domain"}
# A required option that has a default — should NOT appear in module.args
_OPT_THREADS = {"type": "integer", "required": True,
                "advanced": False, "desc": "Threads", "default": 1}
# An advanced required option — should NOT appear in module.args
_OPT_VERBOSE = {"type": "bool", "required": False,
                "advanced": True, "desc": "Verbose", "default": False}

MSF_INFO_RESPONSES = {
    ("auxiliary", "scanner/smb/smb_ms17_010"): {
        "fullname": "auxiliary/scanner/smb/smb_ms17_010",
        "name": "smb_ms17_010",
        "description": (
            "Uses information disclosure to determine if MS17-010 has been "
            "patched or not. Specifically, it connects to the IPC$ tree and "
            "attempts a transaction on FID 0."
        ),
        # RHOSTS + RPORT excluded; DOMAIN is a required non-default non-auto opt
        "options": {
            "RHOSTS": _OPT_RHOSTS,
            "RPORT": _OPT_RPORT_445,
            "DOMAIN": _OPT_DOMAIN,
            "THREADS": _OPT_THREADS,
            "VERBOSE": _OPT_VERBOSE,
        },
    },
    ("auxiliary", "scanner/ssh/ssh_version"): {
        "fullname": "auxiliary/scanner/ssh/ssh_version",
        "name": "ssh_version",
        "description": "Detect SSH Version.",
        # Only auto-populated opts — args should be empty
        "options": {
            "RHOSTS": _OPT_RHOSTS,
            "RPORT": _OPT_RPORT_22,
        },
    },
    ("exploit", "windows/smb/ms17_010_eternalblue"): {
        "fullname": "exploit/windows/smb/ms17_010_eternalblue",
        "name": "ms17_010_eternalblue",
        "description": (
            "This module is a port of the Equation Group ETERNALBLUE exploit, "
            "part of the FuzzBunch toolkit released by Shadow Brokers."
        ),
        # No extra required non-auto opts
        "options": {
            "RHOSTS": _OPT_RHOSTS,
            "RPORT": _OPT_RPORT_445,
        },
    },
}

# module.search with a single entry that has no module.info description
MSF_SEARCH_NO_DESCRIPTION_RESPONSE = {
    "jsonrpc": "2.0", "id": "test-id-3",
    "result": [
        {"fullname": "auxiliary/scanner/ftp/ftp_version",
            "name": "ftp_version", "type": "auxiliary", "rank": 300},
    ],
}

TARGET_IP = '192.168.110.131'

# Simulated console output for auxiliary/scanner/smb/smb_ms17_010.
# The text is parsed by ImportMetasploitOutput using the [prefix] IP:PORT - Message pattern.


def _make_mock_console_output(ip: str, port: str) -> str:
    return (
        f"[*] {ip}:{port} - Scanned 1 of 1 hosts\n"
        f"[*] {ip}:{port} - Host is running Windows Server 2016 14393\n"
        f"[+] {ip}:{port} - Host is likely VULNERABLE to MS17-010!\n"
    )


def _mock_execute_msfrpc_commands(ip_list, module_path, output_file, **kwargs):
    """Patch for execute_msfrpc_commands — writes mock console text output."""
    # Derive port from RPORT in additional_options (set per scan job by MetasploitScan.run)
    port = (kwargs.get('additional_options') or {}).get('RPORT', '445')
    # Strip CIDR notation if the IP was passed as a subnet string (e.g. "1.2.3.4/32")
    raw_ip = ip_list[0] if ip_list else TARGET_IP
    ip = raw_ip.split('/')[0]
    output = _make_mock_console_output(ip, port)
    with open(output_file, 'w') as f:
        f.write(output)
    return output


class TestMetasploitScan:

    TOOL_NAME = 'metasploit'
    TEST_SCAN_ID = format(uuid.uuid4().int, 'x')
    TEST_SCHEDULED_SCAN_ID = format(uuid.uuid4().int, 'x')

    def _make_scan_objects(self, recon_manager, port_list="135, 445", args="auxiliary/scanner/smb/smb_ms17_010"):
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
            patch('reverge_collector.metasploit_scan.execute_msfrpc_commands',
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
                    patch('reverge_collector.metasploit_scan.execute_msfrpc_commands',
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

    # ------------------------------------------------------------------
    # Description-parsing tests — mock requests.post so no live server
    # ------------------------------------------------------------------

    def _mock_post(self, url, json=None, **kwargs):
        """Side-effect for requests.post: dispatches module.search and module.info."""
        method = (json or {}).get("method", "")
        params = (json or {}).get("params", [])
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()

        if method == "module.search":
            query = params[0] if params else ""
            if "type:auxiliary" in query:
                mock_resp.json.return_value = MSF_SEARCH_AUXILIARY_RESPONSE
            elif "type:exploit" in query:
                mock_resp.json.return_value = MSF_SEARCH_EXPLOIT_RESPONSE
            else:
                mock_resp.json.return_value = {"jsonrpc": "2.0", "result": []}

        elif method == "module.info":
            mtype = params[0] if len(params) > 0 else ""
            name = params[1] if len(params) > 1 else ""
            info = MSF_INFO_RESPONSES.get((mtype, name))
            if info:
                mock_resp.json.return_value = {
                    "jsonrpc": "2.0", "result": info}
            else:
                mock_resp.json.return_value = {"jsonrpc": "2.0", "result": {}}

        else:
            mock_resp.json.return_value = {"jsonrpc": "2.0", "result": []}

        return mock_resp

    def test_generate_modules_descriptions_populated(self):
        """Descriptions from module.info are stored on CollectionModule objects."""
        with patch("reverge_collector.metasploit_scan.requests.post",
                   side_effect=self._mock_post):
            modules = Metasploit._generate_metasploit_modules(
                "127.0.0.1", 8081, "token", False
            )

        by_name = {m.name: m for m in modules}
        assert len(modules) == 3

        smb = by_name["auxiliary/scanner/smb/smb_ms17_010"]
        assert smb.description == MSF_INFO_RESPONSES[(
            "auxiliary", "scanner/smb/smb_ms17_010")]["description"]
        assert smb.description != smb.name

        ssh = by_name["auxiliary/scanner/ssh/ssh_version"]
        assert ssh.description == "Detect SSH Version."
        assert ssh.description != ssh.name

        eternal = by_name["exploit/windows/smb/ms17_010_eternalblue"]
        assert eternal.description == MSF_INFO_RESPONSES[(
            "exploit", "windows/smb/ms17_010_eternalblue")]["description"]
        assert eternal.description != eternal.name

    def test_generate_modules_args_required_opts(self):
        """module.args starts with the module path followed by required non-advanced
        options that have no default (KEY=CHANGEME), excluding RHOSTS and RPORT which
        are auto-populated.  When there are no required options the args string is
        still just the module path so MetasploitScan.run() can locate the module."""
        with patch("reverge_collector.metasploit_scan.requests.post",
                   side_effect=self._mock_post):
            modules = Metasploit._generate_metasploit_modules(
                "127.0.0.1", 8081, "token", False
            )

        by_name = {m.name: m for m in modules}

        # smb_ms17_010 has a required DOMAIN option with no default
        smb = by_name["auxiliary/scanner/smb/smb_ms17_010"]
        assert smb.args == "auxiliary/scanner/smb/smb_ms17_010 DOMAIN=CHANGEME THREADS=1", (
            f"Expected 'auxiliary/scanner/smb/smb_ms17_010 DOMAIN=CHANGEME THREADS=1', got {smb.args!r}"
        )

        # ssh_version has only auto-populated opts — args should be just the module path
        ssh = by_name["auxiliary/scanner/ssh/ssh_version"]
        assert ssh.args == "auxiliary/scanner/ssh/ssh_version", (
            f"Expected 'auxiliary/scanner/ssh/ssh_version', got {ssh.args!r}"
        )

        # eternalblue has only auto-populated opts — args should be just the module path
        eternal = by_name["exploit/windows/smb/ms17_010_eternalblue"]
        assert eternal.args == "exploit/windows/smb/ms17_010_eternalblue", (
            f"Expected 'exploit/windows/smb/ms17_010_eternalblue', got {eternal.args!r}"
        )

    def test_generate_modules_missing_description_falls_back_to_fullname(self):
        """When module.info returns no description the fullname is used as a fallback."""
        def _mock_no_desc(url, json=None, **kwargs):
            mock_resp = MagicMock()
            mock_resp.raise_for_status = MagicMock()
            method = (json or {}).get("method", "")
            params = (json or {}).get("params", [])
            if method == "module.search" and "type:auxiliary" in (params[0] if params else ""):
                mock_resp.json.return_value = MSF_SEARCH_NO_DESCRIPTION_RESPONSE
            elif method == "module.info":
                # return info with no description field
                mock_resp.json.return_value = {"jsonrpc": "2.0", "result": {
                    "fullname": "auxiliary/scanner/ftp/ftp_version",
                    "name": "ftp_version",
                }}
            else:
                mock_resp.json.return_value = {"jsonrpc": "2.0", "result": []}
            return mock_resp

        with patch("reverge_collector.metasploit_scan.requests.post",
                   side_effect=_mock_no_desc):
            modules = Metasploit._generate_metasploit_modules(
                "127.0.0.1", 8081, "token", False
            )

        assert len(modules) == 1
        m = modules[0]
        assert m.name == "auxiliary/scanner/ftp/ftp_version"
        assert m.description == m.name
