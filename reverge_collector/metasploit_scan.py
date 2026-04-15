"""
Metasploit network scanning module for the reverge_collector framework.

This module provides network scanning capabilities using Metasploit Framework via the msfrpc
daemon. The Metasploit module to execute is specified in the tool's args field as the first
slash-delimited token (e.g. ``auxiliary/scanner/smb/smb_ms17_010``), followed by any optional
``KEY=VALUE`` datastore options.  RHOSTS is populated from the target IP list and RPORT is
populated from the port number for each scan job.

The module supports both subnet-based and targeted scanning. It processes JSON-formatted output
to extract host, port, and service information.

Classes:
    Metasploit: Tool configuration class for Metasploit scanner
    MetasploitScan: Luigi task for executing Metasploit network scans via msfrpc
    ImportMetasploitOutput: Luigi task for processing and importing Metasploit scan results

Functions:
    remove_dups_from_dict: Utility function to remove duplicate script results

"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import partial
import json
import os
import re
import time
import uuid as uuid_lib
from typing import Dict, Any, List, Set, Optional, Union
import netaddr
import requests
import traceback
import logging

from reverge_collector import scan_utils
from reverge_collector import data_model
from reverge_collector.tool_spec import ToolSpec


def execute_msfrpc_commands(ip_list: List[str], module_path: str, output_file: str,
                            additional_options: Optional[Dict[str, Any]] = None,
                            bearer_token: str = "",
                            msf_host: str = "127.0.0.1",
                            msf_port: int = 8081, use_ssl: bool = False,
                            poll_interval: float = 2.0,
                            max_wait: int = 300) -> str:
    """
    Execute a Metasploit module via the JSON RPC console interface.

    Creates a dedicated MSF console, sets RHOSTS / RPORT and any extra datastore
    options, runs the module, drains the console output until the module finishes,
    destroys the console, and writes the raw console text to *output_file*.

    Using the console API (rather than module.execute + module.results) is required
    because most scanner modules return ``nil`` from their Ruby ``run`` method —
    all useful output is printed to the console, not returned as a structured value.

    Args:
        ip_list: Target IP addresses / hostnames to scan (set as RHOSTS).
        module_path: Fully-qualified Metasploit module path, e.g.
            ``auxiliary/scanner/ssh/ssh_version``.
        output_file: Path where the captured console text is written.
        additional_options: Extra module datastore options merged on top of RHOSTS.
        bearer_token: Bearer token for the ``Authorization`` header (may be empty).
        msf_host: Hostname / IP of the JSON RPC server (default ``127.0.0.1``).
        msf_port: TCP port of the JSON RPC server (default ``8081``).
        use_ssl: Whether to use HTTPS (default ``False``).
        poll_interval: Seconds between ``console.read`` polls (default ``2.0``).
        max_wait: Maximum seconds to wait for the module to finish (default ``300``).

    Returns:
        The captured console output string, or an empty string on error.
    """
    logger = logging.getLogger(__name__)
    scheme = "https" if use_ssl else "http"
    rpc_url = f"{scheme}://{msf_host}:{msf_port}/api/v1/json-rpc"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {bearer_token}",
    }

    def _rpc_call(method: str, params: list) -> Dict[str, Any]:
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "id": str(uuid_lib.uuid4()),
            "params": params,
        }
        resp = requests.post(rpc_url, json=payload, headers=headers,
                             verify=use_ssl, timeout=30)
        resp.raise_for_status()
        return resp.json()

    # Build datastore options dict: RHOSTS from ip_list, rest from additional_options
    options: Dict[str, Any] = {"RHOSTS": " ".join(ip_list)}
    if additional_options:
        options.update(additional_options)

    # logger.debug("console execute — module=%s options=%s",
    #             module_path, options)

    console_id: Optional[str] = None
    console_output: str = ""
    session_opened: bool = False

    try:
        # Create a dedicated console for this module run
        create_resp = _rpc_call("console.create", [{}])
        if "error" in create_resp:
            logger.error("console.create failed for %s: %s",
                         module_path, create_resp["error"])
            return ""
        console_id = str(create_resp.get("result", {}).get("id", ""))
        if not console_id:
            logger.error("console.create returned no id for %s", module_path)
            return ""

        # logger.debug("Console id=%s created for module %s",
        #             console_id, module_path)

        def _drain(max_rounds: int = 5) -> str:
            """Read from the console until it reports busy=false."""
            out = ""
            for _ in range(max_rounds):
                time.sleep(poll_interval)
                read_resp = _rpc_call("console.read", [console_id])
                chunk = read_resp.get("result", {})
                data = chunk.get("data", "")
                if data:
                    out += data
                if not chunk.get("busy", True):
                    break
            return out

        # Drain the MSF banner so subsequent reads only contain module output
        _drain(max_rounds=10)

        # Write all setup commands in one shot
        _rpc_call("console.write", [console_id, f"use {module_path}\n"])
        for key, val in options.items():
            _rpc_call("console.write", [console_id, f"set {key} {val}\n"])
        # Exploit modules are run with 'check' to test exploitability without
        # setting up a full callback listener.  Auxiliary modules use 'run'.
        run_cmd = "check" if module_path.startswith("exploit/") else "run"
        _rpc_call("console.write", [console_id, f"{run_cmd}\n"])

        # Indicators that tell us the module has definitively finished without
        # waiting for busy=false (useful for exploit modules that leave a
        # reverse-TCP handler running and never go idle on their own).
        _SESSION_OPENED = re.compile(
            r'(Meterpreter session|Command shell session|session \d+ opened)',
            re.IGNORECASE)
        _EXPLOIT_ABORTED = re.compile(
            r'(Exploit aborted|exploit failed|no session|module failed)',
            re.IGNORECASE)

        session_opened = False

        # Drain until the module finishes (busy=false after the run)
        elapsed = 0.0
        while elapsed < max_wait:
            time.sleep(poll_interval)
            elapsed += poll_interval
            read_resp = _rpc_call("console.read", [console_id])
            chunk = read_resp.get("result", {})
            data = chunk.get("data", "")
            if data:
                console_output += data
                # logger.debug("[t=%.0fs console=%s] %s",
                #             elapsed, console_id, data.rstrip())
                # Incrementally persist output so it survives a hard timeout
                with open(output_file, 'w') as _fd:
                    _fd.write(console_output)
                # Session opened — we're done, preserve the session
                if _SESSION_OPENED.search(data):
                    # logger.info("Session opened for module %s — stopping poll",
                    #            module_path)
                    session_opened = True
                    break
                # Clear failure — no point waiting for busy=false
                if _EXPLOIT_ABORTED.search(data) and not chunk.get("busy", True):
                    logger.info("Exploit aborted for module %s — stopping poll",
                                module_path)
                    break

            if not chunk.get("busy", True):
                # Drain any buffered output that arrived just as busy cleared.
                for _ in range(20):
                    time.sleep(poll_interval)
                    read_resp = _rpc_call("console.read", [console_id])
                    trailing_chunk = read_resp.get("result", {})
                    trailing = trailing_chunk.get("data", "")
                    if trailing:
                        console_output += trailing
                        # logger.debug("[trailing console=%s] %s",
                        #             console_id, trailing.rstrip())
                        with open(output_file, 'w') as _fd:
                            _fd.write(console_output)
                    if not trailing_chunk.get("busy", True) and not trailing:
                        break
                break
        else:
            logger.warning(
                "Timed out after %.0fs waiting for module %s on console %s — "
                "output so far:\n%s",
                max_wait, module_path, console_id,
                console_output[-2000:] if console_output else "(none)")

        if not console_output.strip():
            logger.warning(
                "Module %s produced no console output (RHOSTS=%s)",
                module_path, options.get("RHOSTS", ""))

    except Exception as e:
        logger.error("Console execution failed for %s: %s", module_path, e)
    finally:
        # Don't destroy the console if a session was opened — doing so would
        # kill the session.  Leave it for the operator to interact with.
        if console_id is not None and not session_opened:
            try:
                _rpc_call("console.destroy", [console_id])
                # logger.debug("Console id=%s destroyed", console_id)
            except Exception as e:
                logger.warning(
                    "console.destroy failed for id=%s: %s", console_id, e)
        elif session_opened:
            logger.info(
                "Console id=%s left open — session is active", console_id)

    # Final write (covers the no-data and exception paths)
    with open(output_file, 'w') as out_fd:
        out_fd.write(console_output)

    return console_output


class Metasploit(ToolSpec):

    name = 'metasploit'
    description = 'Metasploit Framework is a penetration testing platform that interfaces with the msfrpc daemon to execute exploits, auxiliary modules, and post-exploitation tasks on a computer network.'
    project_url = 'https://github.com/rapid7/metasploit-framework'
    tags = ['vuln-scan', 'authenticated', 'service-detection', 'exploitation']
    collector_type = data_model.CollectorType.ACTIVE.value
    scan_order = 6
    args = ''
    input_records = [
        data_model.ServerRecordType.SUBNET,
        data_model.ServerRecordType.HOST,
        data_model.ServerRecordType.PORT,
    ]
    output_records = [
        data_model.ServerRecordType.COLLECTION_MODULE,
        data_model.ServerRecordType.COLLECTION_MODULE_OUTPUT,
        data_model.ServerRecordType.DOMAIN,
        data_model.ServerRecordType.PORT,
        data_model.ServerRecordType.HOST,
    ]

    def __init__(self):
        super().__init__()
        self.modules_func = Metasploit.metasploit_modules

    def get_output_path(self, scan_input) -> str:
        return get_output_path(scan_input)

    def execute_scan(self, scan_input) -> None:
        execute_scan(scan_input)

    def parse_output(self, output_path: str, scan_input) -> list:
        ret_arr: List[Any] = []
        module_id_map: Dict[str, str] = {}

        tool_instance_id = scan_input.current_tool_instance_id
        scope_obj = scan_input.scan_data
        tool_id = scan_input.current_tool.id

        if not os.path.exists(output_path):
            return ret_arr

        with open(output_path) as file_fd:
            json_input = file_fd.read()

        if not json_input:
            return ret_arr

        metasploit_scan_obj = json.loads(json_input)
        for metasploit_scan_entry in metasploit_scan_obj.get('metasploit_scan_list', []):
            metasploit_out = metasploit_scan_entry['output_file']
            protocol = metasploit_scan_entry['protocol']
            if not (os.path.exists(metasploit_out) and os.path.getsize(metasploit_out) > 0):
                continue
            try:
                with open(metasploit_out, 'r') as output_file:
                    all_output = output_file.read()

                ip_lines_map: Dict[str, List[str]] = {}
                ip_port_map_local: Dict[str, str] = {}
                current_ip: Optional[str] = None

                for line in all_output.split('\n'):
                    stripped = line.strip()
                    if stripped.startswith('[*]') or stripped.startswith('[+]') or \
                            stripped.startswith('[-]') or stripped.startswith('[!]'):
                        content = stripped[3:].strip()
                        ip_match = re.match(
                            r'^(\d+\.\d+\.\d+\.\d+):(\d+)\s+-\s+', content)
                        if ip_match:
                            ip = ip_match.group(1)
                            port = ip_match.group(2)
                            current_ip = ip
                            if ip not in ip_lines_map:
                                ip_lines_map[ip] = []
                                ip_port_map_local[ip] = port
                            ip_lines_map[ip].append(stripped)
                        else:
                            ip_match = re.match(
                                r'^(\d+\.\d+\.\d+\.\d+)\s+-\s+', content)
                            if ip_match:
                                ip = ip_match.group(1)
                                current_ip = ip
                                if ip not in ip_lines_map:
                                    ip_lines_map[ip] = []
                                    ip_port_map_local[ip] = str(
                                        metasploit_scan_entry.get('port', '0'))
                                ip_lines_map[ip].append(stripped)
                    elif stripped and current_ip is not None:
                        ip_lines_map[current_ip].append(stripped)

                module_key = protocol
                if module_key not in module_id_map:
                    module_obj = data_model.CollectionModule(parent_id=tool_id)
                    module_obj.collection_tool_instance_id = tool_instance_id
                    module_obj.name = module_key.lower()
                    ret_arr.append(module_obj)
                    module_id_map[module_key] = module_obj.id
                temp_module_id = module_id_map[module_key]

                host_id_map: Dict[str, str] = {}
                port_id_map: Dict[tuple, str] = {}
                domain_id_map: Dict[str, str] = {}
                host_os_map: Dict[str, tuple] = {}

                for ip_address, ip_lines in ip_lines_map.items():
                    port_str = ip_port_map_local.get(
                        ip_address,
                        str(metasploit_scan_entry.get('port', '0')))
                    hostname = ip_address
                    server_os = None

                    for ln in ip_lines:
                        if ln.startswith('['):
                            msg = ln[3:].strip()
                            os_match = re.search(
                                r'Host is running (.+?)(?:\s+\(build:|\s*$)', msg)
                            if os_match:
                                server_os = os_match.group(1).strip()
                                break
                        else:
                            tbl = re.match(r'^(os\.\w+)\s{2,}(\S[^\s]*)$', ln)
                            if tbl:
                                key, value = tbl.group(1), tbl.group(2).strip()
                                if key == 'os.product' and not server_os:
                                    server_os = value
                                elif key == 'os.family' and not server_os:
                                    server_os = value

                    host_id: Optional[str] = None
                    port_id: Optional[str] = None
                    host_key = '%s:%s' % (ip_address, port_str)
                    if host_key in scope_obj.host_port_obj_map:
                        host_port_dict = scope_obj.host_port_obj_map[host_key]
                        port_id = host_port_dict['port_obj'].id
                        host_id = host_port_dict['host_obj'].id
                    elif ip_address in scope_obj.host_ip_id_map:
                        host_id = scope_obj.host_ip_id_map[ip_address]

                    if ip_address not in host_id_map:
                        ip_object = netaddr.IPAddress(ip_address)
                        host_obj = data_model.Host(id=host_id)
                        host_obj.collection_tool_instance_id = tool_instance_id
                        if ip_object.version == 4:
                            host_obj.ipv4_addr = str(ip_object)
                        elif ip_object.version == 6:
                            host_obj.ipv6_addr = str(ip_object)
                        host_id = host_obj.id
                        host_id_map[ip_address] = host_id
                        ret_arr.append(host_obj)
                    else:
                        host_id = host_id_map[ip_address]

                    port_key = (host_id, port_str)
                    if port_key not in port_id_map:
                        port_obj = data_model.Port(
                            parent_id=host_id, id=port_id)
                        port_obj.collection_tool_instance_id = tool_instance_id
                        port_obj.proto = 0
                        port_obj.port = port_str
                        port_id = port_obj.id
                        port_id_map[port_key] = port_id
                        ret_arr.append(port_obj)
                    else:
                        port_id = port_id_map[port_key]

                    ip_output_obj = data_model.CollectionModuleOutput(
                        parent_id=temp_module_id)
                    ip_output_obj.collection_tool_instance_id = tool_instance_id
                    ip_output_obj.output = '\n'.join(ip_lines)
                    ip_output_obj.port_id = port_id
                    ret_arr.append(ip_output_obj)

                    if server_os:
                        os_name = server_os
                        os_version = ''
                        parts = server_os.strip().split()
                        if len(parts) > 1 and re.match(r'^\d+(\.\d+)*$', parts[-1]):
                            os_version = parts[-1]
                            os_name = ' '.join(parts[:-1])

                        should_create_os = False
                        if host_id not in host_os_map:
                            should_create_os = True
                        else:
                            existing_os_name, existing_os_obj = host_os_map[host_id]
                            if ' or ' in existing_os_name.lower() and \
                                    ' or ' not in os_name.lower():
                                should_create_os = True
                                ret_arr.remove(existing_os_obj)

                        if should_create_os:
                            os_obj = data_model.OperatingSystem(
                                parent_id=host_id)
                            os_obj.collection_tool_instance_id = tool_instance_id
                            os_obj.name = os_name
                            if os_version:
                                os_obj.version = os_version
                            ret_arr.append(os_obj)
                            host_os_map[host_id] = (os_name, os_obj)

                    if ip_address != hostname:
                        if hostname not in domain_id_map:
                            domain_obj = data_model.Domain(parent_id=host_id)
                            domain_obj.collection_tool_instance_id = tool_instance_id
                            domain_obj.name = hostname
                            domain_id_map[hostname] = domain_obj.id
                            ret_arr.append(domain_obj)

            except Exception as e:
                logging.getLogger(__name__).error(
                    'Error processing metasploit output file %s: %s',
                    metasploit_out, str(e))
                traceback.print_exc()

        return ret_arr

    @staticmethod
    def metasploit_modules() -> List:
        """
        Retrieve available Metasploit modules as collection modules.

        Queries the msfrpc daemon to discover available auxiliary and exploit modules,
        then retrieves module metadata for each. Each module becomes a CollectionModule
        object that can be selectively enabled for scanning.

        Results are cached on disk and only regenerated when the Metasploit
        framework version changes (or the msfconsole binary hash changes when
        the RPC server is not reachable).

        Returns:
            List[data_model.CollectionModule]: List of collection modules, one for each Metasploit module

        Example:
            >>> metasploit_tool = Metasploit()
            >>> modules = metasploit_tool.modules_func()
            >>> for module in modules:
            ...     print(f"{module.name}: {module.args}")
        """
        from reverge_collector.module_cache import get_cached_modules

        msf_host = os.environ.get("MSF_JSON_RPC_HOST", "127.0.0.1")
        msf_port = int(os.environ.get("MSF_JSON_RPC_PORT", "8081"))
        bearer_token = Metasploit._read_msf_token()
        use_ssl = os.environ.get(
            "MSF_JSON_RPC_SSL", "").lower() in ("1", "true", "yes")

        def fp_func(): return Metasploit._fingerprint(
            msf_host, msf_port, bearer_token, use_ssl)

        def gen_func(): return Metasploit._generate_metasploit_modules(
            msf_host, msf_port, bearer_token, use_ssl
        )
        return get_cached_modules('metasploit', fp_func, gen_func)

    @staticmethod
    def _read_msf_token() -> str:
        """Return the MSF JSON RPC bearer token from env or token file."""
        _token_file = "/opt/collector/msf_rpc_token"
        token = os.environ.get("MSF_JSON_RPC_TOKEN", "")
        if token:
            return token
        if os.path.exists(_token_file):
            try:
                with open(_token_file, 'r') as fh:
                    return fh.read().strip()
            except Exception:
                pass
        return ""

    @staticmethod
    def _fingerprint(
        msf_host: str = "127.0.0.1",
        msf_port: int = 8081,
        bearer_token: str = "",
        use_ssl: bool = False,
    ) -> Optional[str]:
        """Cache fingerprint: MSF framework version from core.version RPC.

        Falls back to SHA-256 of the msfconsole binary when the server is
        not reachable.
        """
        import shutil as _shutil
        from reverge_collector.module_cache import sha256_file
        _log = logging.getLogger(__name__)
        scheme = "https" if use_ssl else "http"
        url = f"{scheme}://{msf_host}:{msf_port}/api/v1/json-rpc"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {bearer_token}",
        }
        try:
            payload = {
                "jsonrpc": "2.0",
                "method": "core.version",
                "id": str(uuid_lib.uuid4()),
                "params": [],
            }
            resp = requests.post(url, json=payload, headers=headers,
                                 verify=use_ssl, timeout=5)
            resp.raise_for_status()
            result = resp.json().get("result", {})
            version = result.get("version") or result.get("framework")
            if version:
                _log.debug("MSF fingerprint via RPC core.version: %s", version)
                return str(version).strip()
            _log.debug(
                "MSF core.version RPC returned no version field; result=%s", result)
        except Exception as exc:
            _log.debug("MSF core.version RPC failed (%s: %s); falling back to binary hash",
                       type(exc).__name__, exc)

        path = _shutil.which('msfconsole')
        if path and os.path.exists(path):
            h = sha256_file(path)
            _log.debug(
                "MSF fingerprint via msfconsole binary hash: %s (path=%s)", h, path)
            return h
        _log.debug(
            "MSF fingerprint: msfconsole not found on PATH; returning None")
        return None

    @staticmethod
    def _generate_metasploit_modules(
        msf_host: str,
        msf_port: int,
        bearer_token: str,
        use_ssl: bool,
        info_workers: int = 50,
    ) -> List:
        """Enumerate auxiliary and exploit modules via the Metasploit JSON RPC.

        Strategy:
        1. ``module.search type:<X>`` returns the full module list quickly but
           does **not** include a description field.
        2. ``module.info <type> <name>`` (where name is the path *without* the
           leading type component) returns the full description.
        So we first fetch all names via search, then fan-out ``module.info``
        calls concurrently (``info_workers`` threads) to enrich descriptions.
        Since the results are cached this cost is only paid once.
        """
        _log = logging.getLogger(__name__)
        modules = []
        scheme = "https" if use_ssl else "http"
        url = f"{scheme}://{msf_host}:{msf_port}/api/v1/json-rpc"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {bearer_token}",
        }

        def _post(method: str, params: list) -> dict:
            payload = {
                "jsonrpc": "2.0",
                "method": method,
                "id": str(uuid_lib.uuid4()),
                "params": params,
            }
            resp = requests.post(url, json=payload, headers=headers,
                                 verify=use_ssl, timeout=30)
            resp.raise_for_status()
            return resp.json()

        def _search_names(mtype: str) -> List[str]:
            """Return list of short module names (without type prefix) for a type."""
            try:
                data = _post("module.search", [f"type:{mtype}"])
                if "error" in data:
                    _log.warning("module.search(type:%s) error: %s",
                                 mtype, data["error"])
                    return []
                result = data.get("result", [])
                if isinstance(result, dict):
                    result = result.get("modules", [])
                if not isinstance(result, list):
                    return []
                # Each entry has 'name' (short) and optionally 'fullname'
                names = []
                for e in result:
                    fullname = e.get("fullname", "")
                    if fullname:
                        # strip leading type prefix to get the short name
                        parts = fullname.split("/", 1)
                        names.append(parts[1] if len(parts) == 2 else fullname)
                    elif e.get("name"):
                        names.append(e["name"])
                _log.debug("module.search(type:%s) returned %d names",
                           mtype, len(names))
                return names
            except Exception as exc:
                _log.warning("module.search(type:%s) failed: %s",
                             mtype, exc)
            return []

        # Options that are auto-populated by the framework at run time;
        # exclude them from the required-args string so users aren't prompted
        # to supply values they don't need to think about.
        _AUTO_OPTIONS = frozenset({"RHOSTS", "RPORT"})

        def _fetch_info(mtype: str, name: str) -> Optional[data_model.CollectionModule]:
            """Call module.info and return a CollectionModule, or None on error."""
            try:
                data = _post("module.info", [mtype, name])
                if "error" in data:
                    return None
                info = data.get("result", {})
                if not isinstance(info, dict):
                    return None
                fullname = info.get("fullname") or f"{mtype}/{name}"
                description = (info.get("description") or "").strip()
                if not description:
                    description = fullname

                # Build args from required, non-advanced options that aren't
                # auto-populated by the framework.  Options without a default
                # get "CHANGEME" as a placeholder; options that have a default
                # are included with their default value so the user can see and
                # override them.
                required_args: List[tuple] = []
                for opt_name, opt in (info.get("options") or {}).items():
                    if (
                        opt.get("required")
                        and not opt.get("advanced")
                        and opt_name not in _AUTO_OPTIONS
                    ):
                        default = opt.get("default")
                        value = str(
                            default) if default is not None else "CHANGEME"
                        required_args.append((opt_name, value))
                required_args.sort(key=lambda x: x[0])

                m = data_model.CollectionModule()
                m.name = fullname
                m.description = description
                opts = " ".join(f"{k}={v}" for k, v in required_args)
                m.args = (fullname + " " + opts) if opts else fullname
                return m
            except Exception as exc:
                _log.debug("module.info(%s, %s) failed: %s", mtype, name, exc)
            return None

        for mtype in ("auxiliary", "exploit"):
            names = _search_names(mtype)
            if not names:
                continue
            _log.debug("Fetching module.info for %d %s modules (%d workers) …",
                       len(names), mtype, info_workers)
            with ThreadPoolExecutor(max_workers=info_workers) as pool:
                futures = {pool.submit(
                    _fetch_info, mtype, n): n for n in names}
                for future in as_completed(futures):
                    result = future.result()
                    if result is not None:
                        modules.append(result)

        _log.debug("_generate_metasploit_modules: total %d modules built",
                   len(modules))
        return modules


def get_output_path(scan_input) -> str:
    scheduled_scan_obj = scan_input
    scan_id: str = scheduled_scan_obj.id
    mod_str: str = ''
    if scheduled_scan_obj.scan_data.module_id:
        module_id: str = str(scheduled_scan_obj.scan_data.module_id)
        mod_str = "_" + module_id
    tool_name: str = scheduled_scan_obj.current_tool.name
    dir_path: str = scan_utils.init_tool_folder(tool_name, 'outputs', scan_id)
    return dir_path + os.path.sep + "metasploit_scan_" + scan_id + mod_str + ".meta"


def execute_scan(scan_input) -> None:
    output_file_path = get_output_path(scan_input)
    if os.path.exists(output_file_path):
        return

    scheduled_scan_obj = scan_input
    meta_file_path: str = output_file_path
    dir_path: str = os.path.dirname(meta_file_path)
    scope_obj = scheduled_scan_obj.scan_data

    module_path: Optional[str] = None
    additional_options: Dict[str, str] = {}
    if scheduled_scan_obj.current_tool.args:
        for token in scheduled_scan_obj.current_tool.args.split():
            if '=' in token:
                key, _, val = token.partition('=')
                additional_options[key.strip()] = val.strip()
            elif '/' in token and module_path is None:
                module_path = token.strip()

    if not module_path:
        logging.getLogger(__name__).warning(
            "No Metasploit module path found in tool args for scan ID %s" % scheduled_scan_obj.id)
        metasploit_scan_data: Dict[str, Any] = {'metasploit_scan_list': []}
        with open(meta_file_path, 'w') as meta_file_fd:
            meta_file_fd.write(json.dumps(metasploit_scan_data))
        return

    port_scan_map: Dict[str, Dict[str, Any]] = {}

    target_map = scope_obj.host_port_obj_map
    port_num_list: List[str] = scope_obj.get_port_number_list_from_scope()
    subnet_map: Dict[int, Any] = scope_obj.subnet_map

    if len(target_map) > 0:
        for target_key in target_map:
            target_obj_dict = target_map[target_key]
            port_obj = target_obj_dict['port_obj']
            port_str = port_obj.port

            host_obj = target_obj_dict['host_obj']
            ip_addr = host_obj.ipv4_addr

            if port_str not in port_scan_map:
                port_scan_map[port_str] = {
                    'protocol': module_path,
                    'ip_set': set()
                }

            ip_set: Set[str] = port_scan_map[port_str]['ip_set']
            ip_set.add(ip_addr)

            target_arr = target_key.split(":")
            extra = target_arr[0]
            if extra != ip_addr and ('.' in extra):
                ip_set.add(extra)

    else:
        if len(port_num_list) > 0:
            target_set: Set[str] = set()

            for subnet_id in subnet_map:
                subnet_obj = subnet_map[subnet_id]
                target_set.add("%s/%s" % (subnet_obj.subnet, subnet_obj.mask))

            host_list = scope_obj.get_hosts(
                [data_model.RecordTag.SCOPE.value, data_model.RecordTag.LOCAL.value])
            for host_obj in host_list:
                target_set.add(host_obj.ipv4_addr)

            for port_str in port_num_list:
                port_scan_map[port_str] = {
                    'protocol': module_path,
                    'ip_set': target_set.copy()
                }

    metasploit_scan_cmd_list: List[Dict[str, Any]] = []
    metasploit_scan_data = {}

    msf_host: str = os.environ.get("MSF_JSON_RPC_HOST", "127.0.0.1")
    msf_port: int = int(os.environ.get("MSF_JSON_RPC_PORT", "8081"))
    bearer_token: str = os.environ.get("MSF_JSON_RPC_TOKEN", "")
    use_ssl: bool = os.environ.get(
        "MSF_JSON_RPC_SSL", "").lower() in ("1", "true", "yes")

    counter: int = 0
    futures: List[Any] = []

    if len(port_scan_map) == 0:
        logging.getLogger(__name__).warning(
            "No scan targets found for Metasploit scan ID %s" % scheduled_scan_obj.id)

    for port_str in sorted(port_scan_map.keys()):
        port_obj = port_scan_map[port_str]
        metasploit_scan_inst: Dict[str, Any] = {}
        module_path_for_port: str = port_obj['protocol']

        metasploit_output_file: str = dir_path + os.path.sep + \
            "metasploit_out_" + str(counter)

        ip_list_path: str = dir_path + os.path.sep + \
            "metasploit_in_" + str(counter)
        ip_set_val: Set[str] = port_obj['ip_set']
        if len(ip_set_val) == 0:
            counter += 1
            continue

        ip_list = list(ip_set_val)
        with open(ip_list_path, 'w') as in_file_fd:
            for ip in ip_list:
                in_file_fd.write(ip + "\n")

        port_options: Dict[str, str] = dict(additional_options)
        port_options['RPORT'] = port_str

        metasploit_scan_inst['output_file'] = metasploit_output_file
        metasploit_scan_inst['protocol'] = module_path_for_port
        metasploit_scan_inst['port'] = port_str
        metasploit_scan_inst['ip_list'] = ip_list_path
        metasploit_scan_cmd_list.append(metasploit_scan_inst)

        futures.append(scan_utils.executor.submit(
            execute_msfrpc_commands,
            ip_list=ip_list,
            module_path=module_path_for_port,
            output_file=metasploit_output_file,
            additional_options=port_options,
            bearer_token=bearer_token,
            msf_host=msf_host,
            msf_port=msf_port,
            use_ssl=use_ssl,
        ))
        counter += 1

    if len(futures) > 0:
        scan_proc_inst = data_model.ToolExecutor(futures)
        scheduled_scan_obj.register_tool_executor(
            scheduled_scan_obj.current_tool_instance_id, scan_proc_inst)

        for future in futures:
            future.result()

    metasploit_scan_data['metasploit_scan_list'] = metasploit_scan_cmd_list

    if metasploit_scan_data:
        with open(meta_file_path, 'w') as meta_file_fd:
            meta_file_fd.write(json.dumps(metasploit_scan_data))
