"""
Metasploit network scanning module for the Waluigi framework.

This module provides comprehensive network scanning capabilities using Metasploit Framework via
msfrpc daemon, a post-exploitation framework used for network reconnaissance and security assessment.
It implements protocol-specific scanning for FTP, SSH, NFS, WMI, LDAP, SMB, MySQL, RDP, VNC, and WinRM services.

The module supports both subnet-based and targeted scanning, with intelligent scan optimization
based on previous port discovery results. It processes JSON-formatted output with fields
(protocol, host, port, hostname, message, module_name) to extract detailed host, port, and
service information.

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
import luigi
import requests
import traceback
import logging

from luigi.util import inherits
from waluigi import scan_utils
from waluigi import data_model

# Maps well-known port numbers to their corresponding Metasploit auxiliary module paths
metasploit_protocol_map: Dict[str, str] = {
    '21':   'auxiliary/scanner/ftp/ftp_version',
    '22':   'auxiliary/scanner/ssh/ssh_version',
    '111':  'auxiliary/scanner/nfs/nfsmount',
    '135':  'auxiliary/scanner/dcerpc/endpoint_mapper',
    '389':  'auxiliary/scanner/ldap/ldap_search',
    '445':  'auxiliary/scanner/smb/smb_ms17_010',
    '3306': 'auxiliary/scanner/mysql/mysql_version',
    '3389': 'auxiliary/scanner/rdp/rdp_scanner',
    '5900': 'auxiliary/scanner/vnc/vnc_none_auth',
    '5985': 'auxiliary/scanner/winrm/winrm_enum_users',
}


def execute_msfrpc_commands(ip_list: List[str], module_path: str, output_file: str,
                            additional_options: Optional[Dict[str, Any]] = None,
                            bearer_token: str = "",
                            msf_host: str = "127.0.0.1",
                            msf_port: int = 8081, use_ssl: bool = False,
                            poll_interval: float = 2.0,
                            max_wait: int = 300) -> Dict[str, Any]:
    """
    Execute a Metasploit module via the JSON RPC interface.

    Submits a module run request to the Metasploit JSON RPC server, polls until the
    job completes, retrieves the structured results, acknowledges them to free server
    memory, and writes the full JSON response to *output_file*.

    The JSON RPC server must already be running (e.g. started with
    ``bundle exec thin --rackup msf-json-rpc.ru ...``).

    Args:
        ip_list: Target IP addresses / hostnames to scan (set as RHOSTS).
        module_path: Fully-qualified Metasploit module path, e.g.
            ``auxiliary/scanner/smb/smb_ms17_010``.
        output_file: Path where the JSON response from ``module.results`` is written.
        additional_options: Extra module datastore options merged on top of RHOSTS.
        bearer_token: Bearer token for the ``Authorization`` header (may be empty).
        msf_host: Hostname / IP of the JSON RPC server (default ``127.0.0.1``).
        msf_port: TCP port of the JSON RPC server (default ``8081``).
        use_ssl: Whether to use HTTPS (default ``False``).
        poll_interval: Seconds between ``module.running_stats`` polls (default ``2.0``).
        max_wait: Maximum seconds to wait for the module to finish (default ``300``).

    Returns:
        The decoded JSON response dict from ``module.results``, or an empty dict on error.
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

    # JSON RPC module.execute takes (mtype, mname, opts) where mname is the path
    # *without* the leading type component:
    #   module_path = "auxiliary/scanner/smb/smb_ms17_010"
    #   module_type = "auxiliary"
    #   module_name = "scanner/smb/smb_ms17_010"
    path_parts = module_path.split('/', 1)
    module_type = path_parts[0]
    module_name = path_parts[1] if len(path_parts) > 1 else module_path

    # Build module options; RHOSTS accepts comma-separated values
    options: Dict[str, Any] = {"RHOSTS": ",".join(ip_list)}
    if additional_options:
        options.update(additional_options)

    # Submit the module run request via module.execute
    try:
        submit_result = _rpc_call(
            "module.execute", [module_type, module_name, options])
    except Exception as e:
        logger.error("JSON RPC module.execute failed for %s: %s",
                     module_path, e)
        return {}

    if "error" in submit_result:
        logger.error("JSON RPC error submitting %s: %s",
                     module_path, submit_result["error"])
        return {}

    module_uuid: str = submit_result.get("result", {}).get("uuid", "")
    if not module_uuid:
        logger.error("No UUID returned for module %s", module_path)
        return {}

    logger.debug("Module %s submitted, uuid=%s", module_path, module_uuid)

    # Poll until the UUID appears in the 'results' bucket
    elapsed = 0.0
    while elapsed < max_wait:
        time.sleep(poll_interval)
        elapsed += poll_interval
        try:
            stats = _rpc_call("module.running_stats", []).get("result", {})
        except Exception as e:
            logger.warning("module.running_stats error: %s", e)
            continue

        if module_uuid in stats.get("results", []):
            break

        # UUID is no longer tracked as waiting or running — treat as done
        if (module_uuid not in stats.get("waiting", [])
                and module_uuid not in stats.get("running", [])):
            time.sleep(poll_interval)  # one final grace period
            break
    else:
        logger.warning("Timed out waiting for module %s (uuid=%s)",
                       module_path, module_uuid)

    # Retrieve the results
    try:
        results_response = _rpc_call("module.results", [module_uuid])
    except Exception as e:
        logger.error("module.results failed for uuid %s: %s", module_uuid, e)
        results_response = {}

    # Acknowledge to allow the server to free memory
    try:
        _rpc_call("module.ack", [module_uuid])
    except Exception as e:
        logger.warning("module.ack failed for uuid %s: %s", module_uuid, e)

    # Persist the response on disk
    with open(output_file, 'w') as out_fd:
        json.dump(results_response, out_fd)

    return results_response


class Metasploit(data_model.WaluigiTool):
    """
    Metasploit network scanner tool configuration.

    This class configures the Metasploit Framework for integration with the
    Waluigi framework. Metasploit is the industry-standard penetration testing
    platform that can perform exploitation, post-exploitation, and security
    assessment via the msfrpc daemon interface.

    The tool is configured for comprehensive network exploitation with module
    execution and payload delivery capabilities.

    Attributes:
        name (str): Tool identifier name
        description (str): Human-readable tool description
        project_url (str): Official project URL
        collector_type (str): Type of collection (ACTIVE)
        scan_order (int): Execution order in scan chain
        args (str): Default command line arguments
        scan_func (callable): Function to execute scans
        import_func (callable): Function to import results

    Example:
        >>> metasploit_tool = Metasploit()
        >>> print(metasploit_tool.name)
        'metasploit'
        >>> metasploit_tool.scan_func(scan_input)
        True
    """

    def __init__(self) -> None:
        """
        Initialize Metasploit tool configuration.

        Sets up the tool with default parameters for comprehensive penetration
        testing including exploitation, post-exploitation, and security assessment
        via msfrpc daemon interface.
        """
        super().__init__()
        self.name: str = 'metasploit'
        self.description: str = 'Metasploit Framework is a penetration testing platform that interfaces with the msfrpc daemon to execute exploits, auxiliary modules, and post-exploitation tasks on a computer network.'
        self.project_url: str = "https://github.com/rapid7/metasploit-framework"
        self.collector_type: str = data_model.CollectorType.ACTIVE.value
        self.scan_order: int = 6
        self.args: str = ""
        self.scan_func = Metasploit.metasploit_scan_func
        self.import_func = Metasploit.metasploit_import
        self.modules_func = Metasploit.metasploit_modules
        self.input_records = [
            data_model.ServerRecordType.SUBNET, data_model.ServerRecordType.HOST, data_model.ServerRecordType.PORT]
        self.output_records = [
            data_model.ServerRecordType.COLLECTION_MODULE,
            data_model.ServerRecordType.COLLECTION_MODULE_OUTPUT,
            data_model.ServerRecordType.WEB_COMPONENT,
            data_model.ServerRecordType.DOMAIN,
            data_model.ServerRecordType.CERTIFICATE,
            data_model.ServerRecordType.LIST_ITEM,
            data_model.ServerRecordType.PORT,
            data_model.ServerRecordType.HOST
        ]

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
        from waluigi.module_cache import get_cached_modules

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
        from waluigi.module_cache import sha256_file
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

                # Build args from required, non-advanced options that have no
                # default and aren't auto-populated by the framework.
                required_args = []
                for opt_name, opt in (info.get("options") or {}).items():
                    if (
                        opt.get("required")
                        and not opt.get("advanced")
                        and "default" not in opt
                        and opt_name not in _AUTO_OPTIONS
                    ):
                        required_args.append(opt_name)
                required_args.sort()

                m = data_model.CollectionModule()
                m.name = fullname
                m.description = description
                m.args = " ".join(f"{k}=CHANGEME" for k in required_args)
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

    @staticmethod
    def metasploit_scan_func(scan_input: data_model.ScheduledScan) -> bool:
        """
        Execute Metasploit network scan via msfrpc daemon.

        Initiates a Metasploit scan using Luigi task orchestration. The scan targets
        are processed from the scheduled scan input and executed via the msfrpc daemon
        interface with intelligent optimization based on previous discovery results.

        Args:
            scan_input (data_model.ScheduledScan): Scheduled scan configuration
                containing target information and scan parameters

        Returns:
            bool: True if scan completed successfully, False otherwise

        Example:
            >>> scan_input = ScheduledScan(...)
            >>> success = Metasploit.metasploit_scan_func(scan_input)
            >>> print(success)
            True
        """
        luigi_run_result = luigi.build([MetasploitScan(
            scan_input=scan_input)], local_scheduler=True, detailed_summary=True)
        if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
            return False
        return True

    @staticmethod
    def metasploit_import(scan_input: data_model.ScheduledScan) -> bool:
        """
        Import and process Metasploit scan results.

        Processes the output from completed Metasploit scans executed via msfrpc daemon,
        parsing detailed host information, exploitation results, and module outputs
        into the data model.

        Args:
            scan_input (data_model.ScheduledScan): Scheduled scan configuration
                containing scan results to import

        Returns:
            bool: True if import completed successfully, False otherwise

        Example:
            >>> scan_input = ScheduledScan(...)
            >>> success = Metasploit.metasploit_import(scan_input)
            >>> print(success)
            True
        """
        luigi_run_result = luigi.build([ImportMetasploitOutput(
            scan_input=scan_input)], local_scheduler=True, detailed_summary=True)
        if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
            return False
        return True


class MetasploitScan(luigi.Task):
    """
    Luigi task for executing Metasploit network scans.

    This task orchestrates the execution of Metasploit scans against target networks,
    handling input preparation, command execution, and output collection. The
    task supports both subnet-based scanning and targeted port scanning with
    intelligent optimization based on previous masscan results.

    The scan process includes:
    - Target preparation (subnets, IPs, domains)
    - Port list optimization based on previous scans
    - Command construction with appropriate arguments
    - Parallel execution of scan jobs
    - XML output collection for import processing

    Attributes:
        scan_input (luigi.Parameter): Scheduled scan configuration parameter

    """

    scan_input: luigi.Parameter = luigi.Parameter()

    def output(self) -> luigi.LocalTarget:
        """
        Define output file target for scan metadata.

        Creates the output file path where scan metadata will be stored,
        incorporating scan ID and optional module ID for uniqueness.

        Returns:
            luigi.LocalTarget: Output file target for scan metadata

        Example:
            >>> task = MetasploitScan(scan_input=scan)
            >>> target = task.output()
            >>> print(target.path)
            '/path/to/outputs/metasploit_scan_scan123.meta'
        """
        scheduled_scan_obj = self.scan_input
        scan_id: str = scheduled_scan_obj.id

        mod_str: str = ''
        if scheduled_scan_obj.scan_data.module_id:
            module_id: str = str(scheduled_scan_obj.scan_data.module_id)
            mod_str = "_" + module_id

        # Init directory
        tool_name: str = scheduled_scan_obj.current_tool.name
        dir_path: str = scan_utils.init_tool_folder(
            tool_name, 'outputs', scan_id)
        meta_file_path: str = dir_path + os.path.sep + \
            "metasploit_scan_" + scan_id + mod_str + ".meta"

        return luigi.LocalTarget(meta_file_path)

    def run(self) -> None:
        """
        Execute the Metasploit network scan via msfrpc daemon.

        Processes target networks and ports, creates optimized scan jobs, and
        executes Metasploit modules via msfrpc daemon with appropriate arguments.
        The method handles different scanning scenarios:

        1. Post-discovery optimization: Executes modules on discovered services
        2. Subnet scanning: Comprehensive scans across network ranges
        3. Targeted scanning: Specific host-port combinations
        4. Full scope scanning: All hosts and ports in scope

        The method:
        - Analyzes previous scan results for optimization
        - Prepares target lists and port specifications
        - Constructs Metasploit module arguments
        - Executes parallel scan jobs via msfrpc
        - Collects output files for import

        Raises:
            Exception: If scan execution fails or output cannot be written

        Example:
            >>> task = MetasploitScan(scan_input=scheduled_scan)
            >>> task.run()
            # Executes optimized Metasploit scans via msfrpc and writes metadata
        """
        scheduled_scan_obj = self.scan_input

        # Ensure output folder exists
        meta_file_path: str = self.output().path
        dir_path: str = os.path.dirname(meta_file_path)

        # Load input file
        scope_obj = scheduled_scan_obj.scan_data

        metasploit_scan_data: Optional[Dict[str, Any]] = None
        metasploit_scan_args: Optional[List[str]] = None
        if scheduled_scan_obj.current_tool.args:
            metasploit_scan_args = scheduled_scan_obj.current_tool.args.split(
                " ")

        # Map to organize scans by port - only include ports in protocol map
        port_scan_map: Dict[str, Dict[str, Any]] = {}

        # Use original scope for comprehensive scanning
        target_map = scope_obj.host_port_obj_map
        port_num_list: List[str] = scope_obj.get_port_number_list_from_scope()

        # Filter port list to only include ports with defined protocols
        valid_port_list: List[str] = [
            p for p in port_num_list if p in metasploit_protocol_map]

        # Create scan for each subnet with supported ports
        subnet_map: Dict[int, Any] = scope_obj.subnet_map
        if len(target_map) > 0:
            # Process individual targets organized by port
            for target_key in target_map:
                target_obj_dict = target_map[target_key]
                port_obj = target_obj_dict['port_obj']
                port_str = port_obj.port

                # Skip ports not in protocol map
                if port_str not in metasploit_protocol_map:
                    continue

                host_obj = target_obj_dict['host_obj']
                ip_addr = host_obj.ipv4_addr

                # Get or create scan object for this port
                if port_str not in port_scan_map:
                    port_scan_map[port_str] = {
                        'protocol': metasploit_protocol_map[port_str],
                        'tool_args': metasploit_scan_args,
                        'ip_set': set()
                    }

                ip_set: Set[str] = port_scan_map[port_str]['ip_set']

                # Add IP
                ip_set.add(ip_addr)

                # Add domain if different from IP
                target_arr = target_key.split(":")
                if target_arr[0] != ip_addr:
                    domain_str = target_arr[0]
                    ip_set.add(domain_str)

        else:
            # Full scope scanning when no specific targets - organize by supported ports
            if len(valid_port_list) > 0:
                target_set: Set[str] = set()

                # Collect all targets (subnets, hosts, domains)
                for subnet_id in subnet_map:
                    subnet_obj = subnet_map[subnet_id]
                    subnet_str: str = "%s/%s" % (subnet_obj.subnet,
                                                 subnet_obj.mask)
                    target_set.add(subnet_str)

                # Get all hosts in scope
                host_list = scope_obj.get_hosts(
                    [data_model.RecordTag.SCOPE.value, data_model.RecordTag.LOCAL.value])

                for host_obj in host_list:
                    ip_addr = host_obj.ipv4_addr
                    target_set.add(ip_addr)

                # Create a scan object for each supported port
                for port_str in valid_port_list:
                    port_scan_map[port_str] = {
                        'protocol': metasploit_protocol_map[port_str],
                        'tool_args': metasploit_scan_args,
                        'ip_set': target_set.copy()
                    }

        # Output structure for scan jobs
        metasploit_scan_cmd_list: List[Dict[str, Any]] = []
        metasploit_scan_data = {}

        # JSON RPC connection config — may be customised via environment variables
        msf_host: str = os.environ.get("MSF_JSON_RPC_HOST", "127.0.0.1")
        msf_port: int = int(os.environ.get("MSF_JSON_RPC_PORT", "8081"))
        bearer_token: str = os.environ.get("MSF_JSON_RPC_TOKEN", "")
        use_ssl: bool = os.environ.get(
            "MSF_JSON_RPC_SSL", "").lower() in ("1", "true", "yes")

        # Parse tool args as extra module datastore options (KEY=VALUE pairs)
        additional_options: Dict[str, str] = {}
        if metasploit_scan_args:
            for arg in metasploit_scan_args:
                if '=' in arg:
                    key, _, val = arg.partition('=')
                    additional_options[key.strip()] = val.strip()

        # Create and execute metasploit commands — one per port
        counter: int = 0
        futures: List[Any] = []

        if len(port_scan_map) == 0:
            logging.getLogger(__name__).warning(
                "No valid ports found for Metasploit scan for scan ID %s" % scheduled_scan_obj.id)

        for port_str in sorted(port_scan_map.keys()):
            port_obj = port_scan_map[port_str]
            metasploit_scan_inst: Dict[str, Any] = {}
            port_id: str = port_obj.get('port_id')
            host_id: str = port_obj.get('host_id')
            module_path: str = port_obj['protocol']

            # Prepare output file
            metasploit_output_file: str = dir_path + os.path.sep + \
                "metasploit_out_" + str(counter)

            # Write IPs to a sidecar file for reference / debugging
            ip_list_path: str = dir_path + os.path.sep + \
                "metasploit_in_" + str(counter)
            ip_set: Set[str] = port_obj['ip_set']
            if len(ip_set) == 0:
                counter += 1
                continue

            ip_list = list(ip_set)
            with open(ip_list_path, 'w') as in_file_fd:
                for ip in ip_list:
                    in_file_fd.write(ip + "\n")

            # Store scan metadata (protocol key is consumed by ImportMetasploitOutput)
            metasploit_scan_inst['output_file'] = metasploit_output_file
            metasploit_scan_inst['protocol'] = module_path
            metasploit_scan_inst['port_id'] = port_id
            metasploit_scan_inst['host_id'] = host_id
            metasploit_scan_inst['ip_list'] = ip_list_path
            metasploit_scan_cmd_list.append(metasploit_scan_inst)

            # Submit to the thread-pool; execute_msfrpc_commands blocks until complete
            futures.append(scan_utils.executor.submit(
                execute_msfrpc_commands,
                ip_list=ip_list,
                module_path=module_path,
                output_file=metasploit_output_file,
                additional_options=additional_options if additional_options else None,
                bearer_token=bearer_token,
                msf_host=msf_host,
                msf_port=msf_port,
                use_ssl=use_ssl,
            ))
            counter += 1

        # Register futures for process tracking and wait for all scans to complete
        if len(futures) > 0:
            scan_proc_inst = data_model.ToolExecutor(futures)
            scheduled_scan_obj.register_tool_executor(
                scheduled_scan_obj.current_tool_instance_id, scan_proc_inst)

            for future in futures:
                result = future.result()
                if result:
                    status = result.get("result", {}).get("status", "")
                    if status == "errored":
                        error_msg = result.get("result", {}).get(
                            "error", "unknown error")
                        logging.getLogger(__name__).error(
                            "Metasploit module errored for scan ID %s: %s" % (
                                scheduled_scan_obj.id, error_msg))

        # Store scan metadata
        metasploit_scan_data['metasploit_scan_list'] = metasploit_scan_cmd_list

        # Write metadata file
        if metasploit_scan_data:
            with open(meta_file_path, 'w') as meta_file_fd:
                meta_file_fd.write(json.dumps(metasploit_scan_data))


@inherits(MetasploitScan)
class ImportMetasploitOutput(data_model.ImportToolXOutput):
    """
    Luigi task for importing and processing Metasploit scan results from msfrpc daemon.

    This task handles the complete import and processing of Metasploit output files executed
    via msfrpc daemon, parsing exploitation and post-exploitation information and integrating
    it into the Waluigi framework's data model. It processes host discovery, service enumeration,
    and exploitation results from Metasploit modules.

    """

    def requires(self) -> MetasploitScan:
        """
        Specify task dependencies for the import operation.

        Returns:
            MetasploitScan: The Metasploit scan task that must complete before
                this import task can execute, providing output files.
        """
        return MetasploitScan(scan_input=self.scan_input)

    def run(self) -> None:
        """
        Import and process Metasploit scan results from msfrpc daemon into the framework's data model.


        """

        scheduled_scan_obj = self.scan_input
        tool_instance_id = scheduled_scan_obj.current_tool_instance_id
        scope_obj = scheduled_scan_obj.scan_data
        tool_obj = scheduled_scan_obj.current_tool
        tool_id = tool_obj.id

        # Initialize result array for data model objects
        ret_arr: List[Any] = []
        module_id_map: Dict[str, str] = {}

        # Read scan metadata file containing output file paths
        meta_file = self.input().path
        if os.path.exists(meta_file):

            with open(meta_file) as file_fd:
                json_input = file_fd.read()

            # Process scan metadata and output files
            if len(json_input) > 0:
                metasploit_scan_obj = json.loads(json_input)
                metasploit_json_arr = metasploit_scan_obj['metasploit_scan_list']

                # Process each parallel scan output file
                for metasploit_scan_entry in metasploit_json_arr:

                    # Parse Metasploit output file with error handling
                    metasploit_out = metasploit_scan_entry['output_file']
                    protocol = metasploit_scan_entry['protocol']
                    if os.path.exists(metasploit_out) and os.path.getsize(metasploit_out) > 0:

                        try:
                            # First pass: Consolidate all data from the Metasploit output.
                            # Supports two formats:
                            #   (a) JSON RPC module.results response (new) – structured JSON
                            #       written by execute_msfrpc_commands.
                            #   (b) Raw Metasploit console text (legacy) – lines prefixed
                            #       with [*] / [+] / [-] / [!].
                            # Structure: {(host, port, hostname, protocol, module_name): {messages: [], data: {...}}}
                            consolidated_data: Dict[tuple, Dict[str, Any]] = {}

                            with open(metasploit_out, 'r') as output_file:
                                raw_content = output_file.read()

                            # Try to interpret the file as a JSON RPC module.results response.
                            # If successful, extract the console message text from it so the
                            # existing line-based parser can process it unchanged.
                            all_output = raw_content
                            json_result_details: Optional[Dict[str, Any]] = None
                            try:
                                rpc_response = json.loads(raw_content)
                                rpc_inner = rpc_response.get("result", {})
                                if isinstance(rpc_inner, dict) and "status" in rpc_inner:
                                    if rpc_inner.get("status") == "errored":
                                        logging.getLogger(__name__).warning(
                                            "Module %s reported error: %s",
                                            metasploit_scan_entry.get(
                                                'protocol'),
                                            rpc_inner.get("error", "unknown"))
                                    inner_result = rpc_inner.get(
                                        "result") or {}
                                    all_output = inner_result.get(
                                        "message", "") or ""
                                    json_result_details = inner_result.get(
                                        "details")
                            except (json.JSONDecodeError, TypeError, AttributeError):
                                pass  # plain-text console output — parse as-is

                            # Parse console-style output lines
                            # Expected format: [prefix] IP:PORT - Message
                            # Prefixes: [*] info, [+] success, [-] error, [!] warning

                            for line in all_output.split('\n'):
                                line = line.strip()
                                if not line:
                                    continue

                                # Skip ASCII art, headers, and non-message lines
                                if not line.startswith('['):
                                    continue

                                # Parse message prefix and determine type
                                output_level = 'INFO'
                                output_type = 'info'

                                if line.startswith('[*]'):
                                    output_level = 'INFO'
                                    output_type = 'info'
                                    message_start = 3
                                elif line.startswith('[+]'):
                                    output_level = 'SUCCESS'
                                    output_type = 'success'
                                    message_start = 3
                                elif line.startswith('[-]'):
                                    output_level = 'ERROR'
                                    output_type = 'error'
                                    message_start = 3
                                elif line.startswith('[!]'):
                                    output_level = 'WARNING'
                                    output_type = 'warning'
                                    message_start = 3
                                else:
                                    continue

                                # Extract the rest of the line after the prefix
                                content = line[message_start:].strip()

                                # Try to extract IP and port from format: IP:PORT - Message or IP - Message
                                ip_address = None
                                port_str = None
                                hostname = None
                                script_output = content

                                # Pattern 1: IP:PORT - Message
                                match = re.match(
                                    r'^(\d+\.\d+\.\d+\.\d+):(\d+)\s+-\s+(.+)$', content)
                                if match:
                                    ip_address = match.group(1)
                                    port_str = match.group(2)
                                    script_output = match.group(3)
                                    hostname = ip_address
                                else:
                                    # Pattern 2: IP - Message
                                    match = re.match(
                                        r'^(\d+\.\d+\.\d+\.\d+)\s+-\s+(.+)$', content)
                                    if match:
                                        ip_address = match.group(1)
                                        script_output = match.group(2)
                                        hostname = ip_address
                                        # Use port from scan entry if not in output
                                        port_str = str(
                                            metasploit_scan_entry.get('port', '0'))

                                # Skip if no IP address found
                                if not ip_address:
                                    continue

                                # Ensure port_str is set
                                if not port_str:
                                    port_str = str(
                                        metasploit_scan_entry.get('port', '0'))

                                # Extract OS information if present in message
                                server_os = None
                                os_match = re.search(
                                    r'Host is running (.+?)(?:\s+\(build:|\s*$)', script_output)
                                if os_match:
                                    server_os = os_match.group(1).strip()

                                module_name = metasploit_scan_entry.get(
                                    'protocol')

                                # Create consolidation key: (host, port, hostname, protocol, module_name, server_os)
                                consolidation_key = (
                                    ip_address, port_str, hostname, protocol, module_name, server_os)

                                # Add or update consolidated data
                                if consolidation_key not in consolidated_data:
                                    consolidated_data[consolidation_key] = {
                                        'messages': [],
                                        'output_level': output_level,
                                        'output_type': output_type,
                                        'timestamps': []
                                    }

                                # Append message to the list for this consolidation key
                                consolidated_data[consolidation_key]['messages'].append(
                                    script_output)
                                consolidated_data[consolidation_key]['timestamps'].append(
                                    time.strftime('%Y-%m-%dT%H:%M:%S'))

                            # Second pass: Create data model objects from consolidated data
                            # Track created objects to avoid duplicates
                            # Key: IP address, Value: host_id
                            host_id_map: Dict[str, str] = {}
                            # Key: (host_id, port), Value: port_id
                            port_id_map: Dict[tuple, str] = {}
                            # Key: domain name, Value: domain_id
                            domain_id_map: Dict[str, str] = {}
                            # Key: host_id, Value: (os_name, os_obj) - track OS objects to prevent duplicates
                            host_os_map: Dict[str, tuple] = {}

                            for consolidation_key, consolidated_entry in consolidated_data.items():
                                ip_address, port_str, hostname, protocol_out, module_name, server_os = consolidation_key

                                # Create or retrieve Host object using IP address as key
                                if ip_address not in host_id_map:
                                    # Create new Host object with proper IPv4/IPv6 handling
                                    ip_object = netaddr.IPAddress(ip_address)

                                    host_obj = data_model.Host(id=None)
                                    host_obj.collection_tool_instance_id = tool_instance_id

                                    # Set appropriate IP address field based on version
                                    if ip_object.version == 4:
                                        host_obj.ipv4_addr = str(ip_object)
                                    elif ip_object.version == 6:
                                        host_obj.ipv6_addr = str(ip_object)

                                    host_id = host_obj.id
                                    host_id_map[ip_address] = host_id

                                    # Add host object to results
                                    ret_arr.append(host_obj)

                                else:
                                    # Reuse existing host_id
                                    host_id = host_id_map[ip_address]

                                # Handle OperatingSystem object - check if we should create or update
                                if server_os:
                                    # Parse server_os to extract name and version
                                    # Format examples: "Windows Server 2016 Standard 14393", "Linux"
                                    os_name = server_os
                                    os_version = ''

                                    # Split on whitespace and check if last token is numeric (version)
                                    parts = server_os.strip().split()
                                    if len(parts) > 1 and parts[-1].isdigit():
                                        # Last part is version number
                                        os_version = parts[-1]
                                        os_name = ' '.join(parts[:-1])

                                    # Check if we already have an OS for this host
                                    should_create_os = False
                                    if host_id not in host_os_map:
                                        # No OS exists for this host yet
                                        should_create_os = True
                                    else:
                                        # OS exists - check if we should replace it
                                        existing_os_name, existing_os_obj = host_os_map[host_id]
                                        # Replace if old name has "or" and new name doesn't
                                        if ' or ' in existing_os_name.lower() and ' or ' not in os_name.lower():
                                            should_create_os = True
                                            # Remove old OS object from results
                                            ret_arr.remove(existing_os_obj)

                                    if should_create_os:
                                        os_obj = data_model.OperatingSystem(
                                            parent_id=host_id)
                                        os_obj.collection_tool_instance_id = tool_instance_id
                                        os_obj.name = os_name

                                        # Add version information if available
                                        if len(os_version) > 0:
                                            os_obj.version = os_version

                                        ret_arr.append(os_obj)
                                        # Track this OS object
                                        host_os_map[host_id] = (
                                            os_name, os_obj)

                                # Create or retrieve Port object using (host_id, port) as key
                                port_key = (host_id, port_str)
                                if port_key not in port_id_map:
                                    # Create new Port object with parent relationship to host
                                    port_obj = data_model.Port(
                                        parent_id=host_id, id=None)
                                    port_obj.collection_tool_instance_id = tool_instance_id
                                    # TCP protocol (0 = TCP, 1 = UDP)
                                    port_obj.proto = 0
                                    port_obj.port = port_str
                                    port_id = port_obj.id
                                    port_id_map[port_key] = port_id

                                    # Add port object to results
                                    ret_arr.append(port_obj)
                                else:
                                    # Reuse existing port_id
                                    port_id = port_id_map[port_key]

                                # Create or retrieve Domain object using domain name as key
                                if ip_address != hostname:
                                    if hostname not in domain_id_map:
                                        # Create new domain object linked to host
                                        domain_obj = data_model.Domain(
                                            parent_id=host_id)
                                        domain_obj.collection_tool_instance_id = tool_instance_id
                                        domain_obj.name = hostname
                                        domain_id = domain_obj.id
                                        domain_id_map[hostname] = domain_id

                                        # Add domain object to results
                                        ret_arr.append(domain_obj)
                                    else:
                                        # Reuse existing domain_id
                                        domain_id = domain_id_map[hostname]

                                # Use module_name if present, otherwise use protocol for module identification
                                module_key = module_name if module_name else protocol_out

                                if module_key not in module_id_map:
                                    module_obj = data_model.CollectionModule(
                                        parent_id=tool_id)
                                    module_obj.collection_tool_instance_id = tool_instance_id
                                    module_obj.name = module_key.lower()

                                    ret_arr.append(module_obj)
                                    temp_module_id = module_obj.id
                                    module_id_map[module_key] = temp_module_id
                                else:
                                    temp_module_id = module_id_map[module_key]

                                # Concatenate all messages for this consolidation key
                                consolidated_messages = '\n'.join(
                                    consolidated_entry['messages'])

                                # Add single module output with consolidated messages
                                module_output_obj = data_model.CollectionModuleOutput(
                                    parent_id=temp_module_id)
                                module_output_obj.collection_tool_instance_id = tool_instance_id
                                module_output_obj.output = consolidated_messages
                                module_output_obj.port_id = port_id

                                ret_arr.append(module_output_obj)

                        except Exception as e:
                            logging.getLogger(__name__).error(
                                "Error processing metasploit output file %s: %s" % (metasploit_out, str(e)))
                            traceback.print_exc()

        # Import, Update, & Save
        self.import_results(scheduled_scan_obj, ret_arr)
