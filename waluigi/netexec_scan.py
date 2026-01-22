"""
Netexec network scanning module for the Waluigi framework.

This module provides comprehensive network scanning capabilities using Netexec, a post-exploitation
framework used for network reconnaissance and security assessment. It implements protocol-specific
scanning for FTP, SSH, NFS, WMI, LDAP, SMB, MySQL, RDP, VNC, and WinRM services.

The module supports both subnet-based and targeted scanning, with intelligent scan optimization
based on previous port discovery results. It processes JSON-formatted output with fields
(protocol, host, port, hostname, message, module_name) to extract detailed host, port, and
service information.

Classes:
    Netexec: Tool configuration class for Netexec scanner
    NetexecScan: Luigi task for executing Netexec network scans
    ImportNetexecOutput: Luigi task for processing and importing Netexec scan results

Functions:
    remove_dups_from_dict: Utility function to remove duplicate script results

"""

from functools import partial
import json
import os
import re
from typing import Dict, Any, List, Set, Optional, Union
import netaddr
import luigi
import traceback
import logging

from luigi.util import inherits
from waluigi import scan_utils
from waluigi import data_model
from waluigi.proc_utils import process_wrapper

netexec_protocol_map = {'21': 'ftp', '22': 'ssh', '111': 'nfs', '135': 'wmi', '389': 'ldap', '445': 'smb',
                        '3306': 'mysql', '3389': 'rdp', '5900': 'vnc', '5985': 'winrm'}


class Netexec(data_model.WaluigiTool):
    """
    Netexec network scanner tool configuration.

    This class configures the Netexec network scanner for integration with the
    Waluigi framework. Netexec is the industry-standard network discovery and
    security auditing tool that can perform port scanning, service detection,
    OS detection, and script-based vulnerability scanning.

    The tool is configured for comprehensive TCP scanning with service version
    detection and SSL certificate analysis capabilities.

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
        >>> netexec_tool = Netexec()
        >>> print(netexec_tool.name)
        'netexec'
        >>> netexec_tool.scan_func(scan_input)
        True
    """

    def __init__(self) -> None:
        """
        Initialize Netexec tool configuration.

        Sets up the tool with default parameters for comprehensive network
        scanning including service version detection and SSL certificate
        analysis with script execution.
        """
        super().__init__()
        self.name: str = 'netexec'
        self.description: str = 'Netexec is a network scanning tool used to discover hosts and services on a computer network. It can be used to perform port scanning, service detection, and OS detection.'
        self.project_url: str = "https://github.com/Pennyw0rth/NetExec"
        self.collector_type: str = data_model.CollectorType.ACTIVE.value
        self.scan_order: int = 6
        self.args: str = ""
        self.scan_func = Netexec.netexec_scan_func
        self.import_func = Netexec.netexec_import
        self.modules_func = Netexec.netexec_modules
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
    def netexec_modules() -> List:
        """
        Retrieve available Netexec modules as collection modules.

        Executes 'netexec -h' to discover available protocols, then runs
        'netexec <protocol> -L' for each protocol to discover all available
        modules. Each module becomes a CollectionModule object that can be
        selectively enabled for scanning.

        Returns:
            List[data_model.CollectionModule]: List of collection modules, one for each Netexec module

        Example:
            >>> netexec_tool = Netexec()
            >>> modules = netexec_tool.modules_func()
            >>> for module in modules:
            ...     print(f"{module.name}: {module.args}")
        """
        modules = []

        try:
            # Execute netexec -h to get list of all protocols
            cmd_args = ['/root/.local/bin/netexec', '-h']
            result = process_wrapper(cmd_args=cmd_args, store_output=True)

            if result and 'exit_code' in result and result['exit_code'] != 0:
                logging.getLogger(__name__).warning(
                    f"netexec -h failed with exit code {result['exit_code']}"
                )
                return modules

            output = result.get('stdout', '') if result else ''

            # Parse the output to extract protocols from "Available Protocols:" section
            protocols = []
            lines = output.split('\n')
            in_protocols_section = False

            for line in lines:
                if 'Available Protocols:' in line:
                    in_protocols_section = True
                    continue

                if in_protocols_section:
                    # Protocol lines start with 4 spaces and protocol name
                    if line.strip() and line.startswith('    ') and not line.startswith('      '):
                        # Extract protocol name (first word after spaces)
                        parts = line.strip().split()
                        if parts:
                            protocol = parts[0]
                            protocols.append(protocol)

            # For each protocol, get its modules
            for protocol in protocols:
                try:
                    # Execute netexec <protocol> -L to get modules
                    cmd_args = ['/root/.local/bin/netexec', protocol, '-L']
                    result = process_wrapper(
                        cmd_args=cmd_args, store_output=True)

                    if result and 'exit_code' in result and result['exit_code'] != 0:
                        logging.getLogger(__name__).warning(
                            f"netexec {protocol} -L failed with exit code {result['exit_code']}"
                        )
                        continue

                    module_output = result.get('stdout', '') if result else ''

                    # Parse module list output
                    # Format includes category headers (LOW/HIGH PRIVILEGE MODULES, ENUMERATION, etc)
                    # Module lines: [*] module_name         description
                    module_lines = module_output.split('\n')
                    for line in module_lines:
                        # Only process lines that start with [*] (actual module entries)
                        if not line.strip().startswith('[*]'):
                            continue

                        # Remove [*] prefix and strip whitespace
                        line = line.strip()[3:].strip()

                        # Split by whitespace to get module name and description
                        # module_name is first word, rest is description
                        parts = line.split(None, 1)
                        if parts:
                            module_name = parts[0]
                            description = parts[1] if len(parts) > 1 else ''

                            # Create CollectionModule for this module
                            module = data_model.CollectionModule()
                            module.name = f"{protocol}_{module_name}"
                            module.description = description.strip()
                            module.args = f"{protocol} -M {module_name}"
                            modules.append(module)

                except Exception as e:
                    logging.getLogger(__name__).error(
                        f"Error getting modules for {protocol}: {str(e)}"
                    )
                    logging.getLogger(__name__).debug(traceback.format_exc())

        except FileNotFoundError:
            logging.getLogger(__name__).error("netexec command not found")
        except Exception as e:
            logging.getLogger(__name__).error(
                f"Error getting netexec modules: {str(e)}"
            )
            logging.getLogger(__name__).debug(traceback.format_exc())

        return modules

    @staticmethod
    def netexec_scan_func(scan_input: data_model.ScheduledScan) -> bool:
        """
        Execute Netexec network scan.

        Initiates a Netexec scan using Luigi task orchestration. The scan targets
        are processed from the scheduled scan input, with intelligent optimization
        based on previous masscan results when available.

        Args:
            scan_input (data_model.ScheduledScan): Scheduled scan configuration
                containing target information and scan parameters

        Returns:
            bool: True if scan completed successfully, False otherwise

        Example:
            >>> scan_input = ScheduledScan(...)
            >>> success = Netexec.netexec_scan_func(scan_input)
            >>> print(success)
            True
        """
        luigi_run_result = luigi.build([NetexecScan(
            scan_input=scan_input)], local_scheduler=True, detailed_summary=True)
        if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
            return False
        return True

    @staticmethod
    def netexec_import(scan_input: data_model.ScheduledScan) -> bool:
        """
        Import and process Netexec scan results.

        Processes the XML output from completed Netexec scans, parsing detailed
        host information, open ports, services, SSL certificates, and script
        results into the data model.

        Args:
            scan_input (data_model.ScheduledScan): Scheduled scan configuration
                containing scan results to import

        Returns:
            bool: True if import completed successfully, False otherwise

        Example:
            >>> scan_input = ScheduledScan(...)
            >>> success = Netexec.netexec_import(scan_input)
            >>> print(success)
            True
        """
        luigi_run_result = luigi.build([ImportNetexecOutput(
            scan_input=scan_input)], local_scheduler=True, detailed_summary=True)
        if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
            return False
        return True


class NetexecScan(luigi.Task):
    """
    Luigi task for executing Netexec network scans.

    This task orchestrates the execution of Netexec scans against target networks,
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

    Example:
        >>> scan_task = NetexecScan(scan_input=scheduled_scan)
        >>> scan_task.run()
        # Executes Netexec scan and saves XML results
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
            >>> task = NetexecScan(scan_input=scan)
            >>> target = task.output()
            >>> print(target.path)
            '/path/to/outputs/netexec_scan_scan123.meta'
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
            "netexec_scan_" + scan_id + mod_str + ".meta"

        return luigi.LocalTarget(meta_file_path)

    def run(self) -> None:
        """
        Execute the Netexec network scan.

        Processes target networks and ports, creates optimized scan jobs, and
        executes Netexec with appropriate arguments. The method handles different
        scanning scenarios:

        1. Post-masscan optimization: Scans only discovered ports on specific IPs
        2. Subnet scanning: Comprehensive scans across network ranges
        3. Targeted scanning: Specific host-port combinations
        4. Full scope scanning: All hosts and ports in scope

        The method:
        - Analyzes previous scan results for optimization
        - Prepares target lists and port specifications
        - Constructs Netexec command arguments
        - Executes parallel scan jobs
        - Collects output files for import

        Raises:
            Exception: If scan execution fails or output cannot be written

        Example:
            >>> task = NetexecScan(scan_input=scheduled_scan)
            >>> task.run()
            # Executes optimized Netexec scans and writes metadata
        """
        scheduled_scan_obj = self.scan_input

        # Ensure output folder exists
        meta_file_path: str = self.output().path
        dir_path: str = os.path.dirname(meta_file_path)

        # Load input file
        scope_obj = scheduled_scan_obj.scan_data

        netexec_scan_data: Optional[Dict[str, Any]] = None
        netexec_scan_args: Optional[List[str]] = None
        if scheduled_scan_obj.current_tool.args:
            netexec_scan_args = scheduled_scan_obj.current_tool.args.split(" ")

        # Map to organize scans by port - only include ports in protocol map
        port_scan_map: Dict[str, Dict[str, Any]] = {}

        # Use original scope for comprehensive scanning
        target_map = scope_obj.host_port_obj_map
        port_num_list: List[str] = scope_obj.get_port_number_list_from_scope()

        # Filter port list to only include ports with defined protocols
        valid_port_list: List[str] = [
            p for p in port_num_list if p in netexec_protocol_map]

        # Create scan for each subnet with supported ports
        subnet_map: Dict[int, Any] = scope_obj.subnet_map
        if len(target_map) > 0:
            # Process individual targets organized by port
            for target_key in target_map:
                target_obj_dict = target_map[target_key]
                port_obj = target_obj_dict['port_obj']
                port_str = port_obj.port

                # Skip ports not in protocol map
                if port_str not in netexec_protocol_map:
                    continue

                host_obj = target_obj_dict['host_obj']
                ip_addr = host_obj.ipv4_addr

                # Get or create scan object for this port
                if port_str not in port_scan_map:
                    port_scan_map[port_str] = {
                        'protocol': netexec_protocol_map[port_str],
                        'tool_args': netexec_scan_args,
                        'ip_set': set()
                    }

                ip_set: Set[str] = port_scan_map[port_str]['ip_set']

                # If credential id exists, add to scan metadata
                if host_obj.credential and host_obj.credential.get('credential_id'):
                    port_scan_map[port_str]['credential_id'] = host_obj.credential.get(
                        'credential_id')
                elif port_obj.credential and port_obj.credential.get('credential_id'):
                    port_scan_map[port_str]['credential_id'] = port_obj.credential.get(
                        'credential_id')

                # Add IP
                ip_set.add(ip_addr)

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
                        'protocol': netexec_protocol_map[port_str],
                        'tool_args': netexec_scan_args,
                        'ip_set': target_set.copy()
                    }

        # Output structure for scan jobs
        netexec_scan_cmd_list: List[Dict[str, Any]] = []
        netexec_scan_data = {}

        # Create and execute netexec commands - one per port
        counter: int = 0
        futures: List[Any] = []

        if len(port_scan_map) == 0:
            logging.getLogger(__name__).warning(
                "No valid ports found for Netexec scan for scan ID %s" % scheduled_scan_obj.id)

        # logging.getLogger(__name__).debug(
        #    "Netexec scan port map: %s" % port_scan_map)
        for port_str in sorted(port_scan_map.keys()):
            port_obj = port_scan_map[port_str]
            netexec_scan_inst: Dict[str, Any] = {}
            script_args: Optional[List[str]] = port_obj.get('tool_args')
            protocol: str = port_obj.get('protocol')
            port_id: str = port_obj.get('port_id')
            host_id: str = port_obj.get('host_id')
            credential_id: str = port_obj.get('credential_id')

            ip_list_path: str = dir_path + os.path.sep + \
                "netexec_in_" + str(counter)

            # Write IPs to input file
            ip_set: Set[str] = port_obj['ip_set']
            if len(ip_set) == 0:
                continue

            with open(ip_list_path, 'w') as in_file_fd:
                for ip in ip_set:
                    in_file_fd.write(ip + "\n")

            # Prepare output file
            netexec_output_file: str = dir_path + os.path.sep + \
                "netexec_out_" + str(counter)

            # Build command arguments
            command: List[str] = []
            if os.name != 'nt':
                command.append("sudo")

            command.append("/root/.local/bin/netexec")
            command.append("-j")

            # Add script arguments
            command_custom_args = []
            if script_args and len(script_args) > 0:
                protocol_arg = script_args[0]
                command_custom_args = script_args[1:]
                if protocol_arg != protocol:
                    logging.getLogger(__name__).warning(
                        "Netexec scan protocol mismatch: expected %s, got %s" % (protocol, protocol_arg))
                    continue

            command.append(protocol)

            # Add the target list
            command.append(ip_list_path)

            # Add credentials
            if credential_id and credential_id in scope_obj.credential_map:
                credential = scope_obj.credential_map[credential_id]
                # Add username
                command.append("-u")
                command.append(credential.username)
                # Add password
                command.append("-p")
                command.append(credential.password)

            # Add custom args
            command.extend(command_custom_args)

            # Store scan metadata
            netexec_scan_inst['netexec_command'] = command
            netexec_scan_inst['output_file'] = netexec_output_file
            netexec_scan_inst['port'] = port_str
            netexec_scan_inst['protocol'] = protocol
            netexec_scan_inst['port_id'] = port_id
            netexec_scan_inst['host_id'] = host_id
            netexec_scan_cmd_list.append(netexec_scan_inst)

            # Execute scan with process tracking
            callback_with_tool_id = partial(
                scheduled_scan_obj.register_tool_executor,
                scheduled_scan_obj.current_tool_instance_id)

            futures.append(scan_utils.executor.submit(
                process_wrapper,
                cmd_args=command,
                pid_callback=callback_with_tool_id, stdout_file=netexec_output_file))
            counter += 1

        # Register futures for process tracking
        if len(futures) > 0:
            scan_proc_inst = data_model.ToolExecutor(futures)
            scheduled_scan_obj.register_tool_executor(
                scheduled_scan_obj.current_tool_instance_id, scan_proc_inst)

            # Wait for all scans to complete
            for future in futures:
                ret_dict = future.result()
                if ret_dict and 'exit_code' in ret_dict:
                    exit_code = ret_dict['exit_code']
                    logging.getLogger(__name__).warning(
                        "Exit code %s" % (exit_code))
                    if exit_code != 0:
                        err_msg = ''
                        if 'stderr' in ret_dict and ret_dict['stderr']:
                            err_msg = ret_dict['stderr']
                        logging.getLogger(__name__).error(
                            "Netexec scan for scan ID %s exited with code %d: %s" % (scheduled_scan_obj.id, exit_code, err_msg))
                        raise RuntimeError("Netexec scan for scan ID %s exited with code %d: %s" % (
                            scheduled_scan_obj.id, exit_code, err_msg))

        # Store scan metadata
        netexec_scan_data['netexec_scan_list'] = netexec_scan_cmd_list

        # Write metadata file
        if netexec_scan_data:
            with open(meta_file_path, 'w') as meta_file_fd:
                meta_file_fd.write(json.dumps(netexec_scan_data))


@inherits(NetexecScan)
class ImportNetexecOutput(data_model.ImportToolXOutput):
    """
    Luigi task for importing and processing Netexec scan results.

    This task handles the complete import and processing of Netexec text output files,
    parsing network reconnaissance information and integrating it into the Waluigi framework's
    data model. It processes host discovery, port scanning, and service enumeration results
    from Netexec reconnaissance activities.

    The import process includes:
        - Reading and parsing line-by-line Netexec output format
        - Extracting protocol, IP address, port, and hostname fields
        - Processing variable-length script output payloads
        - Processing host information and network addresses
        - Extracting service details and module outputs
        - Creating data model objects (Host, Port, Domain, Module, ModuleOutput)
        - Handling protocol-based module mapping

    Key Features:
        - Robust text parsing with line-by-line error handling and recovery
        - Complete host and port information extraction from parsed data
        - IPv4 and IPv6 address handling
        - Domain extraction from hostname reconnaissance data
        - Service reconnaissance result processing and module correlation
        - Protocol-based module organization and tracking
        - Comprehensive logging and error reporting

    Attributes:
        Inherits all attributes from NetexecScan and ImportToolXOutput

    Methods:
        requires: Specifies dependency on completed NetexecScan task
        run: Main processing method for importing scan results

    Example:
        >>> # Task is executed as part of the Luigi workflow
        >>> import_task = ImportNetexecOutput(scan_input=scan_obj)
        >>> luigi.build([import_task], local_scheduler=True)

    Note:
        This task creates comprehensive data model objects including hosts,
        ports, domains, modules, and module outputs with proper parent-child
        relationships and tracking information.
    """

    def requires(self) -> NetexecScan:
        """
        Specify task dependencies for the import operation.

        Returns:
            NetexecScan: The Netexec scan task that must complete before
                this import task can execute, providing XML output files.
        """
        return NetexecScan(scan_input=self.scan_input)

    def run(self) -> None:
        """
        Import and process Netexec scan results into the framework's data model.

        This method performs comprehensive processing of Netexec text output files,
        extracting detailed reconnaissance information and creating appropriate data
        model objects. The process handles multiple text output files from parallel
        scan executions (one per protocol/port combination) and correlates results
        with existing scan data.

        The import workflow includes:
            1. Reading scan metadata from the meta file containing output file paths
            2. Processing each JSON output file from parallel scans
            3. FIRST PASS - Consolidation: Parse all JSON lines and consolidate by (host, port, hostname, protocol, module_name)
            4. Preprocessing: Filter redundant info/display messages that lack actionable data
            5. Aggregate all messages for the same module/host/port combination
            6. SECOND PASS - Object Creation: Build data model objects from consolidated data
            7. Creating Host objects for discovered IP addresses (one per unique IP)
            8. Creating Port objects with parent-child relationships to hosts (one per unique port)
            9. Creating Domain objects from hostname reconnaissance data
            10. Creating CollectionModule objects for each protocol/service or module (e.g., NANODUMP)
            11. Creating CollectionModuleOutput objects with consolidated reconnaissance payloads
            12. Importing all results into the framework database

        Data Processing Details:
            - Consolidation: All JSON lines grouped by (host, port, hostname, protocol, module_name)
            - Messages: Multiple messages for the same module are concatenated with newlines
            - Host Objects: Created for each discovered IP address (IPv4/IPv6)
            - Port Objects: Generated for each scanned port with protocol information (one per unique port)
            - Domain Objects: Extracted from reconnaissance hostnames
            - Collection Module Objects: One per service protocol (ftp, ssh, smb, etc.) or module_name when present
            - Module Output Objects: Raw reconnaissance output payloads linked to ports and modules

        JSON Line Format Parsing:
            Each output line is a complete JSON object containing:
            - protocol: Service protocol (e.g., "SMB", "SSH", "FTP")
            - host: Target IP address (IPv4 or IPv6)
            - port: Target port number (integer)
            - hostname: Discovered hostname
            - message: Reconnaissance output payload
            - module_name: Optional module name for the reconnaissance result (e.g., "NANODUMP")
            - type: Message type (display, success, highlight)
            - level: Message level (INFO, SUCCESS, HIGHLIGHT)
            - timestamp: ISO timestamp of the message

        Preprocessing Logic:
            - Skips redundant generic info/display messages without actionable data
            - Filters out status updates unrelated to credentials, files, or system discovery
            - Retains messages containing structured data (parenthetical values) or action keywords
            - Uses module_name field when present to create specific module instances

        Error Handling:
            - Graceful handling of malformed JSON and missing required fields
            - Comprehensive logging of parsing errors
            - Continuation of processing despite individual line failures
            - Try-catch wrapping for file I/O operations

        Example:
            >>> import_task = ImportNetexecOutput(scan_input=scan_obj)
            >>> import_task.run()  # Processes all text output files and imports results

        Note:
            The method handles protocol-specific scanning results, creating
            module instances per protocol and linking all outputs to the
            appropriate port and host objects.
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

            # Process scan metadata and XML output files
            if len(json_input) > 0:
                netexec_scan_obj = json.loads(json_input)
                netexec_json_arr = netexec_scan_obj['netexec_scan_list']

                # Process each parallel scan output file
                for netexec_scan_entry in netexec_json_arr:

                    # Parse Netexec output file with error handling
                    netexec_out = netexec_scan_entry['output_file']
                    protocol = netexec_scan_entry['protocol']
                    if os.path.exists(netexec_out) and os.path.getsize(netexec_out) > 0:

                        try:
                            # First pass: Consolidate all JSON data from the file
                            # Structure: {(host, port, hostname, protocol, module_name): {messages: [], data: {...}}}
                            consolidated_data: Dict[tuple, Dict[str, Any]] = {}

                            with open(netexec_out, 'r') as output_file:
                                for line in output_file:
                                    line = line.strip()
                                    if not line:
                                        continue

                                    # Parse JSON line: each line is a complete JSON object
                                    # Expected fields: protocol, host, port, hostname, message, module_name (optional)
                                    try:
                                        json_data = json.loads(line)
                                    except json.JSONDecodeError as je:
                                        logging.getLogger(__name__).warning(
                                            "Skipping invalid JSON line in netexec output: %s (error: %s)" % (line, str(je)))
                                        continue

                                    # Extract required fields from JSON
                                    if 'host' not in json_data or 'port' not in json_data or 'hostname' not in json_data:
                                        logging.getLogger(__name__).warning(
                                            "Skipping netexec output line missing required fields: %s" % line)
                                        continue

                                    # Preprocess: Skip redundant display/info messages if they don't contain actionable data
                                    output_type = json_data.get('type', '')
                                    output_level = json_data.get('level', '')
                                    message = json_data.get('message', '')

                                    protocol_out = json_data.get(
                                        'protocol', protocol)
                                    ip_address = json_data.get('host')
                                    port_str = str(json_data.get('port'))
                                    hostname = json_data.get('hostname')
                                    module_name = json_data.get(
                                        'module_name', None)
                                    server_os = json_data.get(
                                        'server_os', None)

                                    # Parse INFO messages to extract domain information
                                    # Example: "(name:WIN-JRO991PA8A2) (domain:CONTOSO)"
                                    domain_info = None
                                    if output_level in ['INFO'] and message:
                                        # Use regex to extract name and domain from message
                                        name_match = re.search(
                                            r'\(name:([^)]+)\)', message)
                                        domain_match = re.search(
                                            r'\(domain:([^)]+)\)', message)

                                        if name_match and domain_match:
                                            name_value = name_match.group(
                                                1).strip()
                                            domain_value = domain_match.group(
                                                1).strip()

                                            # Only create domain object if name and domain differ
                                            if name_value.upper() != domain_value.upper():
                                                # Create FQDN: name.domain
                                                domain_info = f"{name_value}.{domain_value}"

                                    # Parse credentials from success messages
                                    credential_obj = None
                                    if output_type in ['success'] and message:
                                        # Message format: "DOMAIN\username:password" or "DOMAIN\username:password (Pwn3d!)"
                                        if '\\' in message and ':' in message:
                                            try:
                                                # Extract credential parts from message
                                                # Example: "WIN-JRO991PA8A2\\Administrator:password (Pwn3d!)"
                                                credential_part = message.split(
                                                    '(')[0].strip()
                                                domain_username, password = credential_part.rsplit(
                                                    ':', 1)
                                                domain_or_host, username = domain_username.split(
                                                    '\\', 1)

                                                # Determine if this is a host or domain credential
                                                # If domain_or_host matches hostname, it's a host credential
                                                parent_id = None
                                                if domain_or_host.upper() == hostname.upper():
                                                    # Host credential - will be set later when we have host_id
                                                    parent_id = 'HOST'
                                                else:
                                                    # Domain credential - will be set later when we have domain_id
                                                    parent_id = 'DOMAIN'

                                                # Check if credential is privileged (Pwn3d! in message)
                                                is_privileged = 'Pwn3d' in message

                                                # Store credential info for later creation
                                                credential_obj = {
                                                    'username': username,
                                                    'password': password,
                                                    'privileged': is_privileged,
                                                    'parent_type': parent_id,
                                                    'domain_name': domain_or_host if parent_id == 'DOMAIN' else None
                                                }

                                            except Exception as cred_err:
                                                logging.getLogger(__name__).warning(
                                                    "Failed to parse credential from message '%s': %s" % (message, str(cred_err)))

                                    # Create consolidation key: (host, port, hostname, protocol, module_name)
                                    consolidation_key = (
                                        ip_address, port_str, hostname, protocol_out, module_name, server_os)

                                    # Add or update consolidated data
                                    if consolidation_key not in consolidated_data:
                                        consolidated_data[consolidation_key] = {
                                            'messages': [],
                                            'output_level': output_level,
                                            'output_type': output_type,
                                            'timestamps': []
                                        }

                                    # Append message to the list for this consolidation key
                                    consolidated_data[consolidation_key]['timestamps'].append(
                                        json_data.get('timestamp', ''))

                                    # Store credential info if parsed
                                    if credential_obj:
                                        if 'credentials' not in consolidated_data[consolidation_key]:
                                            consolidated_data[consolidation_key]['credentials'] = [
                                            ]
                                        consolidated_data[consolidation_key]['credentials'].append(
                                            credential_obj)
                                    else:
                                        consolidated_data[consolidation_key]['messages'].append(
                                            message)

                                    # Store domain info if parsed
                                    if domain_info:
                                        if 'domain_info' not in consolidated_data[consolidation_key]:
                                            consolidated_data[consolidation_key]['domain_info'] = [
                                            ]
                                        consolidated_data[consolidation_key]['domain_info'].append(
                                            domain_info)

                            # Second pass: Create data model objects from consolidated data
                            # Track created objects to avoid duplicates
                            # Key: IP address, Value: host_obj
                            host_obj_map: Dict[str, Any] = {}
                            # Key: (host_id, port), Value: port_id
                            port_id_map: Dict[tuple, str] = {}
                            # Key: domain name, Value: domain_obj
                            domain_obj_map: Dict[str, Any] = {}
                            # Key: host_id, Value: (os_name, os_obj) - track OS objects to prevent duplicates
                            host_os_map: Dict[str, tuple] = {}

                            for consolidation_key, consolidated_entry in consolidated_data.items():
                                ip_address, port_str, hostname, protocol_out, module_name, server_os = consolidation_key

                                # Create or retrieve Host object using IP address as key
                                if ip_address not in host_obj_map:
                                    # Create new Host object with proper IPv4/IPv6 handling
                                    ip_object = netaddr.IPAddress(ip_address)

                                    host_obj = data_model.Host(id=None)
                                    host_obj.collection_tool_instance_id = tool_instance_id

                                    # Set appropriate IP address field based on version
                                    if ip_object.version == 4:
                                        host_obj.ipv4_addr = str(ip_object)
                                    elif ip_object.version == 6:
                                        host_obj.ipv6_addr = str(ip_object)

                                    host_obj_map[ip_address] = host_obj

                                    # Add host object to results
                                    ret_arr.append(host_obj)

                                else:
                                    # Reuse existing host object
                                    host_obj = host_obj_map[ip_address]

                                # Get host_id from object
                                host_id = host_obj.id

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
                                    if hostname not in domain_obj_map:
                                        # Create new domain object linked to host
                                        domain_obj = data_model.Domain(
                                            parent_id=host_id)
                                        domain_obj.collection_tool_instance_id = tool_instance_id
                                        domain_obj.name = hostname
                                        domain_obj_map[hostname] = domain_obj

                                        # Add domain object to results
                                        ret_arr.append(domain_obj)
                                    else:
                                        # Reuse existing domain object
                                        domain_obj = domain_obj_map[hostname]

                                # Create FQDN domain objects from parsed domain_info
                                if 'domain_info' in consolidated_entry:
                                    for domain_info in consolidated_entry['domain_info']:
                                        if domain_info not in domain_obj_map:
                                            # Create new FQDN domain object linked to host
                                            fqdn_domain_obj = data_model.Domain(
                                                parent_id=host_id)
                                            fqdn_domain_obj.collection_tool_instance_id = tool_instance_id
                                            fqdn_domain_obj.name = domain_info
                                            domain_obj_map[domain_info] = fqdn_domain_obj

                                            # Add FQDN domain object to results
                                            ret_arr.append(fqdn_domain_obj)

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

                                # Create credential objects if any were parsed
                                if 'credentials' in consolidated_entry:

                                    for cred_info in consolidated_entry['credentials']:
                                        # Create credential object
                                        cred_obj = data_model.Credential()
                                        cred_obj.collection_tool_instance_id = tool_instance_id
                                        cred_obj.username = cred_info['username']
                                        cred_obj.password = cred_info['password']
                                        ret_arr.append(cred_obj)

                                        # Set credential_id on host or domain object
                                        if cred_info['parent_type'] == 'HOST':
                                            # Set credential_id on host object
                                            host_obj.credential = {
                                                'credential_id': cred_obj.id, 'privileged': cred_info['privileged']}

                                        # elif cred_info['parent_type'] == 'DOMAIN':
                                        #     # Need to find or create domain object for this credential
                                        #     domain_name = cred_info.get(
                                        #         'domain_name')
                                        #     if domain_name:
                                        #         if domain_name in domain_obj_map:
                                        #             # Set credential_id on existing domain object
                                        #             target_domain_obj = domain_obj_map[domain_name]
                                        #             target_domain_obj.credential = {
                                        #                 'credential_id': cred_obj.id, 'privileged': cred_info['privileged']}
                                        #         else:
                                        #             # Create domain if it doesn't exist
                                        #             new_domain_obj = data_model.Domain(
                                        #                 parent_id=host_id)
                                        #             new_domain_obj.collection_tool_instance_id = tool_instance_id
                                        #             new_domain_obj.name = domain_name
                                        #             new_domain_obj.credential_id = cred_obj.id
                                        #             domain_obj_map[domain_name] = new_domain_obj
                                        #             ret_arr.append(
                                        #                 new_domain_obj)

                        except Exception as e:
                            logging.getLogger(__name__).error(
                                "Error processing netexec output file %s: %s" % (netexec_out, str(e)))
                            traceback.print_exc()

        # Import, Update, & Save
        self.import_results(scheduled_scan_obj, ret_arr)
