"""
Nmap network scanning module for the Waluigi framework.

This module provides comprehensive network scanning capabilities using Nmap, the industry-standard
network discovery and security auditing tool. It implements port scanning, service detection,
OS fingerprinting, and SSL certificate analysis through Luigi task orchestration.

The module supports both subnet-based and targeted scanning, with intelligent scan optimization
based on previous masscan results. It processes XML output to extract detailed host, port,
service, and certificate information.

Classes:
    Nmap: Tool configuration class for Nmap scanner
    NmapScan: Luigi task for executing Nmap network scans
    ImportNmapOutput: Luigi task for processing and importing Nmap scan results

Functions:
    remove_dups_from_dict: Utility function to remove duplicate script results

"""

from functools import partial
import json
import os
import shutil
from typing import Dict, Any, List, Set, Optional, Union
import netaddr
import luigi
import traceback
import time
import logging

from luigi.util import inherits
from libnmap.parser import NmapParser
from waluigi import scan_utils
from waluigi import data_model
from waluigi.proc_utils import process_wrapper
from datetime import datetime


class Nmap(data_model.WaluigiTool):
    """
    Nmap network scanner tool configuration.

    This class configures the Nmap network scanner for integration with the
    Waluigi framework. Nmap is the industry-standard network discovery and
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
        >>> nmap_tool = Nmap()
        >>> print(nmap_tool.name)
        'nmap'
        >>> nmap_tool.scan_func(scan_input)
        True
    """

    def __init__(self) -> None:
        """
        Initialize Nmap tool configuration.

        Sets up the tool with default parameters for comprehensive network
        scanning including service version detection and SSL certificate
        analysis with script execution.
        """
        super().__init__()
        self.name: str = 'nmap'
        self.description: str = 'Nmap is a network scanning tool used to discover hosts and services on a computer network. It can be used to perform port scanning, service detection, and OS detection.'
        self.project_url: str = "https://github.com/nmap/nmap"
        self.collector_type: str = data_model.CollectorType.ACTIVE.value
        self.scan_order: int = 6
        self.args: str = "-sV --script +ssl-cert --script-args ssl=True"
        self.scan_func = Nmap.nmap_scan_func
        self.import_func = Nmap.nmap_import
        self.modules_func = Nmap.nmap_modules
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
    def nmap_modules() -> List:
        """
        Retrieve available Nmap NSE scripts as collection modules.

        Executes 'nmap --script-help' to discover all available Nmap Scripting
        Engine (NSE) scripts and converts them to CollectionModule objects.
        Each script becomes a module that can be selectively enabled for scanning.

        Returns:
            List[data_model.CollectionModule]: List of collection modules, one for each NSE script

        Example:
            >>> nmap_tool = Nmap()
            >>> modules = nmap_tool.modules_func()
            >>> for module in modules:
            ...     print(f"{module.name}: {module.args}")
        """
        modules = []

        try:
            # Execute nmap --script-help to get list of all scripts
            cmd_args = ['nmap', '--script-help', 'all']
            result = process_wrapper(cmd_args=cmd_args, store_output=True)

            if result and 'exit_code' in result and result['exit_code'] != 0:
                logging.getLogger(__name__).warning(
                    f"nmap --script-help failed with exit code {result['exit_code']}"
                )
                return modules

            output = result.get('stdout', '') if result else ''

            # Parse the output - format is:
            # script-name
            # Categories: cat1 cat2 cat3
            # https://nmap.org/nsedoc/scripts/script-name.html
            #   Description (potentially multi-line, indented with tabs)
            # (blank line)

            lines = output.split('\n')
            i = 0

            while i < len(lines):
                line = lines[i]

                # Skip empty lines
                if not line.strip():
                    i += 1
                    continue

                # Line 1: Script name (not indented)
                if not line.startswith('\t') and not line.startswith(' '):
                    script_name = line.strip()

                    # Line 2: Categories
                    i += 1
                    if i < len(lines) and lines[i].startswith('Categories:'):
                        categories = lines[i].replace(
                            'Categories:', '').strip()
                    else:
                        categories = ''

                    # Line 3: URL
                    i += 1
                    if i < len(lines) and lines[i].startswith('http'):
                        url = lines[i].strip()
                    else:
                        url = ''

                    # Lines 4+: Description (indented lines until empty line)
                    description_parts = []
                    i += 1
                    while i < len(lines):
                        if not lines[i].strip():
                            # Empty line marks end of this script entry
                            break
                        if lines[i].startswith('\t') or lines[i].startswith('  '):
                            description_parts.append(lines[i].strip())
                        i += 1

                    # Create CollectionModule for this script
                    module = data_model.CollectionModule()
                    module.name = script_name
                    module.description = ' '.join(description_parts).strip()
                    module.args = f"--script +{script_name}"
                    modules.append(module)

                i += 1

        except FileNotFoundError:
            logging.getLogger(__name__).error("nmap command not found")
        except Exception as e:
            logging.getLogger(__name__).error(
                f"Error getting nmap modules: {str(e)}"
            )
            logging.getLogger(__name__).debug(traceback.format_exc())

        return modules

    @staticmethod
    def nmap_scan_func(scan_input: data_model.ScheduledScan) -> bool:
        """
        Execute Nmap network scan.

        Initiates an Nmap scan using Luigi task orchestration. The scan targets
        are processed from the scheduled scan input, with intelligent optimization
        based on previous masscan results when available.

        Args:
            scan_input (data_model.ScheduledScan): Scheduled scan configuration
                containing target information and scan parameters

        Returns:
            bool: True if scan completed successfully, False otherwise

        Example:
            >>> scan_input = ScheduledScan(...)
            >>> success = Nmap.nmap_scan_func(scan_input)
            >>> print(success)
            True
        """
        luigi_run_result = luigi.build([NmapScan(
            scan_input=scan_input)], local_scheduler=True, detailed_summary=True)
        if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
            return False
        return True

    @staticmethod
    def nmap_import(scan_input: data_model.ScheduledScan) -> bool:
        """
        Import and process Nmap scan results.

        Processes the XML output from completed Nmap scans, parsing detailed
        host information, open ports, services, SSL certificates, and script
        results into the data model.

        Args:
            scan_input (data_model.ScheduledScan): Scheduled scan configuration
                containing scan results to import

        Returns:
            bool: True if import completed successfully, False otherwise

        Example:
            >>> scan_input = ScheduledScan(...)
            >>> success = Nmap.nmap_import(scan_input)
            >>> print(success)
            True
        """
        luigi_run_result = luigi.build([ImportNmapOutput(
            scan_input=scan_input)], local_scheduler=True, detailed_summary=True)
        if luigi_run_result and luigi_run_result.status != luigi.execution_summary.LuigiStatusCode.SUCCESS:
            return False
        return True


class NmapScan(luigi.Task):
    """
    Luigi task for executing Nmap network scans.

    This task orchestrates the execution of Nmap scans against target networks,
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
        >>> scan_task = NmapScan(scan_input=scheduled_scan)
        >>> scan_task.run()
        # Executes Nmap scan and saves XML results
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
            >>> task = NmapScan(scan_input=scan)
            >>> target = task.output()
            >>> print(target.path)
            '/path/to/outputs/nmap_scan_scan123.meta'
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
            "nmap_scan_" + scan_id + mod_str + ".meta"

        return luigi.LocalTarget(meta_file_path)

    def run(self) -> None:
        """
        Execute the Nmap network scan.

        Processes target networks and ports, creates optimized scan jobs, and
        executes Nmap with appropriate arguments. The method handles different
        scanning scenarios:

        1. Post-masscan optimization: Scans only discovered ports on specific IPs
        2. Subnet scanning: Comprehensive scans across network ranges
        3. Targeted scanning: Specific host-port combinations
        4. Full scope scanning: All hosts and ports in scope

        The method:
        - Analyzes previous scan results for optimization
        - Prepares target lists and port specifications
        - Constructs Nmap command arguments
        - Executes parallel scan jobs
        - Collects XML output files for import

        Raises:
            Exception: If scan execution fails or output cannot be written

        Example:
            >>> task = NmapScan(scan_input=scheduled_scan)
            >>> task.run()
            # Executes optimized Nmap scans and writes metadata
        """
        scheduled_scan_obj = self.scan_input
        selected_interface = scheduled_scan_obj.selected_interface

        # Ensure output folder exists
        meta_file_path: str = self.output().path
        dir_path: str = os.path.dirname(meta_file_path)

        # Load input file
        scope_obj = scheduled_scan_obj.scan_data

        nmap_scan_data: Optional[Dict[str, Any]] = None
        nmap_scan_args: Optional[List[str]] = None
        if scheduled_scan_obj.current_tool.args:
            nmap_scan_args = scheduled_scan_obj.current_tool.args.split(" ")

        # Check if masscan was already run for optimization
        mass_scan_ran: bool = False
        for collection_tool in scheduled_scan_obj.collection_tool_map.values():
            if collection_tool.collection_tool.name == 'masscan':
                mass_scan_ran = True
                break

        nmap_scan_list: List[Dict[str, Any]] = []
        scan_port_map: Dict[str, Dict[str, Any]] = {}

        if mass_scan_ran:
            # Create optimized scan jobs for each port with only discovered IPs
            target_map: Dict[str, Dict[str, Any]] = scope_obj.host_port_obj_map

            for target_key in target_map:
                target_obj_dict = target_map[target_key]
                port_obj = target_obj_dict['port_obj']
                port_str: str = port_obj.port

                host_obj = target_obj_dict['host_obj']
                ip_addr: str = host_obj.ipv4_addr

                # Get or create scan object for this port
                if port_str in scan_port_map:
                    scan_obj = scan_port_map[port_str]
                else:
                    scan_obj: Dict[str, Any] = {
                        'port_list': [str(port_str)],
                        'tool_args': nmap_scan_args,
                        'resolve_dns': False
                    }
                    scan_port_map[port_str] = scan_obj

                # Add the targets
                if 'ip_set' not in scan_obj:
                    scan_obj['ip_set'] = set()
                ip_set: Set[str] = scan_obj['ip_set']

                # Add IP
                ip_set.add(ip_addr)

                # Add domain if different from IP
                target_arr: List[str] = target_key.split(":")
                if target_arr[0] != ip_addr:
                    domain_str: str = target_arr[0]
                    scan_obj['resolve_dns'] = True
                    ip_set.add(domain_str)

            nmap_scan_list.extend(list(scan_port_map.values()))

        else:
            # Use original scope for comprehensive scanning
            target_map = scope_obj.host_port_obj_map
            port_num_list: List[str] = scope_obj.get_port_number_list_from_scope(
            )

            # Create scan for each subnet with all ports
            subnet_map: Dict[int, Any] = scope_obj.subnet_map
            if len(subnet_map) > 0:
                for subnet_id in subnet_map:
                    subnet_obj = subnet_map[subnet_id]
                    subnet_str: str = "%s/%s" % (subnet_obj.subnet,
                                                 subnet_obj.mask)

                    scan_obj: Dict[str, Any] = {
                        'ip_set': [subnet_str],
                        'tool_args': nmap_scan_args,
                        'resolve_dns': False,
                        'port_list': list(set(port_num_list))
                    }
                    nmap_scan_list.append(scan_obj)

            elif len(target_map) > 0:
                # Process individual targets
                for target_key in target_map:
                    target_obj_dict = target_map[target_key]
                    port_obj = target_obj_dict['port_obj']
                    port_str = port_obj.port

                    host_obj = target_obj_dict['host_obj']
                    ip_addr = host_obj.ipv4_addr

                    # Get or create scan object for this port
                    if port_str in scan_port_map:
                        scan_obj = scan_port_map[port_str]
                    else:
                        scan_obj = {
                            'port_list': [str(port_str)],
                            'tool_args': nmap_scan_args,
                            'resolve_dns': False
                        }
                        scan_port_map[port_str] = scan_obj

                    # Add the targets
                    if 'ip_set' not in scan_obj:
                        scan_obj['ip_set'] = set()
                    ip_set = scan_obj['ip_set']

                    # Add IP
                    ip_set.add(ip_addr)

                    # Add domain if different from IP
                    target_arr = target_key.split(":")
                    if target_arr[0] != ip_addr:
                        domain_str = target_arr[0]
                        scan_obj['resolve_dns'] = True
                        ip_set.add(domain_str)

                nmap_scan_list.extend(list(scan_port_map.values()))

            else:
                # Full scope scanning when no specific targets
                if len(port_num_list) > 0:
                    scan_obj: Dict[str, Any] = {}
                    target_set: Set[str] = set()
                    resolve_dns: bool = False

                    # Get all hosts in scope
                    host_list = scope_obj.get_hosts(
                        [data_model.RecordTag.SCOPE.value, data_model.RecordTag.LOCAL.value])

                    for host_obj in host_list:
                        ip_addr = host_obj.ipv4_addr
                        target_set.add(ip_addr)

                        # Add associated domains
                        if host_obj.id in scope_obj.domain_host_id_map:
                            temp_domain_list = scope_obj.domain_host_id_map[host_obj.id]
                            if len(temp_domain_list) > 0:
                                resolve_dns = True
                                for domain_obj in temp_domain_list:
                                    domain_name: str = domain_obj.name
                                    target_set.add(domain_name)

                    # Add standalone domains
                    domain_list = scope_obj.get_domains(
                        [data_model.RecordTag.SCOPE.value, data_model.RecordTag.LOCAL.value])
                    for domain_obj in domain_list:
                        domain_name = domain_obj.name
                        target_set.add(domain_name)

                    scan_obj['ip_set'] = target_set
                    scan_obj['tool_args'] = nmap_scan_args
                    scan_obj['resolve_dns'] = resolve_dns
                    scan_obj['port_list'] = list(set(port_num_list))

                    nmap_scan_list.append(scan_obj)

        # Prepare module string for file naming
        module_id: Optional[str] = None
        mod_str: str = ''
        if scheduled_scan_obj.scan_data.module_id:
            module_id = str(scheduled_scan_obj.scan_data.module_id)
            mod_str = "_" + module_id

        # Output structure for scan jobs
        nmap_scan_cmd_list: List[Dict[str, Any]] = []
        nmap_scan_data = {}

        # Create and execute nmap commands
        counter: int = 0
        futures: List[Any] = []

        for scan_obj in nmap_scan_list:
            nmap_scan_inst: Dict[str, Any] = {}
            script_args: Optional[List[str]] = scan_obj.get('tool_args')
            port_list: List[str] = scan_obj['port_list']
            port_comma_list: str = ','.join(port_list)

            ip_list_path: str = dir_path + os.path.sep + \
                "nmap_in_" + str(counter) + mod_str

            # Write IPs to input file
            ip_list: Union[Set[str], List[str]] = scan_obj['ip_set']
            if len(ip_list) == 0:
                continue

            with open(ip_list_path, 'w') as in_file_fd:
                for ip in ip_list:
                    in_file_fd.write(ip + "\n")

            # Prepare output file
            nmap_output_xml_file: str = dir_path + os.path.sep + \
                "nmap_out_" + str(counter) + mod_str

            # Build command arguments
            command: List[str] = []
            if os.name != 'nt':
                command.append("sudo")

            command_arr: List[str] = [
                "nmap",
                "-v",
                "-Pn",
                "--open",
                "--host-timeout",
                "30m",
                "--script-timeout",
                "2m",
                "--script-args",
                'http.useragent="%s"' % scan_utils.custom_user_agent,
                "-sT",
                "-p",
                port_comma_list,
                "-oX",
                nmap_output_xml_file,
                "-iL",
                ip_list_path
            ]

            # Add network interface if specified
            if selected_interface:
                int_name: str = selected_interface.name.strip()
                command_arr.extend(['-e', int_name])

            command.extend(command_arr)

            # Configure DNS resolution
            resolve_dns: bool = scan_obj['resolve_dns']
            if not resolve_dns:
                command.append("-n")

            # Add script arguments
            if script_args and len(script_args) > 0:
                command.extend(script_args)

            # Store scan metadata
            nmap_scan_inst['nmap_command'] = command
            nmap_scan_inst['output_file'] = nmap_output_xml_file
            nmap_scan_cmd_list.append(nmap_scan_inst)

            # Execute scan with process tracking
            callback_with_tool_id = partial(
                scheduled_scan_obj.register_tool_executor,
                scheduled_scan_obj.current_tool_instance_id)

            futures.append(scan_utils.executor.submit(
                process_wrapper,
                cmd_args=command,
                pid_callback=callback_with_tool_id))
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
                    if exit_code != 0:
                        err_msg = ''
                        if 'stderr' in ret_dict and ret_dict['stderr']:
                            err_msg = ret_dict['stderr']
                        logging.getLogger(__name__).error(
                            "Nmap scan for scan ID %s exited with code %d: %s" % (scheduled_scan_obj.id, exit_code, err_msg))
                        raise RuntimeError("Nmap scan for scan ID %s exited with code %d: %s" % (
                            scheduled_scan_obj.id, exit_code, err_msg))

        # Store scan metadata
        nmap_scan_data['nmap_scan_list'] = nmap_scan_cmd_list

        # Write metadata file
        if nmap_scan_data:
            with open(meta_file_path, 'w') as meta_file_fd:
                meta_file_fd.write(json.dumps(nmap_scan_data))


def remove_dups_from_dict(dict_array: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Remove duplicate script results from Nmap output.

    This utility function removes duplicate script results that may occur
    in Nmap output by converting each dictionary to a JSON string for
    comparison, then reconstructing unique entries.

    Args:
        dict_array (List[Dict[str, Any]]): Array of script result dictionaries
            that may contain duplicates

    Returns:
        List[Dict[str, Any]]: Array of unique script result dictionaries

    Example:
        >>> scripts = [{'id': 'ssl-cert', 'output': 'cert1'}, 
        ...           {'id': 'ssl-cert', 'output': 'cert1'},
        ...           {'id': 'http-title', 'output': 'title1'}]
        >>> unique_scripts = remove_dups_from_dict(scripts)
        >>> len(unique_scripts)
        2
    """
    ret_arr: List[Dict[str, Any]] = []
    script_set: Set[str] = set()

    # Convert each dict to JSON string for comparison
    for script_json in dict_array:
        script_entry: str = json.dumps(script_json)
        script_set.add(script_entry)

    # Reconstruct unique dictionaries
    for script_entry in script_set:
        script_json: Dict[str, Any] = json.loads(script_entry)
        ret_arr.append(script_json)

    return ret_arr


@inherits(NmapScan)
class ImportNmapOutput(data_model.ImportToolXOutput):
    """
    Luigi task for importing and processing Nmap scan results.

    This task handles the complete import and processing of Nmap XML output files,
    parsing detailed network information and integrating it into the Waluigi framework's
    data model. It processes host discovery, port scanning, service detection, 
    SSL certificate information, and script execution results.

    The import process includes:
        - Reading and parsing Nmap XML output files
        - Processing host information and network addresses
        - Extracting open ports and service details
        - Analyzing SSL certificates and subject alternative names
        - Processing Nmap script execution results
        - Creating comprehensive data model objects
        - Handling module-based scan results and outputs

    Key Features:
        - Robust XML parsing with error handling and recovery
        - Complete host and port information extraction
        - SSL certificate analysis with domain extraction
        - Service version and component detection
        - Script result processing and module correlation
        - Duplicate detection and data deduplication
        - Comprehensive logging and error reporting

    Attributes:
        Inherits all attributes from NmapScan and ImportToolXOutput

    Methods:
        requires: Specifies dependency on completed NmapScan task
        run: Main processing method for importing scan results

    Example:
        >>> # Task is executed as part of the Luigi workflow
        >>> import_task = ImportNmapOutput(scan_input=scan_obj)
        >>> luigi.build([import_task], local_scheduler=True)

    Note:
        This task creates comprehensive data model objects including hosts,
        ports, domains, certificates, web components, and module outputs
        with proper parent-child relationships and tracking information.
    """

    def requires(self) -> NmapScan:
        """
        Specify task dependencies for the import operation.

        Returns:
            NmapScan: The Nmap scan task that must complete before
                this import task can execute, providing XML output files.
        """
        return NmapScan(scan_input=self.scan_input)

    def run(self) -> None:
        """
        Import and process Nmap scan results into the framework's data model.

        This method performs comprehensive processing of Nmap XML output files,
        extracting detailed network information and creating appropriate data
        model objects. The process handles multiple XML files from parallel
        scan executions and correlates results with existing scan data.

        The import workflow includes:
            1. Reading scan metadata from the meta file
            2. Processing each XML output file from parallel scans
            3. Parsing host information and network addresses
            4. Extracting port details and service information
            5. Processing SSL certificates and extracting domains
            6. Analyzing Nmap script execution results
            7. Creating data model objects with proper relationships
            8. Handling module outputs and component detection
            9. Importing results into the framework database

        Data Processing Details:
            - Host Objects: Created for each discovered IP address with proper IPv4/IPv6 handling
            - Port Objects: Generated for each open port with protocol and service information
            - Domain Objects: Extracted from hostnames, certificates, and DNS resolution
            - Certificate Objects: Comprehensive SSL/TLS certificate analysis with validity dates
            - Component Objects: Service and product detection from version scanning
            - Module Outputs: Script results and specialized scan module data

        Error Handling:
            - Graceful handling of malformed XML files
            - Comprehensive logging of parsing errors
            - Automatic cleanup of corrupted scan directories
            - Continuation of processing despite individual file failures

        Raises:
            Exception: If critical XML parsing errors occur that prevent
                processing, or if scan directory cleanup fails.

        Example:
            >>> import_task = ImportNmapOutput(scan_input=scan_obj)
            >>> import_task.run()  # Processes all XML files and imports results

        Note:
            The method handles both individual host scanning and subnet-based
            scanning results, with intelligent correlation of existing scope
            data and optimization based on previous scan results.
        """

        scheduled_scan_obj = self.scan_input
        tool_instance_id = scheduled_scan_obj.current_tool_instance_id
        scope_obj = scheduled_scan_obj.scan_data
        tool_obj = scheduled_scan_obj.current_tool
        tool_id = tool_obj.id

        # Initialize result array for data model objects
        ret_arr: List[Any] = []

        # Read scan metadata file containing output file paths
        meta_file = self.input().path
        if os.path.exists(meta_file):

            with open(meta_file) as file_fd:
                json_input = file_fd.read()

            # Process scan metadata and XML output files
            if len(json_input) > 0:
                nmap_scan_obj = json.loads(json_input)
                nmap_json_arr = nmap_scan_obj['nmap_scan_list']

                # Process each parallel scan output file
                for nmap_scan_entry in nmap_json_arr:

                    # Parse Nmap XML output with error handling
                    nmap_out = nmap_scan_entry['output_file']
                    nmap_report = None
                    try:
                        if os.path.exists(nmap_out) and os.path.getsize(nmap_out) > 0:
                            # Use libnmap parser for robust XML processing
                            nmap_report = NmapParser.parse_fromfile(nmap_out)
                        else:
                            logging.getLogger(__name__).warning(
                                f"Skipping nmap output file {nmap_out}: file does not exist or is empty."
                            )
                            continue
                    except Exception as e:
                        logging.getLogger(__name__).error(
                            "Failed parsing nmap output: %s" % nmap_out)
                        logging.getLogger(__name__).error(
                            traceback.format_exc())

                        try:
                            dir_path = os.path.dirname(meta_file)
                            shutil.rmtree(dir_path)
                        except Exception as e:
                            pass

                        raise

                    # Process each discovered host in the scan results
                    for host in nmap_report.hosts:

                        host_ip = host.id  # Primary IP address for the host
                        host_id = None  # Will be populated from existing scope or created new

                        # Process each open port discovered on this host
                        for port in host.get_open_ports():

                            port_str = str(port[0])  # Port number as string
                            # Service identifier (protocol.port)
                            port_service_id = port[1] + "." + port_str

                            # Attempt to correlate with existing scope data
                            port_id = None
                            host_key = '%s:%s' % (host_ip, port_str)

                            # Check for existing host:port mapping in scope
                            if host_key in scope_obj.host_port_obj_map:
                                host_port_dict = scope_obj.host_port_obj_map[
                                    host_key]
                                port_id = host_port_dict['port_obj'].id
                                host_id = host_port_dict['host_obj'].id

                            # Alternative: Check for existing host by IP only
                            elif host_ip in scope_obj.host_ip_id_map:
                                host_id = scope_obj.host_ip_id_map[host_ip]

                            # Create or update Host object with proper IPv4/IPv6 handling
                            ip_object = netaddr.IPAddress(host_ip)

                            host_obj = data_model.Host(id=host_id)
                            host_obj.collection_tool_instance_id = tool_instance_id

                            # Set appropriate IP address field based on version
                            if ip_object.version == 4:
                                host_obj.ipv4_addr = str(ip_object)
                            elif ip_object.version == 6:
                                host_obj.ipv6_addr = str(ip_object)

                            host_id = host_obj.id

                            # Add host object to results
                            ret_arr.append(host_obj)

                            # Create Port object with parent relationship to host
                            port_obj = data_model.Port(
                                parent_id=host_id, id=port_id)
                            port_obj.collection_tool_instance_id = tool_instance_id
                            # TCP protocol (0 = TCP, 1 = UDP)
                            port_obj.proto = 0
                            port_obj.port = port_str
                            port_id = port_obj.id

                            # Add port object to results
                            ret_arr.append(port_obj)

                            # Process discovered hostnames and create domain objects
                            hostnames = host.hostnames
                            for hostname in hostnames:

                                # Handle both string and dictionary hostname formats
                                if type(hostname) is dict:
                                    hostname = hostname['name']

                                # Create domain object linked to host
                                domain_obj = data_model.Domain(
                                    parent_id=host_id)
                                domain_obj.collection_tool_instance_id = tool_instance_id
                                domain_obj.name = hostname

                                # Add domain object to results
                                ret_arr.append(domain_obj)

                            # Process service version detection results
                            svc = host.get_service_byid(port_service_id)
                            if svc:

                                # Extract service information from Nmap results
                                # Note: Banner information available but not currently processed
                                # if svc.banner and len(svc.banner) > 0:
                                #     port_obj.banner = svc.banner

                                # Process service detection dictionary
                                svc_dict = svc.service_dict

                                # Extract service name and create web component
                                if 'name' in svc.service_dict:
                                    service_name = svc.service_dict['name']
                                    if service_name:
                                        component_name = service_name.lower().strip()
                                        if len(component_name) > 0 and component_name != "unknown":
                                            component_obj = data_model.WebComponent(
                                                parent_id=port_id)
                                            component_obj.collection_tool_instance_id = tool_instance_id
                                            component_obj.name = component_name
                                            ret_arr.append(component_obj)

                                # Extract product information with version details
                                if 'product' in svc_dict:
                                    component_name = svc_dict['product']
                                    # Clean product name (remove common suffixes like " httpd")
                                    component_name = component_name.replace(
                                        " httpd", "").lower().strip()
                                    if len(component_name) > 0 and component_name != "unknown":

                                        component_obj = data_model.WebComponent(
                                            parent_id=port_id)
                                        component_obj.collection_tool_instance_id = tool_instance_id
                                        component_obj.name = component_name

                                        # Add version information if available
                                        if 'version' in svc_dict:
                                            component_version = svc_dict['version']
                                            if len(component_version) > 0:
                                                component_obj.version = component_version

                                        ret_arr.append(component_obj)

                                # Process Nmap script execution results
                                script_res_arr = svc.scripts_results
                                if len(script_res_arr) > 0:

                                    # Remove duplicate script results
                                    script_res = remove_dups_from_dict(
                                        script_res_arr)

                                    # Add domains in certificate to port if SSL
                                    for script in script_res:

                                        script_id = script['id']
                                        if script_id == 'ssl-cert':

                                            if port_obj:
                                                port_obj.secure = True

                                            # Create a certificate object
                                            cert_obj = data_model.Certificate(
                                                parent_id=port_obj.id)
                                            cert_obj.collection_tool_instance_id = tool_instance_id
                                            if 'elements' in script:
                                                elements = script['elements']
                                                if 'validity' in elements:
                                                    validity = elements['validity']
                                                    if 'notBefore' in validity:
                                                        issued = validity['notBefore']

                                                        dt = datetime.strptime(
                                                            issued, '%Y-%m-%dT%H:%M:%S')
                                                        cert_obj.issued = int(
                                                            time.mktime(dt.timetuple()))

                                                    if 'notAfter' in validity:
                                                        expires = validity['notAfter']

                                                        dt = datetime.strptime(
                                                            expires, '%Y-%m-%dT%H:%M:%S')
                                                        cert_obj.expires = int(
                                                            time.mktime(dt.timetuple()))

                                                if 'sha1' in elements:
                                                    fingerprint_hash = elements['sha1']
                                                    cert_obj.fingerprint_hash = fingerprint_hash

                                                if 'subject' in elements:
                                                    subject = elements['subject']
                                                    if 'commonName' in subject:
                                                        common_name = subject['commonName']
                                                        domain_obj = cert_obj.add_domain(
                                                            host_id, common_name, tool_instance_id)
                                                        if domain_obj:
                                                            ret_arr.append(
                                                                domain_obj)

                                                if 'issuer' in elements:
                                                    issuer = elements['issuer']
                                                    cert_obj.issuer = json.dumps(
                                                        issuer)

                                                if 'extensions' in elements:
                                                    extensions = elements['extensions']
                                                    if 'null' in extensions:
                                                        null_ext = extensions['null']
                                                        if not isinstance(null_ext, list):
                                                            null_ext = [
                                                                null_ext]

                                                        for ext_inst in null_ext:
                                                            if 'name' in ext_inst:
                                                                ext_name = ext_inst['name']
                                                                if 'X509v3 Subject Alternative Name' == ext_name:
                                                                    san_value = ext_inst['value']
                                                                    if ":" in san_value:
                                                                        dns_name = san_value.split(":")[
                                                                            1]
                                                                        if "," in dns_name:
                                                                            dns_name = dns_name.split(",")[
                                                                                0]
                                                                        # logging.getLogger(__name__).debug(
                                                                        #    "Adding SAN: %s" % dns_name)
                                                                        domain_obj = cert_obj.add_domain(
                                                                            host_id, dns_name, tool_instance_id)
                                                                        if domain_obj:
                                                                            ret_arr.append(
                                                                                domain_obj)

                                            # Add the cert object
                                            ret_arr.append(cert_obj)

                                        elif 'http' in script_id:
                                            # Set to http if nmap detected http in a script
                                            component_obj = data_model.WebComponent(
                                                parent_id=port_id)
                                            component_obj.collection_tool_instance_id = tool_instance_id
                                            component_obj.name = 'http'
                                            ret_arr.append(component_obj)

                                    # Iterate over script entries
                                    for script_out in script_res:
                                        if 'id' in script_out and 'output' in script_out:

                                            script_id = script_out['id']
                                            output = script_out['output']
                                            if len(output) > 0:

                                                # Add collection module
                                                temp_module_id = None
                                                if scope_obj.module_id:
                                                    temp_module_id = scope_obj.module_id

                                                    # Parse output and add components if present
                                                    output_components = scope_obj.module_outputs
                                                    for output_component in output_components:
                                                        if output_component.name in output.lower():
                                                            component_obj = data_model.WebComponent(
                                                                parent_id=port_id)
                                                            component_obj.collection_tool_instance_id = tool_instance_id
                                                            component_obj.name = output_component.name
                                                            ret_arr.append(
                                                                component_obj)

                                                else:
                                                    args_str = "--script +%s" % script_id
                                                    module_obj = data_model.CollectionModule(
                                                        parent_id=tool_id)
                                                    module_obj.collection_tool_instance_id = tool_instance_id
                                                    module_obj.name = script_id
                                                    module_obj.args = args_str

                                                    ret_arr.append(module_obj)
                                                    temp_module_id = module_obj.id

                                                # Add module output
                                                module_output_obj = data_model.CollectionModuleOutput(
                                                    parent_id=temp_module_id)
                                                module_output_obj.collection_tool_instance_id = tool_instance_id
                                                module_output_obj.output = output
                                                module_output_obj.port_id = port_id

                                                ret_arr.append(
                                                    module_output_obj)

        # Import, Update, & Save
        self.import_results(scheduled_scan_obj, ret_arr)
