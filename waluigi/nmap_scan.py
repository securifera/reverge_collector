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

Author: Waluigi Security Framework  
License: Internal Use
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
        self.name: str = 'nmap'
        self.description: str = 'Nmap is a network scanning tool used to discover hosts and services on a computer network. It can be used to perform port scanning, service detection, and OS detection.'
        self.project_url: str = "https://github.com/nmap/nmap"
        self.collector_type: str = data_model.CollectorType.ACTIVE.value
        self.scan_order: int = 6
        self.args: str = "-sV --script +ssl-cert --script-args ssl=True"
        self.scan_func = Nmap.nmap_scan_func
        self.import_func = Nmap.nmap_import

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
                scan_utils.process_wrapper,
                cmd_args=command,
                pid_callback=callback_with_tool_id))
            counter += 1

        # Register futures for process tracking
        scan_proc_inst = data_model.ToolExecutor(futures)
        scheduled_scan_obj.register_tool_executor(
            scheduled_scan_obj.current_tool_instance_id, scan_proc_inst)

        # Wait for all scans to complete
        for future in futures:
            future.result()

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
