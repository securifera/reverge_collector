"""
Feroxbuster Web Directory Scanner Module.

This module provides comprehensive web directory scanning capabilities using Feroxbuster,
a fast, simple, and flexible web directory scanner written in Rust. It integrates with
the Waluigi framework to perform automated directory brute-forcing against web targets.

The module supports:
    - High-performance directory scanning with rate limiting
    - JSON output parsing and structured data extraction
    - Multi-target concurrent scanning
    - Domain and IP-based target resolution
    - HTTP endpoint discovery and cataloging
    - Integration with Luigi workflow management

Classes:
    Feroxbuster: Main tool class implementing the scanner interface
    FeroxScan: Luigi task for executing Feroxbuster scans
    ImportFeroxOutput: Luigi task for importing and processing scan results

Functions:
    queue_url: Queues URLs for scanning and manages output file mapping

Global Variables:
    url_set: Thread-safe set tracking queued URLs to prevent duplicates

Example:
    Basic usage through the Waluigi framework::
    
        # Initialize the tool
        ferox = Feroxbuster()
        
        # Execute scan
        success = ferox.scan_func(scan_input_obj)
        
        # Import results
        imported = ferox.import_func(scan_input_obj)

Note:
    This module requires Feroxbuster to be installed and available in the system PATH.
    The tool performs active scanning and should be used responsibly with proper
    authorization on target systems.

"""

from functools import partial
import json
import os
from typing import Dict, Any, Set, Optional, List, Union
import netaddr
import traceback
import random
import hashlib
import binascii
import logging

from waluigi import scan_utils
from urllib.parse import urlparse
from waluigi import data_model
from waluigi.proc_utils import process_wrapper
from waluigi.tool_runner import (
    import_already_done as _import_already_done,
    import_results as _import_results,
)

# Global URL tracking set to prevent duplicate scanning
url_set: Set[str] = set()


class Feroxbuster(data_model.WaluigiTool):
    """
    Feroxbuster web directory scanner integration for the Waluigi framework.

    This class provides integration with Feroxbuster, a fast, simple, and flexible
    web directory scanner written in Rust. It implements the WaluigiTool interface
    to provide directory brute-forcing capabilities within the reconnaissance workflow.

    Feroxbuster is particularly effective for discovering hidden directories and files
    on web servers through dictionary-based brute-force attacks with high performance
    and reliability.

    Attributes:
        name (str): The tool identifier ('feroxbuster')
        description (str): Human-readable description of the tool's purpose
        project_url (str): URL to the official Feroxbuster project repository
        collector_type (int): Identifies this as an active scanning tool
        scan_order (int): Execution priority within the scanning workflow (10)
        args (str): Default command-line arguments for optimal scanning
        scan_func (callable): Static method for executing scan operations
        import_func (callable): Static method for importing scan results

    Methods:
        feroxbuster_scan_func: Executes directory scanning operations
        feroxbuster_import: Imports and processes scan results

    Example:
        >>> tool = Feroxbuster()
        >>> print(tool.name)
        feroxbuster

        >>> # Execute scan through the framework
        >>> success = tool.scan_func(scan_input_obj)
        >>> if success:
        ...     imported = tool.import_func(scan_input_obj)

    Note:
        Default arguments include rate limiting (50 req/s), filtering for 200 status
        codes, and no recursion to balance performance with target server load.
        The scan_order of 10 positions this tool appropriately in the workflow.
    """

    def __init__(self) -> None:
        """
        Initialize the Feroxbuster tool with default configuration.

        Sets up the tool with optimized default parameters for web directory
        scanning, including rate limiting and response filtering to ensure
        effective and responsible scanning behavior.
        """
        super().__init__()
        self.name = 'feroxbuster'
        self.description = 'Feroxbuster is a fast, simple, and flexible web directory scanner written in Rust'
        self.project_url = "https://github.com/epi052/feroxbuster"
        self.tags = ['http-crawl']
        self.collector_type = data_model.CollectorType.ACTIVE.value
        self.scan_order = 10
        self.args = "--rate-limit 50 -s 200 -n --auto-bail"
        self.scan_func = Feroxbuster.feroxbuster_scan_func
        self.import_func = Feroxbuster.feroxbuster_import
        self.input_records = [data_model.ServerRecordType.PORT,
                              data_model.ServerRecordType.HTTP_ENDPOINT_DATA]
        self.output_records = [
            data_model.ServerRecordType.DOMAIN,
            data_model.ServerRecordType.LIST_ITEM,
            data_model.ServerRecordType.HTTP_ENDPOINT,
            data_model.ServerRecordType.HTTP_ENDPOINT_DATA
        ]

    @staticmethod
    def feroxbuster_scan_func(scan_input: Any) -> bool:
        """
        Execute Feroxbuster directory scanning operations.

        This static method serves as the entry point for executing Feroxbuster scans
        within the Waluigi framework. It builds and runs the FeroxScan Luigi task
        with the provided scan input configuration.

        Args:
            scan_input (Any): The scan input object containing target information,
                            tool configuration, and execution parameters

        Returns:
            bool: True if the scan completed successfully, False otherwise

        Example:
            >>> scan_obj = create_scan_input(...)  # Configure scan
            >>> success = Feroxbuster.feroxbuster_scan_func(scan_obj)
            >>> print(f"Scan successful: {success}")

        Note:
            Uses Luigi's local scheduler for task execution and provides detailed
            summary information for debugging and monitoring purposes.
        """
    @staticmethod
    def feroxbuster_scan_func(scan_input: Any) -> bool:
        try:
            execute_scan(scan_input)
            return True
        except Exception as e:
            logging.getLogger(__name__).error(
                "Feroxbuster scan failed: %s", e, exc_info=True)
            return False

    @staticmethod
    def feroxbuster_import(scan_input: Any) -> bool:
        try:
            output_path = get_output_path(scan_input)
            if not os.path.exists(output_path):
                return True
            if _import_already_done(scan_input, output_path):
                return True
            scheduled_scan_obj = scan_input
            tool_instance_id = scheduled_scan_obj.current_tool_instance_id
            ret_arr = parse_feroxbuster_output(output_path, tool_instance_id)
            _import_results(scan_input, ret_arr, output_path)
            return True
        except Exception as e:
            logging.getLogger(__name__).error(
                "Feroxbuster import failed: %s", e, exc_info=True)
            return False


def get_output_path(scan_input: Any) -> str:
    scan_id = scan_input.id
    tool_name = scan_input.current_tool.name
    dir_path = scan_utils.init_tool_folder(tool_name, 'outputs', scan_id)
    return dir_path + os.path.sep + "ferox_outputs_" + scan_id


def execute_scan(scan_input: Any) -> None:
    output_file_path = get_output_path(scan_input)
    if os.path.exists(output_file_path):
        return

    global url_set
    url_set = set()

    scheduled_scan_obj = scan_input
    output_dir = os.path.dirname(output_file_path)

    url_to_id_map = {}
    tool_args = scheduled_scan_obj.current_tool.args
    if tool_args:
        tool_args = tool_args.split(" ")

    scan_wordlist = None
    if scheduled_scan_obj.current_tool.wordlist_path and os.path.exists(scheduled_scan_obj.current_tool.wordlist_path):
        scan_wordlist = scheduled_scan_obj.current_tool.wordlist_path

    # Get all the URLs to scan using the same pattern as NucleiScan
    endpoint_url_map = scheduled_scan_obj.scan_data.get_urls()

    # Convert the endpoint URL map to the format expected by FeroxScan
    # Skip URLs that already have specific paths (not "/") since Feroxbuster discovers paths
    for url_str, url_metadata in endpoint_url_map.items():
        host_id = url_metadata.get('host_id')
        port_id = url_metadata.get('port_id')
        path = url_metadata.get('path')

        # Skip entries that have non-default paths since Feroxbuster is for path discovery
        if path is not None and path != "/":
            continue

        if url_str and url_str not in url_set:
            url_set.add(url_str)
            rand_str = str(random.randint(1000000, 2000000))

            # Add to url_to_id_map
            scan_output_file_path = output_dir + os.path.sep + "ferox_out_" + rand_str
            url_to_id_map[url_str] = {
                'port_id': port_id,
                'host_id': host_id,
                'output_file': scan_output_file_path
            }

    futures = []
    for target_url in url_to_id_map:

        # Get output file
        scan_output_file_path = url_to_id_map[target_url]['output_file']

        command = []
        if os.name != 'nt':
            command.append("sudo")

        command_arr = [
            "feroxbuster",
            "--json",
            "-k",  # Disable cert validation
            "-A",  # Random User Agent
            "-u",
            target_url,
            "-o",
            scan_output_file_path
        ]

        command.extend(command_arr)

        # Add optional arguments
        if tool_args and len(tool_args) > 0:
            command.extend(tool_args)

        # Add wordlist if provided
        if scan_wordlist:
            command.extend(['-w', scan_wordlist])

        callback_with_tool_id = partial(
            scheduled_scan_obj.register_tool_executor, scheduled_scan_obj.current_tool_instance_id)

        futures.append(scan_utils.executor.submit(
            process_wrapper, cmd_args=command, pid_callback=callback_with_tool_id))

    # Register futures
    scan_proc_inst = data_model.ToolExecutor(futures)
    scheduled_scan_obj.register_tool_executor(
        scheduled_scan_obj.current_tool_instance_id, scan_proc_inst)

    results_dict = {'url_to_id_map': url_to_id_map}

    # Write output file
    with open(output_file_path, 'w') as file_fd:
        file_fd.write(json.dumps(results_dict))

    # Wait for the tasks to complete and retrieve results
    for future in futures:
        ret_dict = future.result()
        if ret_dict and 'exit_code' in ret_dict:
            exit_code = ret_dict['exit_code']
            if exit_code != 0:
                err_msg = ''
                if 'stderr' in ret_dict and ret_dict['stderr']:
                    err_msg = ret_dict['stderr']
                logging.getLogger(__name__).error(
                    "Feroxbuster scan for scan ID %s exited with code %d: %s" % (scheduled_scan_obj.id, exit_code, err_msg))
                raise RuntimeError("Feroxbuster scan for scan ID %s exited with code %d: %s" % (
                    scheduled_scan_obj.id, exit_code, err_msg))


def parse_feroxbuster_output(
    output_file: str,
    tool_instance_id: Optional[str] = None,
) -> List[Any]:
    """Parse a Feroxbuster JSON metadata output file and return data_model Record objects."""

    with open(output_file, 'r') as file_fd:
        data = file_fd.read()

    ret_arr = []
    path_hash_map = {}
    domain_name_id_map = {}
    hash_alg = hashlib.sha1

    if len(data) > 0:
        scan_data_dict = json.loads(data)

        url_to_id_map = scan_data_dict['url_to_id_map']
        for url_str in url_to_id_map:
            obj_data = url_to_id_map[url_str]
            scan_output_file = obj_data['output_file']
            port_id = obj_data['port_id']
            host_id = obj_data['host_id']

            obj_arr = scan_utils.parse_json_blob_file(scan_output_file)
            for web_result in obj_arr:
                if 'type' in web_result:
                    result_type = web_result['type']

                    if result_type == "response":
                        if 'status' in web_result:
                            status_code = web_result['status']
                            endpoint_url = None

                            if 'url' in web_result:
                                endpoint_url = web_result['url']

                                u = urlparse(endpoint_url)
                                web_path_str = u.path
                                if web_path_str and len(web_path_str) > 0:
                                    hashobj = hash_alg()
                                    hashobj.update(web_path_str.encode())
                                    path_hash = hashobj.digest()
                                    web_path_hash = binascii.hexlify(
                                        path_hash).decode()

                                host = u.netloc
                                if ":" in host:
                                    host_arr = host.split(":")
                                    domain_str = host_arr[0].lower()
                                else:
                                    domain_str = host.lower()

                                endpoint_domain_id = None
                                try:
                                    netaddr.IPAddress(domain_str)
                                except Exception as e:
                                    if domain_str in domain_name_id_map:
                                        endpoint_domain_id = domain_name_id_map[domain_str]
                                    else:
                                        domain_obj = data_model.Domain(
                                            parent_id=host_id)
                                        domain_obj.collection_tool_instance_id = tool_instance_id
                                        domain_obj.name = domain_str

                                        ret_arr.append(domain_obj)
                                        endpoint_domain_id = domain_obj.id
                                        domain_name_id_map[domain_str] = endpoint_domain_id

                                        ret_arr.append(domain_obj)

                                if web_path_hash in path_hash_map:
                                    path_obj = path_hash_map[web_path_hash]
                                else:
                                    path_obj = data_model.ListItem()
                                    path_obj.collection_tool_instance_id = tool_instance_id
                                    path_obj.web_path = web_path_str
                                    path_obj.web_path_hash = web_path_hash
                                    path_hash_map[web_path_hash] = path_obj
                                    ret_arr.append(path_obj)

                                web_path_id = path_obj.id

                                http_endpoint_obj = data_model.HttpEndpoint(
                                    parent_id=port_id)
                                http_endpoint_obj.collection_tool_instance_id = tool_instance_id
                                http_endpoint_obj.web_path_id = web_path_id

                                ret_arr.append(http_endpoint_obj)

                                content_length = None
                                if 'content_length' in web_result:
                                    content_length = web_result['content_length']

                                http_endpoint_data_obj = data_model.HttpEndpointData(
                                    parent_id=http_endpoint_obj.id)
                                http_endpoint_data_obj.collection_tool_instance_id = tool_instance_id
                                http_endpoint_data_obj.domain_id = endpoint_domain_id
                                http_endpoint_data_obj.status = status_code
                                http_endpoint_data_obj.content_length = content_length

                                ret_arr.append(http_endpoint_data_obj)

    return ret_arr
