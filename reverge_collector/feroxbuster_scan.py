"""
Feroxbuster Web Directory Scanner Module.

This module provides comprehensive web directory scanning capabilities using Feroxbuster,
a fast, simple, and flexible web directory scanner written in Rust. It integrates with
the reverge_collector framework to perform automated directory brute-forcing against web targets.

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
    Basic usage through the reverge_collector framework::
    
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
import hashlib
import binascii
import logging

from reverge_collector import scan_utils
from urllib.parse import urlparse
from reverge_collector import data_model
from reverge_collector.proc_utils import process_wrapper
from reverge_collector.tool_spec import ToolSpec

# Global URL tracking set to prevent duplicate scanning
url_set: Set[str] = set()


class Feroxbuster(ToolSpec):

    name = 'feroxbuster'
    description = 'Feroxbuster is a fast, simple, and flexible web directory scanner written in Rust'
    project_url = 'https://github.com/epi052/feroxbuster'
    tags = ['http-crawl']
    collector_type = data_model.CollectorType.ACTIVE.value
    scan_order = 10
    args = '--rate-limit 50 -s 200 -n --auto-bail --parallel 10 --scan-limit 10'
    input_records = [data_model.ServerRecordType.PORT,
                     data_model.ServerRecordType.HTTP_ENDPOINT_DATA,
                     data_model.ServerRecordType.SUBNET]
    output_records = [
        data_model.ServerRecordType.DOMAIN,
        data_model.ServerRecordType.LIST_ITEM,
        data_model.ServerRecordType.HTTP_ENDPOINT,
        data_model.ServerRecordType.HTTP_ENDPOINT_DATA,
    ]

    def get_output_path(self, scan_input) -> str:
        return get_output_path(scan_input)

    def execute_scan(self, scan_input) -> None:
        execute_scan(scan_input)

    def parse_output(self, output_path: str, scan_input) -> list:
        return parse_feroxbuster_output(
            output_path,
            scan_input.current_tool_instance_id,
        )


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
    endpoint_url_map = scheduled_scan_obj.scan_data.get_url_metadata_map()

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
            url_to_id_map[url_str] = {
                'port_id': port_id,
                'host_id': host_id,
            }

    ferox_scan_output_file_path = None

    if url_to_id_map:
        # Write all target URLs to a single input file
        ferox_scan_input_file_path = output_dir + os.path.sep + "ferox_scan_in"
        with open(ferox_scan_input_file_path, 'w') as file_fd:
            for url_str in url_to_id_map:
                file_fd.write(url_str + '\n')

        # Read the file contents to feed via stdin
        with open(ferox_scan_input_file_path, 'r') as file_fd:
            stdin_content = file_fd.read()

        ferox_scan_output_file_path = output_dir + os.path.sep + "ferox_scan_out"

        command = []
        if os.name != 'nt':
            command.append("sudo")

        command.extend([
            "feroxbuster",
            "--stdin",
            "--json",
            "-k",  # Disable cert validation
            "-A",  # Random User Agent
            "-o",
            ferox_scan_output_file_path,
        ])

        # Add optional arguments
        if tool_args and len(tool_args) > 0:
            command.extend(tool_args)

        # Add wordlist if provided
        if scan_wordlist:
            command.extend(['-w', scan_wordlist])

        callback_with_tool_id = partial(
            scheduled_scan_obj.register_tool_executor, scheduled_scan_obj.current_tool_instance_id)

        future = scan_utils.executor.submit(
            process_wrapper, cmd_args=command, stdin_data=stdin_content, pid_callback=callback_with_tool_id)

        # Register executor
        scan_proc_inst = data_model.ToolExecutor([future])
        scheduled_scan_obj.register_tool_executor(
            scheduled_scan_obj.current_tool_instance_id, scan_proc_inst)

        results_dict = {
            'url_to_id_map': url_to_id_map,
            'output_file': ferox_scan_output_file_path,
        }

        # Write metadata output file
        with open(output_file_path, 'w') as file_fd:
            file_fd.write(json.dumps(results_dict))

        # Wait for the task to complete
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
    else:
        # No targets — write an empty metadata file
        results_dict = {
            'url_to_id_map': {},
            'output_file': None,
        }
        with open(output_file_path, 'w') as file_fd:
            file_fd.write(json.dumps(results_dict))


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
        ferox_output_file = scan_data_dict.get('output_file')

        if not ferox_output_file or not os.path.exists(ferox_output_file):
            return ret_arr

        obj_arr = scan_utils.parse_json_blob_file(ferox_output_file)
        for web_result in obj_arr:
            if 'type' in web_result:
                result_type = web_result['type']

                if result_type == "response":
                    if 'status' in web_result:
                        status_code = web_result['status']
                        endpoint_url = None

                        if 'url' in web_result:
                            endpoint_url = web_result['url']

                            # Find the base URL entry this response belongs to
                            port_id = None
                            host_id = None
                            for base_url, obj_data in url_to_id_map.items():
                                if endpoint_url.startswith(base_url):
                                    port_id = obj_data['port_id']
                                    host_id = obj_data['host_id']
                                    break

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
