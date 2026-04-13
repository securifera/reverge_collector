"""
CrapSecrets Cryptographic Vulnerability Scanner Module.

This module provides comprehensive cryptographic security analysis using CrapSecrets,
a pure Python library for identifying the use of known or very weak cryptographic
secrets across a variety of web application platforms. It integrates with the Waluigi
framework to perform automated detection of common cryptographic vulnerabilities.

The module focuses on scanning base URLs (root paths) only, filtering out URLs with
specific paths to concentrate vulnerability analysis on the primary endpoints where
cryptographic secrets are most commonly exposed.

The module supports:
    - Detection of known weak cryptographic secrets and keys
    - Analysis of various web application platforms and frameworks
    - HTTP endpoint scanning for cryptographic vulnerabilities focused on base URLs
    - Support for both discovered endpoints and custom URL lists
    - Concurrent processing for performance optimization
    - Comprehensive vulnerability reporting with details
    - Integration with the Waluigi vulnerability management system

Classes:
    Crapsecrets: Main tool class implementing the cryptographic scanner interface
    CrapSecretsScan: Luigi task for executing CrapSecrets vulnerability scanning
    ImportCrapSecretsOutput: Luigi task for importing and processing scan results

Functions:
    queue_scan: Manages vulnerability scan target queuing with deduplication
    request_wrapper: Core HTTP request and vulnerability analysis function
    create_port_objs: Creates database objects from URL analysis for new targets

Global Variables:
    url_set: Thread-safe set tracking scanned URLs to prevent duplicates
    path_hash_map: Mapping for web path deduplication across scans

Example:
    Basic usage through the Waluigi framework::
    
        # Initialize the tool
        crapsecrets = Crapsecrets()
        
        # Execute vulnerability scanning
        success = crapsecrets.scan_func(scan_input_obj)
        
        # Import results
        imported = crapsecrets.import_func(scan_input_obj)

Note:
    This module performs active HTTP requests to analyze cryptographic implementations.
    It should be used responsibly with proper authorization on target systems.
    The tool can identify various types of weak secrets including JWT keys,
    API tokens, and framework-specific cryptographic vulnerabilities.

"""

import json
import os
# import traceback
import time
import logging
from typing import Dict, Set, List, Any, Optional, Union

from waluigi import scan_utils
from waluigi import data_model
from waluigi.proc_utils import process_wrapper
from waluigi.tool_spec import ToolSpec

# Global URL tracking set to prevent duplicate scanning
url_set: Set[str] = set()

# Global path hash mapping for deduplication across vulnerability scans
path_hash_map: Dict[str, Any] = {}


class Crapsecrets(ToolSpec):

    name = 'crapsecrets'
    description = 'A pure python library for identifying the use of known or very weak cryptographic secrets across a variety of web application platforms.'
    project_url = 'https://github.com/irsdl/crapsecrets'
    tags = ['vuln-scan']
    collector_type = data_model.CollectorType.ACTIVE.value
    scan_order = 10
    args = '-nh -t 3 -mrd 5 -avsk -fvsp'
    input_records = [data_model.ServerRecordType.PORT,
                     data_model.ServerRecordType.HTTP_ENDPOINT_DATA]
    output_records = [data_model.ServerRecordType.VULNERABILITY]

    def get_output_path(self, scan_input) -> str:
        return get_output_path(scan_input)

    def execute_scan(self, scan_input) -> None:
        execute_scan(scan_input)

    def parse_output(self, output_path: str, scan_input) -> list:
        return parse_crapsecrets_output(
            output_path,
            scan_input.current_tool_instance_id,
            scan_input.current_tool.id,
        )


def queue_scan(url_dict: Dict[str, Any]) -> Optional[Any]:
    """
    Queue a cryptographic vulnerability scan target with deduplication.

    This function manages the queuing of URLs for CrapSecrets vulnerability scanning
    while preventing duplicate scans. It maintains a global set of processed URLs
    to ensure efficient resource utilization and avoid redundant analysis.

    Args:
        url_dict (Dict[str, Any]): Dictionary containing target URL and metadata
                                  including 'url', 'port_id', and 'http_endpoint_id'

    Returns:
        Optional[Any]: Future object for the queued scan task, or None if URL
                      was already queued (duplicate)

    Side Effects:
        - Modifies the global url_set to track processed URLs
        - Submits vulnerability scanning tasks to the executor pool

    Example:
        >>> url_data = {
        ...     'url': 'https://example.com/api'
        ... }
        >>> future = queue_scan(url_data)
        >>> if future:
        ...     result = future.result()

    Note:
        The function prevents duplicate scanning by checking the global url_set.
        Only unique URLs are submitted for vulnerability analysis to optimize
        performance and avoid redundant cryptographic testing.
    """

    global url_set

    url = url_dict['url']
    if url not in url_set:
        url_set.add(url)
        return scan_utils.executor.submit(request_wrapper, url_dict)


def request_wrapper(url_obj: Dict[str, Any]) -> Dict[str, Any]:
    """
    Core HTTP request and cryptographic vulnerability analysis function.

    This function executes the crapsecrets binary to analyze a target URL for
    cryptographic vulnerabilities. It handles network errors, retries, and
    comprehensive vulnerability detection across various web application platforms.

    Args:
        url_obj (Dict[str, Any]): Dictionary containing URL and metadata including:
                                 - 'url': Target URL for analysis
                                 - 'port_id': Database port identifier
                                 - 'http_endpoint_id': Database endpoint identifier

    Returns:
        Dict[str, Any]: Updated URL object with 'output' field containing
                       CrapSecrets analysis results or empty string if no
                       vulnerabilities found

    Side Effects:
        - Executes crapsecrets binary for each URL
        - Logs debug and error information
        - May retry requests up to 3 times on failure

    Raises:
        Exception: Various exceptions from process execution are caught and logged

    Example:
        >>> url_data = {'url': 'https://example.com/api', 'port_id': 123}
        >>> result = request_wrapper(url_data)
        >>> if result['output']:
        ...     print(f"Vulnerabilities found: {len(result['output'])}")

    Note:
        The function uses the crapsecrets CLI tool via process_wrapper for analysis.
        Results are parsed from the command output.
    """

    url = url_obj['url']
    output = []
    custom_args = url_obj.get('custom_args')

    logging.getLogger(__name__).debug("Scanning URL: %s" % url)

    count = 0
    while True:
        try:

            user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"

            # Build command to run crapsecrets binary
            command = [
                "crapsecrets",
                "--url",
                url,
                "-a",
                user_agent,
                "-j"  # JSON output
            ]

            # Add custom args if provided
            if custom_args:
                command.extend(custom_args)
            ret_dict = process_wrapper(cmd_args=command, store_output=True)

            if ret_dict and 'exit_code' in ret_dict:
                exit_code = ret_dict['exit_code']
                if exit_code == 0:
                    # Parse stdout for results
                    if 'stdout' in ret_dict and ret_dict['stdout']:
                        stdout_text = ret_dict['stdout']
                        try:
                            # Try to parse as JSON if output contains findings
                            if stdout_text.strip():
                                output = json.loads(stdout_text)
                        except json.JSONDecodeError:
                            # If not JSON, store raw output
                            output = [{'raw_output': stdout_text}]
                    elif 'stderr' in ret_dict and ret_dict['stderr']:
                        stderr_text = ret_dict['stderr']
                        logging.getLogger(__name__).error(
                            "Crapsecrets error for URL %s: %s" % (url, stderr_text))

                break
        except Exception as e:
            logging.getLogger(__name__).error(
                "Error scanning URL %s: %s" % (url, str(e)))
            count += 1
            time.sleep(1)
            if count > 2:
                break

    url_obj['output'] = output
    return url_obj


def get_output_path(scan_input) -> str:
    scan_id = scan_input.id
    tool_name = scan_input.current_tool.name
    dir_path = scan_utils.init_tool_folder(tool_name, 'outputs', scan_id)
    return f"{dir_path}{os.path.sep}crapsecrets_outputs_{scan_id}.json"


def execute_scan(scan_input) -> None:
    output_file_path = get_output_path(scan_input)
    if os.path.exists(output_file_path):
        return

    scheduled_scan_obj = scan_input
    output_file_list = []

    global url_set
    url_set = set()
    global path_hash_map
    path_hash_map.clear()

    custom_args = None
    if scheduled_scan_obj.current_tool.args:
        custom_args = scheduled_scan_obj.current_tool.args.split(" ")

    all_endpoint_port_obj_map = scheduled_scan_obj.scan_data.get_urls()
    endpoint_port_obj_map = {}
    for url, port_data in all_endpoint_port_obj_map.items():
        if port_data.get('path') is None or port_data.get('path') == '/':
            endpoint_port_obj_map[url] = port_data

    scope_obj = scheduled_scan_obj.scan_data
    url_list = scope_obj.get_scope_urls()

    futures = []
    for url_str, url_metadata in endpoint_port_obj_map.items():
        port_id = url_metadata.get('port_id')
        http_endpoint_id = url_metadata.get('http_endpoint_id')
        url_obj = {
            'port_id': port_id,
            'http_endpoint_id': http_endpoint_id,
            'url': url_str,
            'custom_args': custom_args
        }
        future_inst = queue_scan(url_obj)
        if future_inst:
            futures.append(future_inst)

    if len(endpoint_port_obj_map) == 0 and len(url_list) > 0:
        for url in url_list:
            url_obj = {'port_id': None, 'http_endpoint_id': None, 'url': url,
                       'custom_args': custom_args}
            future_inst = queue_scan(url_obj)
            if future_inst:
                futures.append(future_inst)

    if len(futures) == 0:
        logging.getLogger(__name__).debug("No targets to scan for CrapSecrets")

    if len(futures) > 0:
        scan_proc_inst = data_model.ToolExecutor(futures)
        scheduled_scan_obj.register_tool_executor(
            scheduled_scan_obj.current_tool_instance_id, scan_proc_inst)
        for future in futures:
            ret_obj = future.result()
            if ret_obj:
                output_file_list.append(ret_obj)
    else:
        logging.getLogger(__name__).debug("No targets to scan for CrapSecrets")

    results_dict = {'output_list': output_file_list}
    with open(output_file_path, 'w') as file_fd:
        file_fd.write(json.dumps(results_dict))


def parse_crapsecrets_output(output_file, tool_instance_id, tool_id):
    """Parse a CrapSecrets JSON output file and return data-model objects."""
    ret_arr = []
    with open(output_file, 'r') as file_fd:
        data = file_fd.read()

    if len(data) > 0:
        scan_data_dict = json.loads(data)

        # Get data and map
        output_list = scan_data_dict['output_list']
        if len(output_list) > 0:

            # Parse the output
            logging.getLogger(__name__).debug(
                "Importing CrapSecrets output with %s" % output_list)
            for entry in output_list:

                output = entry['output']
                http_endpoint_id = entry['http_endpoint_id']
                port_id = entry['port_id']

                # Handle new JSON format with 'target' and 'results' keys
                if output:
                    # Extract results list from new format
                    findings = output.get('results', []) if isinstance(
                        output, dict) else output

                    if findings and len(findings) > 0:
                        for finding in findings:
                            try:
                                # Handle findings from crapsecrets CLI output
                                if isinstance(finding, dict):
                                    # Extract key vulnerability information
                                    secret_type = finding.get(
                                        'secret_type', 'Unknown')

                                    if 'secret' in finding:
                                        # Add vuln
                                        vuln_obj = data_model.Vuln(
                                            parent_id=port_id)
                                        vuln_obj.collection_tool_instance_id = tool_instance_id
                                        vuln_obj.name = secret_type
                                        vuln_obj.endpoint_id = http_endpoint_id
                                        ret_arr.append(vuln_obj)

                                    # Add vuln details as a collection module output
                                    module_obj = data_model.CollectionModule(
                                        parent_id=tool_id)
                                    module_obj.collection_tool_instance_id = tool_instance_id
                                    module_obj.name = secret_type
                                    ret_arr.append(module_obj)
                                    module_id = module_obj.id

                                    # Add module output for all scan results
                                    module_output_obj = data_model.CollectionModuleOutput(
                                        parent_id=module_id)
                                    module_output_obj.collection_tool_instance_id = tool_instance_id
                                    module_output_obj.output = json.dumps(
                                        finding)
                                    module_output_obj.port_id = port_id
                                    ret_arr.append(module_output_obj)

                            except Exception as e:
                                logging.getLogger(__name__).error(
                                    "Error processing finding: %s" % str(e))
                                continue

    return ret_arr
