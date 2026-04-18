"""
SQLMap SQL Injection Scanner Module.

This module provides SQL injection scanning capabilities using SQLMap,
a powerful open-source penetration testing tool that automates the process
of detecting and exploiting SQL injection flaws and taking over database servers.
It integrates with the reverge_collector framework to perform automated SQL injection
testing against web targets.

The module supports:
    - Automated SQL injection detection and exploitation
    - Multi-target concurrent scanning
    - URL-based target collection (same pattern as NucleiScan/FeroxScan)
    - Vulnerability reporting and cataloging
    - Integration with Luigi workflow management

Classes:
    Sqlmap: Main tool class implementing the scanner interface
    SqlmapScan: Luigi task for executing SQLMap scans
    ImportSqlmapOutput: Luigi task for importing and processing scan results

Functions:
    parse_sqlmap_output: Parses SQLMap output files and returns data_model Record objects

Global Variables:
    url_set: Thread-safe set tracking queued URLs to prevent duplicates
    SQLMAP_PATH: File system path to the SQLMap Python script

Example:
    Basic usage through the reverge_collector framework::

        # Initialize the tool
        sqlmap = Sqlmap()

        # Execute scan
        success = sqlmap.scan_func(scan_input_obj)

        # Import results
        imported = sqlmap.import_func(scan_input_obj)

Note:
    This module requires SQLMap to be installed at /opt/sqlmap/sqlmap.py.
    The tool performs active scanning and should be used responsibly with proper
    authorization on target systems.
"""

from functools import partial
import json
import os
from typing import Dict, Any, Set, Optional, List
import logging
import random

from reverge_collector import scan_utils
from reverge_collector import data_model
from reverge_collector.proc_utils import process_wrapper
from reverge_collector.tool_spec import ToolSpec

# Global URL tracking set to prevent duplicate scanning
url_set: Set[str] = set()

# Path to the SQLMap Python script
SQLMAP_PATH = "/opt/sqlmap/sqlmap.py"


class Sqlmap(ToolSpec):

    name = 'sqlmap'
    description = (
        'SQLMap is an open source penetration testing tool that automates '
        'the process of detecting and exploiting SQL injection flaws and '
        'taking over database servers'
    )
    project_url = 'https://sqlmap.org/'
    tags = ['vuln-scan']
    collector_type = data_model.CollectorType.ACTIVE.value
    scan_order = 12
    args = '--batch --level=1 --risk=1 --crawl=2'
    input_records = [
        data_model.ServerRecordType.PORT,
        data_model.ServerRecordType.HTTP_ENDPOINT_DATA,
        data_model.ServerRecordType.SUBNET,
    ]
    output_records = [
        data_model.ServerRecordType.VULNERABILITY,
    ]

    def execute_scan(self, scan_input) -> None:
        execute_scan(scan_input)

    def parse_output(self, output_path: str, scan_input) -> list:
        return parse_sqlmap_output(
            output_path,
            scan_input.current_tool_instance_id,
        )


def get_output_path(scan_input: Any) -> str:
    scan_id = scan_input.id
    tool_name = scan_input.current_tool.name
    dir_path = scan_utils.init_tool_folder(tool_name, 'outputs', scan_id)
    return dir_path + os.path.sep + "sqlmap_outputs_" + scan_id


def execute_scan(scan_input: Any) -> None:
    output_file_path = get_output_path(scan_input)
    if os.path.exists(output_file_path):
        return

    global url_set
    url_set = set()

    scheduled_scan_obj = scan_input

    # Resolve output paths
    output_dir = os.path.dirname(output_file_path)

    url_to_id_map: Dict[str, Dict[str, Any]] = {}

    tool_args = scheduled_scan_obj.current_tool.args
    if tool_args:
        tool_args = tool_args.split()

    # Collect all URLs using the same pattern as NucleiScan / FeroxScan
    endpoint_url_map = scheduled_scan_obj.scan_data.get_url_metadata_map()

    for url_str, url_metadata in endpoint_url_map.items():
        host_id = url_metadata.get('host_id')
        port_id = url_metadata.get('port_id')

        if url_str and url_str not in url_set:
            url_set.add(url_str)
            rand_str = str(random.randint(1000000, 2000000))
            scan_output_file_path = (
                output_dir + os.path.sep + "sqlmap_out_" + rand_str
            )
            url_to_id_map[url_str] = {
                'port_id': port_id,
                'host_id': host_id,
                'output_file': scan_output_file_path,
            }

    futures = []
    for target_url, target_meta in url_to_id_map.items():
        scan_output_file_path = target_meta['output_file']

        command = []
        if os.name != 'nt':
            command.append("sudo")

        command.extend([
            "python3",
            SQLMAP_PATH,
            "-u", target_url,
        ])

        if tool_args and len(tool_args) > 0:
            command.extend(tool_args)

        callback_with_tool_id = partial(
            scheduled_scan_obj.register_tool_executor,
            scheduled_scan_obj.current_tool_instance_id,
        )

        futures.append(scan_utils.executor.submit(
            process_wrapper,
            cmd_args=command,
            pid_callback=callback_with_tool_id,
            stdout_file=scan_output_file_path,
        ))

    # Register all futures as a single ToolExecutor
    scan_proc_inst = data_model.ToolExecutor(futures)
    scheduled_scan_obj.register_tool_executor(
        scheduled_scan_obj.current_tool_instance_id, scan_proc_inst
    )

    results_dict = {'url_to_id_map': url_to_id_map}

    # Write manifest file consumed by the import phase
    with open(output_file_path, 'w') as file_fd:
        file_fd.write(json.dumps(results_dict))

    # Wait for all scan processes to complete
    for future in futures:
        ret_dict = future.result()
        if ret_dict and 'exit_code' in ret_dict:
            exit_code = ret_dict['exit_code']
            if exit_code != 0:
                err_msg = ret_dict.get('stderr', '')
                logging.getLogger(__name__).error(
                    "SQLMap scan for scan ID %s exited with code %d: %s"
                    % (scheduled_scan_obj.id, exit_code, err_msg)
                )
                raise RuntimeError(
                    "SQLMap scan for scan ID %s exited with code %d: %s"
                    % (scheduled_scan_obj.id, exit_code, err_msg)
                )


def _extract_vuln_details(content: str, url: str) -> str:
    """
    Extract a concise vulnerability description from sqlmap stdout.

    Captures the injection-point summary block that sqlmap prints when it
    identifies a vulnerable parameter.

    Args:
        content (str): Full stdout text captured from sqlmap.
        url (str): Target URL, used as a fallback description.

    Returns:
        str: Multi-line description of the identified injection point(s),
             or a simple fallback string when no block can be extracted.
    """
    lines = content.splitlines()
    details: List[str] = []
    capture = False

    for line in lines:
        stripped = line.strip()
        if 'identified the following injection point' in stripped:
            capture = True
        if capture:
            details.append(stripped)
            # Limit capture to a reasonable block size
            if len(details) > 30:
                break

    if details:
        return '\n'.join(details)
    return "SQL injection detected at: %s" % url


def parse_sqlmap_output(
    output_file: str,
    tool_instance_id: Optional[str] = None,
) -> List[Any]:
    """
    Parse a SQLMap manifest output file and return data_model Record objects.

    Reads the JSON manifest written by SqlmapScan, then for each captured
    stdout file checks whether sqlmap reported an injectable parameter.
    A Vuln record is created for each URL where injection was confirmed.

    Args:
        output_file (str): Path to the JSON manifest file produced by SqlmapScan.
        tool_instance_id (Optional[str]): Value to assign to
            ``collection_tool_instance_id`` on each created record.

    Returns:
        List[Any]: List of data_model.Vuln objects for discovered SQL injections.
                   Returns an empty list when no vulnerabilities were found.
    """
    with open(output_file, 'r') as file_fd:
        data = file_fd.read()

    ret_arr: List[Any] = []

    if not data:
        return ret_arr

    scan_data_dict = json.loads(data)
    url_to_id_map = scan_data_dict.get('url_to_id_map', {})

    for url_str, obj_data in url_to_id_map.items():
        scan_output_file = obj_data['output_file']
        port_id = obj_data['port_id']

        if not os.path.exists(scan_output_file):
            continue

        with open(scan_output_file, 'r') as f:
            content = f.read()

        # sqlmap reports findings with this header when a parameter is vulnerable
        injection_found = (
            'identified the following injection point' in content
            or ('Parameter:' in content and 'Type:' in content)
        )

        if injection_found:
            vuln_obj = data_model.Vuln(parent_id=port_id)
            vuln_obj.collection_tool_instance_id = tool_instance_id
            vuln_obj.name = 'sql_injection'
            vuln_obj.vuln_details = _extract_vuln_details(content, url_str)
            ret_arr.append(vuln_obj)

    return ret_arr
